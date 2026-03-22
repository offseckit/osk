"""CVSS 3.1 and 4.0 scoring logic.

Implements the FIRST.org specification for both versions.
CVSS 3.1: Direct formula (ISS, Impact, Exploitability, Roundup).
CVSS 4.0: MacroVector lookup with interpolation.
"""

import math
import re

# ── CVSS 3.1 ──────────────────────────────────────────────────────

AV_W = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
AC_W = {"L": 0.77, "H": 0.44}
PR_W_U = {"N": 0.85, "L": 0.62, "H": 0.27}
PR_W_C = {"N": 0.85, "L": 0.68, "H": 0.50}
UI_W = {"N": 0.85, "R": 0.62}
CIA_W = {"N": 0.0, "L": 0.22, "H": 0.56}

E_W = {"X": 1.0, "U": 0.91, "P": 0.94, "F": 0.97, "H": 1.0}
RL_W = {"X": 1.0, "O": 0.95, "T": 0.96, "W": 0.97, "U": 1.0}
RC_W = {"X": 1.0, "U": 0.92, "R": 0.96, "C": 1.0}
REQ_W = {"X": 1.0, "L": 0.5, "M": 1.0, "H": 1.5}

CVSS31_BASE_KEYS = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]
CVSS31_TEMPORAL_KEYS = ["E", "RL", "RC"]
CVSS31_ENV_KEYS = ["CR", "IR", "AR", "MAV", "MAC", "MPR", "MUI", "MS", "MC", "MI", "MA"]

CVSS31_VALID = {
    "AV": "NALP", "AC": "LH", "PR": "NLH", "UI": "NR", "S": "UC",
    "C": "NLH", "I": "NLH", "A": "NLH",
    "E": "XUPFH", "RL": "XOTWU", "RC": "XURC",
    "CR": "XLMH", "IR": "XLMH", "AR": "XLMH",
    "MAV": "XNALP", "MAC": "XLH", "MPR": "XNLH", "MUI": "XNR", "MS": "XUC",
    "MC": "XNLH", "MI": "XNLH", "MA": "XNLH",
}


def _roundup(n):
    """Roundup per CVSS 3.1 spec."""
    i = int(round(n * 100000))
    if i % 10000 == 0:
        return i / 100000.0
    return (i // 10000 + 1) / 10.0


def parse_cvss31(vector):
    """Parse a CVSS 3.1 vector string into a dict. Returns None on failure."""
    if not vector.startswith("CVSS:3.1/") and not vector.startswith("CVSS:3.0/"):
        return None
    parts = vector.split("/")[1:]
    metrics = {}
    for part in parts:
        kv = part.split(":")
        if len(kv) != 2:
            return None
        k, v = kv
        if k not in CVSS31_VALID:
            return None
        if v not in CVSS31_VALID[k]:
            return None
        metrics[k] = v

    for key in CVSS31_BASE_KEYS:
        if key not in metrics:
            return None
    return metrics


def calc_cvss31(metrics):
    """Calculate CVSS 3.1 scores. Returns dict with base, temporal, environmental."""
    s = metrics["S"]
    pr_w = PR_W_C if s == "C" else PR_W_U

    iss = 1.0 - ((1.0 - CIA_W[metrics["C"]]) * (1.0 - CIA_W[metrics["I"]]) * (1.0 - CIA_W[metrics["A"]]))

    if s == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

    exploitability = 8.22 * AV_W[metrics["AV"]] * AC_W[metrics["AC"]] * pr_w[metrics["PR"]] * UI_W[metrics["UI"]]

    if impact <= 0:
        base = 0.0
    elif s == "U":
        base = _roundup(min(impact + exploitability, 10.0))
    else:
        base = _roundup(min(1.08 * (impact + exploitability), 10.0))

    e = metrics.get("E", "X")
    rl = metrics.get("RL", "X")
    rc = metrics.get("RC", "X")
    temporal = _roundup(base * E_W[e] * RL_W[rl] * RC_W[rc])

    # Environmental
    env = None
    has_env = any(metrics.get(k) and metrics.get(k) != "X" for k in CVSS31_ENV_KEYS)
    if has_env:
        m_av = metrics.get("MAV") if metrics.get("MAV", "X") != "X" else metrics["AV"]
        m_ac = metrics.get("MAC") if metrics.get("MAC", "X") != "X" else metrics["AC"]
        m_pr = metrics.get("MPR") if metrics.get("MPR", "X") != "X" else metrics["PR"]
        m_ui = metrics.get("MUI") if metrics.get("MUI", "X") != "X" else metrics["UI"]
        m_s = metrics.get("MS") if metrics.get("MS", "X") != "X" else metrics["S"]
        m_c = metrics.get("MC") if metrics.get("MC", "X") != "X" else metrics["C"]
        m_i = metrics.get("MI") if metrics.get("MI", "X") != "X" else metrics["I"]
        m_a = metrics.get("MA") if metrics.get("MA", "X") != "X" else metrics["A"]

        cr = REQ_W[metrics.get("CR", "X")]
        ir = REQ_W[metrics.get("IR", "X")]
        ar = REQ_W[metrics.get("AR", "X")]

        m_pr_w = PR_W_C if m_s == "C" else PR_W_U

        miss = min(
            1.0 - ((1.0 - CIA_W[m_c] * cr) * (1.0 - CIA_W[m_i] * ir) * (1.0 - CIA_W[m_a] * ar)),
            0.915,
        )

        if m_s == "U":
            m_impact = 6.42 * miss
        else:
            m_impact = 7.52 * (miss - 0.029) - 3.25 * ((miss * 0.9731 - 0.02) ** 13)

        m_exploit = 8.22 * AV_W[m_av] * AC_W[m_ac] * m_pr_w[m_pr] * UI_W[m_ui]

        if m_impact <= 0:
            env = 0.0
        elif m_s == "U":
            env = _roundup(_roundup(min(m_impact + m_exploit, 10.0)) * E_W[e] * RL_W[rl] * RC_W[rc])
        else:
            env = _roundup(_roundup(min(1.08 * (m_impact + m_exploit), 10.0)) * E_W[e] * RL_W[rl] * RC_W[rc])

    return {
        "version": "3.1",
        "base": base,
        "impact": max(0.0, round(impact, 1)),
        "exploitability": round(exploitability, 1),
        "temporal": temporal,
        "environmental": env,
        "severity": _severity(env if env is not None else (temporal if any(metrics.get(k, "X") != "X" for k in CVSS31_TEMPORAL_KEYS) else base)),
    }


# ── CVSS 4.0 ──────────────────────────────────────────────────────

CVSS40_BASE_KEYS = ["AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA"]

CVSS40_VALID = {
    "AV": "NALP", "AC": "LH", "AT": "NP", "PR": "NLH", "UI": "NPA",
    "VC": "HLN", "VI": "HLN", "VA": "HLN", "SC": "HLN", "SI": "SHLN", "SA": "SHLN",
    "E": "XAPU",
    "CR": "XHML", "IR": "XHML", "AR": "XHML",
    "MAV": "XNALP", "MAC": "XLH", "MAT": "XNP", "MPR": "XNLH", "MUI": "XNPA",
    "MVC": "XHLN", "MVI": "XHLN", "MVA": "XHLN", "MSC": "XHLN", "MSI": "XSHLN", "MSA": "XSHLN",
}

LOOKUP = {
    "000000": 10, "000001": 9.9, "000010": 9.8, "000011": 9.5,
    "000020": 9.5, "000021": 9.2, "000100": 10, "000101": 9.6,
    "000110": 9.3, "000111": 8.7, "000120": 9.1, "000121": 8.1,
    "000200": 9.3, "000201": 9, "000210": 8.9, "000211": 8,
    "000220": 8.1, "000221": 6.8, "001000": 9.8, "001001": 9.5,
    "001010": 9.5, "001011": 9.2, "001020": 9, "001021": 8.4,
    "001100": 9.3, "001101": 9.2, "001110": 8.9, "001111": 8.1,
    "001120": 8.1, "001121": 6.5, "001200": 8.8, "001201": 8,
    "001210": 7.8, "001211": 7, "001220": 6.9, "001221": 4.8,
    "002001": 9.2, "002011": 8.2, "002021": 7.2, "002101": 7.9,
    "002111": 6.9, "002121": 5, "002201": 6.9, "002211": 5.5,
    "002221": 2.7, "010000": 9.9, "010001": 9.7, "010010": 9.5,
    "010011": 9.2, "010020": 9.2, "010021": 8.5, "010100": 9.5,
    "010101": 9.1, "010110": 9, "010111": 8.3, "010120": 8.4,
    "010121": 7.1, "010200": 9.2, "010201": 8.1, "010210": 8.2,
    "010211": 7.1, "010220": 7.2, "010221": 5.3, "011000": 9.5,
    "011001": 9.3, "011010": 9.2, "011011": 8.5, "011020": 8.5,
    "011021": 7.3, "011100": 9.2, "011101": 8.2, "011110": 8,
    "011111": 7.2, "011120": 7, "011121": 5.9, "011200": 8.4,
    "011201": 7, "011210": 7.1, "011211": 5.2, "011220": 5,
    "011221": 3, "012001": 8.6, "012011": 7.5, "012021": 5.2,
    "012101": 7.1, "012111": 5.2, "012121": 2.9, "012201": 6.3,
    "012211": 2.9, "012221": 1.7, "100000": 9.8, "100001": 9.5,
    "100010": 9.4, "100011": 8.7, "100020": 9.1, "100021": 8.1,
    "100100": 9.4, "100101": 8.9, "100110": 8.6, "100111": 7.4,
    "100120": 7.7, "100121": 6.4, "100200": 8.7, "100201": 7.5,
    "100210": 7.4, "100211": 6.3, "100220": 5.8, "100221": 5.9,
    "101000": 9.4, "101001": 8.9, "101010": 8.8, "101011": 7.7,
    "101020": 7.6, "101021": 6.7, "101100": 8.6, "101101": 7.6,
    "101110": 7.4, "101111": 5.8, "101120": 5.9, "101121": 5,
    "101200": 7.2, "101201": 5.7, "101210": 5.7, "101211": 5.2,
    "101220": 5.2, "101221": 2.5, "102001": 8.3, "102011": 7,
    "102021": 5.4, "102101": 6.5, "102111": 5.8, "102121": 2.6,
    "102201": 5.3, "102211": 2.1, "102221": 1.3, "110000": 9.5,
    "110001": 9, "110010": 8.8, "110011": 7.6, "110020": 7.6,
    "110021": 7, "110100": 9, "110101": 7.7, "110110": 7.5,
    "110111": 6.2, "110120": 6.1, "110121": 5.3, "110200": 7.7,
    "110201": 6.6, "110210": 6.8, "110211": 5.9, "110220": 5.2,
    "110221": 3, "111000": 8.9, "111001": 7.8, "111010": 7.6,
    "111011": 6.7, "111020": 6.2, "111021": 5.8, "111100": 7.4,
    "111101": 5.9, "111110": 5.7, "111111": 5.7, "111120": 4.7,
    "111121": 2.3, "111200": 6.1, "111201": 5.2, "111210": 5.7,
    "111211": 2.9, "111220": 2.4, "111221": 1.6, "112001": 7.1,
    "112011": 5.9, "112021": 3, "112101": 5.8, "112111": 2.6,
    "112121": 1.5, "112201": 2.3, "112211": 1.3, "112221": 0.6,
    "200000": 9.3, "200001": 8.7, "200010": 8.6, "200011": 7.2,
    "200020": 7.5, "200021": 5.8, "200100": 8.6, "200101": 7.4,
    "200110": 7.4, "200111": 6.1, "200120": 5.6, "200121": 3.4,
    "200200": 7, "200201": 5.4, "200210": 5.2, "200211": 4,
    "200220": 4, "200221": 2.2, "201000": 8.5, "201001": 7.5,
    "201010": 7.4, "201011": 5.5, "201020": 6.2, "201021": 5.1,
    "201100": 7.2, "201101": 5.7, "201110": 5.5, "201111": 4.1,
    "201120": 4.6, "201121": 1.9, "201200": 5.3, "201201": 3.6,
    "201210": 3.4, "201211": 1.9, "201220": 1.9, "201221": 0.8,
    "202001": 6.4, "202011": 5.1, "202021": 2, "202101": 4.7,
    "202111": 2.1, "202121": 1.1, "202201": 2.4, "202211": 0.9,
    "202221": 0.4, "210000": 8.8, "210001": 7.5, "210010": 7.3,
    "210011": 5.3, "210020": 6, "210021": 5, "210100": 7.3,
    "210101": 5.5, "210110": 5.9, "210111": 4, "210120": 4,
    "210121": 2.2, "210200": 5, "210201": 3.3, "210210": 4.1,
    "210211": 2.8, "210220": 2.5, "210221": 1.3, "211000": 7.5,
    "211001": 5.5, "211010": 5.5, "211011": 4.4, "211020": 4.6,
    "211021": 2.1, "211100": 5.3, "211101": 4, "211110": 4,
    "211111": 2.5, "211120": 2, "211121": 1.1, "211200": 4,
    "211201": 2.7, "211210": 1.9, "211211": 0.8, "211220": 0.7,
    "211221": 0.2, "212001": 5.3, "212011": 2.4, "212021": 1.4,
    "212101": 2.4, "212111": 1.2, "212121": 0.5, "212201": 1,
    "212211": 0.3, "212221": 0.1,
}

METRIC_LEVELS = {
    "AV": {"N": 0, "A": 1, "L": 2, "P": 3},
    "AC": {"L": 0, "H": 1},
    "AT": {"N": 0, "P": 1},
    "PR": {"N": 0, "L": 1, "H": 2},
    "UI": {"N": 0, "P": 1, "A": 2},
    "VC": {"H": 0, "L": 1, "N": 2},
    "VI": {"H": 0, "L": 1, "N": 2},
    "VA": {"H": 0, "L": 1, "N": 2},
    "SC": {"H": 0, "L": 1, "N": 2},
    "SI": {"S": 0, "H": 0, "L": 1, "N": 2},
    "SA": {"S": 0, "H": 0, "L": 1, "N": 2},
    "E": {"A": 0, "P": 1, "U": 2},
    "CR": {"H": 0, "M": 1, "L": 2},
    "IR": {"H": 0, "M": 1, "L": 2},
    "AR": {"H": 0, "M": 1, "L": 2},
}

MAX_COMPOSED = {
    "eq1": [
        [("AV", "N"), ("PR", "N"), ("UI", "N")],
        [("AV", "A"), ("PR", "N"), ("UI", "N")],
        [("AV", "L"), ("PR", "N"), ("UI", "N")],
    ],
    "eq2": [
        [("AC", "L"), ("AT", "N")],
        [("AC", "H"), ("AT", "N")],
    ],
    "eq3": [
        [("VC", "H"), ("VI", "H")],
        [("VC", "H"), ("VI", "L")],
        [("VC", "L"), ("VI", "L")],
    ],
    "eq4": [
        [("SC", "H"), ("SI", "H"), ("SA", "H")],
        [("SC", "H"), ("SI", "H"), ("SA", "L")],
        [("SC", "L"), ("SI", "L"), ("SA", "L")],
    ],
    "eq5": [
        [("E", "A")],
        [("E", "P")],
        [("E", "U")],
    ],
    "eq6": [
        [("CR", "H"), ("VC", "H")],
        [("CR", "H"), ("VC", "L")],
    ],
}


def parse_cvss40(vector):
    """Parse a CVSS 4.0 vector string. Returns None on failure."""
    if not vector.startswith("CVSS:4.0/"):
        return None
    parts = vector.split("/")[1:]
    metrics = {}
    for part in parts:
        kv = part.split(":")
        if len(kv) != 2:
            return None
        k, v = kv
        if k not in CVSS40_VALID:
            return None
        if v not in CVSS40_VALID[k]:
            return None
        metrics[k] = v

    for key in CVSS40_BASE_KEYS:
        if key not in metrics:
            return None
    return metrics


def _eff40(m, metric):
    """Get effective metric value (modified overrides base)."""
    mod_map = {
        "AV": "MAV", "AC": "MAC", "AT": "MAT", "PR": "MPR", "UI": "MUI",
        "VC": "MVC", "VI": "MVI", "VA": "MVA", "SC": "MSC", "SI": "MSI", "SA": "MSA",
    }
    mod_key = mod_map.get(metric)
    if mod_key:
        val = m.get(mod_key)
        if val and val != "X":
            return val
    val = m.get(metric)
    if val and val != "X":
        return val
    if metric == "E":
        return "A"
    if metric in ("CR", "IR", "AR"):
        return "H"
    return "X"


def _compute_eq(m):
    av = _eff40(m, "AV")
    pr = _eff40(m, "PR")
    ui = _eff40(m, "UI")
    ac = _eff40(m, "AC")
    at = _eff40(m, "AT")
    vc = _eff40(m, "VC")
    vi = _eff40(m, "VI")
    va = _eff40(m, "VA")
    sc = _eff40(m, "SC")
    si = _eff40(m, "SI")
    sa = _eff40(m, "SA")
    e = _eff40(m, "E")
    cr = _eff40(m, "CR")
    ir = _eff40(m, "IR")
    ar = _eff40(m, "AR")

    if av == "N" and pr == "N" and ui == "N":
        eq1 = 0
    elif (av == "N" or pr == "N" or ui == "N") and not (av == "N" and pr == "N" and ui == "N") and ui != "A":
        eq1 = 1
    else:
        eq1 = 2

    eq2 = 0 if (ac == "L" and at == "N") else 1

    if vc == "H" and vi == "H":
        eq3 = 0
    elif vc == "H" or vi == "H" or va == "H":
        eq3 = 1
    else:
        eq3 = 2

    if si == "S" or sa == "S":
        eq4 = 0
    elif sc == "H" or si == "H" or sa == "H":
        eq4 = 1
    else:
        eq4 = 2

    if e == "A":
        eq5 = 0
    elif e == "P":
        eq5 = 1
    else:
        eq5 = 2

    if (cr == "H" and vc == "H") or (ir == "H" and vi == "H") or (ar == "H" and va == "H"):
        eq6 = 0
    else:
        eq6 = 1

    return f"{eq1}{eq2}{eq3}{eq4}{eq5}{eq6}"


def calc_cvss40(metrics):
    """Calculate CVSS 4.0 score. Returns dict with score and severity."""
    vc = _eff40(metrics, "VC")
    vi = _eff40(metrics, "VI")
    va = _eff40(metrics, "VA")
    sc = _eff40(metrics, "SC")
    si = _eff40(metrics, "SI")
    sa = _eff40(metrics, "SA")

    if all(v == "N" for v in [vc, vi, va, sc, si, sa]):
        return {"version": "4.0", "score": 0.0, "severity": "None"}

    eq = _compute_eq(metrics)
    macro_score = LOOKUP.get(eq)
    if macro_score is None:
        return {"version": "4.0", "score": 0.0, "severity": "None"}

    # Build max vector
    eq_digits = [int(d) for d in eq]
    max_vector = {}
    for eqi in range(6):
        composed = MAX_COMPOSED.get(f"eq{eqi + 1}", [])
        if eq_digits[eqi] < len(composed):
            for k, v in composed[eq_digits[eqi]]:
                max_vector[k] = v

    # Interpolation
    total_dist = 0.0
    dist_count = 0
    for eqi in range(6):
        next_eq = list(eq_digits)
        next_eq[eqi] += 1
        next_key = "".join(str(d) for d in next_eq)
        next_score = LOOKUP.get(next_key)
        if next_score is None:
            continue
        avail = macro_score - next_score
        if avail <= 0:
            continue

        eq_key = f"eq{eqi + 1}"
        composed = MAX_COMPOSED.get(eq_key, [])
        if eq_digits[eqi] >= len(composed):
            continue
        mc = composed[eq_digits[eqi]]

        cur_dist = 0.0
        max_dist = 0.0
        for metric, _ in mc:
            levels = METRIC_LEVELS.get(metric, {})
            if not levels:
                continue
            eff_val = _eff40(metrics, metric)
            max_val = max_vector.get(metric, list(levels.keys())[0])
            cur_dist += levels.get(eff_val, 0) - levels.get(max_val, 0)
            max_dist += max(levels.values()) - levels.get(max_val, 0)

        if max_dist > 0:
            total_dist += avail * (cur_dist / max_dist)
            dist_count += 1

    mean = total_dist / dist_count if dist_count > 0 else 0.0
    score = max(0.0, min(10.0, macro_score - mean))
    score = round(score, 1)

    return {"version": "4.0", "score": score, "severity": _severity(score)}


# ── Shared ─────────────────────────────────────────────────────────

def _severity(score):
    if score == 0:
        return "None"
    if score <= 3.9:
        return "Low"
    if score <= 6.9:
        return "Medium"
    if score <= 8.9:
        return "High"
    return "Critical"


def build_vector_31(metrics):
    """Build a CVSS 3.1 vector string from metrics dict."""
    base = "CVSS:3.1/" + "/".join(f"{k}:{metrics[k]}" for k in CVSS31_BASE_KEYS)
    extra = ""
    for k in CVSS31_TEMPORAL_KEYS + CVSS31_ENV_KEYS:
        v = metrics.get(k)
        if v and v != "X":
            extra += f"/{k}:{v}"
    return base + extra


def build_vector_40(metrics):
    """Build a CVSS 4.0 vector string from metrics dict."""
    base = "CVSS:4.0/" + "/".join(f"{k}:{metrics[k]}" for k in CVSS40_BASE_KEYS)
    extra_keys = ["E", "CR", "IR", "AR", "MAV", "MAC", "MAT", "MPR", "MUI", "MVC", "MVI", "MVA", "MSC", "MSI", "MSA"]
    extra = ""
    for k in extra_keys:
        v = metrics.get(k)
        if v and v != "X":
            extra += f"/{k}:{v}"
    return base + extra


PRESETS = [
    ("rce", "Remote Code Execution", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
     "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"),
    ("sqli", "SQL Injection", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
     "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N"),
    ("xss-stored", "Stored XSS", "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N",
     "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:P/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N"),
    ("xss-reflected", "Reflected XSS", "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
     "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N"),
    ("ssrf", "SSRF", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
     "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:H/SI:N/SA:N"),
    ("idor", "IDOR", "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
     "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"),
    ("privesc", "Local Privilege Escalation", "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
     "CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"),
    ("dos", "Denial of Service", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
     "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N"),
    ("info-disclosure", "Information Disclosure", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
     "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"),
]

SEV_COLORS = {
    "None": "bright_black",
    "Low": "green",
    "Medium": "yellow",
    "High": "bright_red",
    "Critical": "red",
}
