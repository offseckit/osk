"""HTTP header security analysis logic.

Analyzes pasted/piped HTTP response headers for security misconfigurations.
No network requests are made — headers are read from stdin or a file.
"""

import re

# ── Security headers to check ──────────────────────────────────────

SECURITY_HEADERS = [
    {
        "name": "Strict-Transport-Security",
        "description": "Enforces HTTPS connections, preventing protocol downgrade attacks.",
        "recommended": "max-age=63072000; includeSubDomains; preload",
        "core": True,
    },
    {
        "name": "Content-Security-Policy",
        "description": "Mitigates XSS and data injection by specifying allowed content sources.",
        "recommended": "default-src 'self'; form-action 'self'; object-src 'none'; frame-ancestors 'none'",
        "core": True,
    },
    {
        "name": "X-Frame-Options",
        "description": "Prevents clickjacking by controlling iframe embedding.",
        "recommended": "DENY",
        "core": True,
    },
    {
        "name": "X-Content-Type-Options",
        "description": "Prevents MIME-type sniffing.",
        "recommended": "nosniff",
        "core": True,
    },
    {
        "name": "Referrer-Policy",
        "description": "Controls referrer information exposure.",
        "recommended": "no-referrer",
        "core": True,
    },
    {
        "name": "Permissions-Policy",
        "description": "Controls browser feature access (camera, mic, geolocation).",
        "recommended": "geolocation=(), camera=(), microphone=()",
        "core": True,
    },
    {
        "name": "Cross-Origin-Opener-Policy",
        "description": "Isolates the browsing context from cross-origin attacks.",
        "recommended": "same-origin",
        "core": False,
    },
    {
        "name": "Cross-Origin-Embedder-Policy",
        "description": "Prevents loading cross-origin resources without permission.",
        "recommended": "require-corp",
        "core": False,
    },
    {
        "name": "Cross-Origin-Resource-Policy",
        "description": "Prevents other origins from loading this resource.",
        "recommended": "same-origin",
        "core": False,
    },
    {
        "name": "X-Permitted-Cross-Domain-Policies",
        "description": "Controls Adobe Flash/PDF cross-domain data loading.",
        "recommended": "none",
        "core": False,
    },
    {
        "name": "X-DNS-Prefetch-Control",
        "description": "Controls DNS prefetching to prevent information leakage.",
        "recommended": "off",
        "core": False,
    },
    {
        "name": "Cache-Control",
        "description": "Controls caching. Sensitive pages should use no-store.",
        "recommended": "no-store, max-age=0",
        "core": False,
    },
]

DEPRECATED_HEADERS = [
    {"name": "X-XSS-Protection", "reason": "Deprecated by all browsers. Can introduce XSS in older browsers.", "replacement": "Content-Security-Policy"},
    {"name": "Expect-CT", "reason": "Deprecated since 2021. CT is enforced by default.", "replacement": None},
    {"name": "Public-Key-Pins", "reason": "Removed from all browsers. Can cause permanent DoS.", "replacement": None},
    {"name": "Feature-Policy", "reason": "Renamed to Permissions-Policy.", "replacement": "Permissions-Policy"},
    {"name": "Pragma", "reason": "HTTP/1.0 relic.", "replacement": "Cache-Control"},
]

LEAKAGE_HEADERS = [
    {"name": "Server", "description": "Reveals web server software and version."},
    {"name": "X-Powered-By", "description": "Reveals server-side framework or language."},
    {"name": "X-AspNet-Version", "description": "Reveals ASP.NET version."},
    {"name": "X-AspNetMvc-Version", "description": "Reveals ASP.NET MVC version."},
    {"name": "X-Generator", "description": "Reveals CMS or site generator."},
    {"name": "X-Drupal-Cache", "description": "Reveals Drupal CMS usage."},
    {"name": "X-Varnish", "description": "Reveals Varnish cache usage."},
    {"name": "Via", "description": "May reveal proxy infrastructure."},
]


# ── Parse headers ──────────────────────────────────────────────────

def parse_headers(raw):
    """Parse raw HTTP response headers into a list of (name, value) tuples."""
    headers = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        # Skip HTTP status lines
        if re.match(r"^HTTP/[\d.]+\s+\d+", line):
            continue
        colon = line.find(":")
        if colon == -1:
            continue
        name = line[:colon].strip()
        value = line[colon + 1:].strip()
        if name:
            headers.append((name, value))
    return headers


# ── CSP analysis ───────────────────────────────────────────────────

def analyze_csp(value):
    """Analyze a Content-Security-Policy value for security issues."""
    findings = []
    directives = {}

    for part in value.split(";"):
        part = part.strip()
        if not part:
            continue
        tokens = part.split()
        name = tokens[0].lower()
        values = tokens[1:]
        directives[name] = values

    for name, values in directives.items():
        if "'unsafe-inline'" in values:
            findings.append(("warn", name, f"'unsafe-inline' in {name} allows inline scripts/styles, reducing XSS protection."))
        if "'unsafe-eval'" in values:
            findings.append(("warn", name, f"'unsafe-eval' in {name} allows eval() and similar, enabling code injection."))
        if "*" in values:
            findings.append(("fail", name, f"Wildcard (*) in {name} allows any origin, defeating CSP."))
        if "data:" in values:
            sev = "fail" if name in ("script-src", "default-src") else "warn"
            findings.append((sev, name, f"data: URI in {name} can inject arbitrary content."))
        if name in ("script-src", "default-src"):
            http_sources = [v for v in values if v.startswith("http:")]
            if http_sources:
                findings.append(("warn", name, f"HTTP sources in {name} allow scripts over unencrypted connections."))

    if "default-src" not in directives:
        findings.append(("warn", "default-src", "Missing default-src directive."))
    if "object-src" not in directives and "default-src" not in directives:
        findings.append(("warn", "object-src", "Missing object-src — Flash/applet embeds not restricted."))
    if "base-uri" not in directives:
        findings.append(("info", "base-uri", "Missing base-uri — <base> tag injection possible."))
    if "form-action" not in directives:
        findings.append(("info", "form-action", "Missing form-action — forms can submit to arbitrary destinations."))
    if "frame-ancestors" not in directives:
        findings.append(("info", "frame-ancestors", "Missing frame-ancestors — page may be framed (clickjacking)."))

    return findings


# ── Value checks ───────────────────────────────────────────────────

def check_hsts(value):
    """Check HSTS header value."""
    match = re.search(r"max-age=(\d+)", value, re.IGNORECASE)
    if not match:
        return "fail", "Missing max-age directive."
    max_age = int(match.group(1))
    if max_age < 31536000:
        return "warn", f"max-age is {max_age}s ({max_age // 86400} days). OWASP recommends >= 1 year."
    has_sub = bool(re.search(r"includeSubDomains", value, re.IGNORECASE))
    has_preload = bool(re.search(r"preload", value, re.IGNORECASE))
    if not has_sub:
        return "warn", "Missing includeSubDomains."
    if not has_preload:
        return "info", "Missing preload directive."
    return "pass", "Properly configured with includeSubDomains and preload."


def check_xfo(value):
    """Check X-Frame-Options value."""
    upper = value.strip().upper()
    if upper in ("DENY", "SAMEORIGIN"):
        return "pass", f"Set to {upper}."
    if upper.startswith("ALLOW-FROM"):
        return "warn", "ALLOW-FROM is not supported by modern browsers."
    return "fail", f"Unrecognized value: {value}."


def check_xcto(value):
    """Check X-Content-Type-Options value."""
    if value.strip().lower() == "nosniff":
        return "pass", "Correctly set to nosniff."
    return "fail", f"Invalid value: {value}. Only 'nosniff' is valid."


def check_referrer(value):
    """Check Referrer-Policy value."""
    secure = {"no-referrer", "same-origin", "strict-origin", "strict-origin-when-cross-origin"}
    risky = {"unsafe-url", "no-referrer-when-downgrade"}
    policies = [p.strip().lower() for p in value.split(",")]
    last = policies[-1]
    if last in secure:
        return "pass", f"Set to '{last}'."
    if last in risky:
        return "fail", f"'{last}' leaks full URL to other origins."
    return "warn", f"Policy: '{value}'."


def check_cache_control(value):
    """Check Cache-Control value."""
    lower = value.lower()
    if "no-store" in lower:
        return "pass", "Includes no-store."
    if "private" in lower:
        return "warn", "Set to private but sensitive pages should use no-store."
    return "info", "Does not prevent caching."


def check_coop(value):
    """Check Cross-Origin-Opener-Policy."""
    v = value.strip().lower()
    if v == "same-origin":
        return "pass", "Same-origin isolation enabled."
    if v == "same-origin-allow-popups":
        return "warn", "Allows popups to retain opener reference."
    return "warn", f"Value: {value}."


def check_coep(value):
    """Check Cross-Origin-Embedder-Policy."""
    v = value.strip().lower()
    if v in ("require-corp", "credentialless"):
        return "pass", f"Set to {v}."
    return "warn", f"Value: {value}."


def check_corp(value):
    """Check Cross-Origin-Resource-Policy."""
    v = value.strip().lower()
    if v in ("same-origin", "same-site"):
        return "pass", f"Set to {v}."
    if v == "cross-origin":
        return "warn", "Allows cross-origin loading."
    return "info", f"Value: {value}."


HEADER_CHECKERS = {
    "strict-transport-security": check_hsts,
    "x-frame-options": check_xfo,
    "x-content-type-options": check_xcto,
    "referrer-policy": check_referrer,
    "cache-control": check_cache_control,
    "cross-origin-opener-policy": check_coop,
    "cross-origin-embedder-policy": check_coep,
    "cross-origin-resource-policy": check_corp,
}


# ── Main analysis ──────────────────────────────────────────────────

def analyze(raw):
    """Analyze raw HTTP response headers and return results dict."""
    headers = parse_headers(raw)
    header_map = {}
    for name, value in headers:
        header_map[name.lower()] = (name, value)

    checks = []  # list of (severity, header_name, description, recommendation)
    csp_findings = []

    # Check required security headers
    for hdef in SECURITY_HEADERS:
        key = hdef["name"].lower()
        entry = header_map.get(key)

        if entry is None:
            sev = "info" if not hdef["core"] else "fail"
            checks.append((sev, hdef["name"], f"Missing. {hdef['description']}", hdef["recommended"]))
            continue

        _, value = entry

        if key == "content-security-policy":
            checks.append(("pass", hdef["name"], "Present. See CSP analysis.", None))
            csp_findings = analyze_csp(value)
            # Downgrade to warn if CSP has issues
            if any(f[0] == "fail" for f in csp_findings):
                checks[-1] = ("warn", hdef["name"], "Present but has security issues.", None)
            continue

        checker = HEADER_CHECKERS.get(key)
        if checker:
            sev, desc = checker(value)
            rec = hdef["recommended"] if sev in ("fail", "warn") else None
            checks.append((sev, hdef["name"], desc, rec))
        elif key == "permissions-policy":
            checks.append(("pass", hdef["name"], "Present.", None))
        else:
            checks.append(("pass", hdef["name"], "Present.", None))

    # Check deprecated headers
    for dep in DEPRECATED_HEADERS:
        key = dep["name"].lower()
        entry = header_map.get(key)
        if entry:
            rec = f"Remove and use {dep['replacement']}." if dep["replacement"] else f"Remove {dep['name']}."
            checks.append(("warn", dep["name"], f"Deprecated. {dep['reason']}", rec))

    # Check info leakage headers
    for leak in LEAKAGE_HEADERS:
        key = leak["name"].lower()
        entry = header_map.get(key)
        if entry:
            _, value = entry
            checks.append(("info", leak["name"], f"{leak['description']} Value: \"{value}\"", f"Remove {leak['name']} header."))

    # Calculate score
    score = _calculate_score(checks, csp_findings)
    grade = _score_to_grade(score)

    summary = {"pass": 0, "warn": 0, "fail": 0, "info": 0}
    for sev, _, _, _ in checks:
        summary[sev] += 1

    return {
        "headers": headers,
        "checks": checks,
        "csp_findings": csp_findings,
        "grade": grade,
        "score": score,
        "summary": summary,
    }


def _calculate_score(checks, csp_findings):
    core_names = {h["name"] for h in SECURITY_HEADERS if h["core"]}
    dep_names = {d["name"] for d in DEPRECATED_HEADERS}
    leak_names = {l["name"] for l in LEAKAGE_HEADERS}
    score = 100

    for sev, name, _, _ in checks:
        is_core = name in core_names
        if sev == "fail":
            score -= 15 if is_core else 5
        elif sev == "warn":
            if name in dep_names or name in leak_names:
                score -= 3
            else:
                score -= 8 if is_core else 3

    for sev, _, _ in csp_findings:
        if sev == "fail":
            score -= 5
        elif sev == "warn":
            score -= 3

    return max(0, min(100, score))


def _score_to_grade(score):
    if score >= 95:
        return "A+"
    if score >= 80:
        return "A"
    if score >= 65:
        return "B"
    if score >= 50:
        return "C"
    if score >= 35:
        return "D"
    return "F"


def list_headers():
    """Return list of security headers checked."""
    return [{"name": h["name"], "description": h["description"], "core": h["core"]} for h in SECURITY_HEADERS]
