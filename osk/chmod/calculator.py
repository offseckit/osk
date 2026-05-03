"""Chmod / Linux permissions calculator logic.

Mode is represented as an int 0..0o7777:
  bits 0..2  -> other  (r=4, w=2, x=1)
  bits 3..5  -> group  (r=4, w=2, x=1)
  bits 6..8  -> owner  (r=4, w=2, x=1)
  bit 9      -> sticky (1000 octal)
  bit 10     -> setgid (2000 octal)
  bit 11     -> setuid (4000 octal)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable, List, Optional, Set

MODE_MAX = 0o7777

WHO_OFFSET = {"owner": 6, "group": 3, "other": 0}
PERM_BIT = {"read": 4, "write": 2, "execute": 1}
SPECIAL_BIT = {"setuid": 0o4000, "setgid": 0o2000, "sticky": 0o1000}


def clamp_mode(mode: int) -> int:
    if not isinstance(mode, int):
        return 0
    if mode < 0:
        return 0
    if mode > MODE_MAX:
        return MODE_MAX
    return mode


def has_perm(mode: int, who: str, perm: str) -> bool:
    return ((mode >> WHO_OFFSET[who]) & PERM_BIT[perm]) != 0


def set_perm(mode: int, who: str, perm: str, on: bool) -> int:
    bit = PERM_BIT[perm] << WHO_OFFSET[who]
    return mode | bit if on else mode & ~bit


def has_special(mode: int, bit: str) -> bool:
    return (mode & SPECIAL_BIT[bit]) != 0


def set_special(mode: int, bit: str, on: bool) -> int:
    b = SPECIAL_BIT[bit]
    return mode | b if on else mode & ~b


# ── Octal formatting ──────────────────────────────────────────────


def to_octal(mode: int) -> str:
    """Octal string. 4 digits when special bits present, else 3."""
    m = clamp_mode(mode)
    special = (m >> 9) & 0o7
    if special == 0:
        return f"{m & 0o777:03o}"
    return f"{m:04o}"


def to_octal4(mode: int) -> str:
    return f"{clamp_mode(mode):04o}"


def parse_octal(value: str) -> Optional[int]:
    s = value.strip()
    if not s:
        return None
    if not re.fullmatch(r"[0-7]{1,4}", s):
        return None
    n = int(s, 8)
    if n < 0 or n > MODE_MAX:
        return None
    return n


# ── Symbolic (rwx) string ─────────────────────────────────────────


def to_rwx_string(mode: int) -> str:
    m = clamp_mode(mode)
    suid = has_special(m, "setuid")
    sgid = has_special(m, "setgid")
    stk = has_special(m, "sticky")

    out = []
    out.append("r" if has_perm(m, "owner", "read") else "-")
    out.append("w" if has_perm(m, "owner", "write") else "-")
    ox = has_perm(m, "owner", "execute")
    out.append("s" if (suid and ox) else "S" if suid else "x" if ox else "-")

    out.append("r" if has_perm(m, "group", "read") else "-")
    out.append("w" if has_perm(m, "group", "write") else "-")
    gx = has_perm(m, "group", "execute")
    out.append("s" if (sgid and gx) else "S" if sgid else "x" if gx else "-")

    out.append("r" if has_perm(m, "other", "read") else "-")
    out.append("w" if has_perm(m, "other", "write") else "-")
    tx = has_perm(m, "other", "execute")
    out.append("t" if (stk and tx) else "T" if stk else "x" if tx else "-")

    return "".join(out)


def parse_rwx_string(value: str) -> Optional[int]:
    s = value.strip()
    if len(s) == 10:
        if not re.fullmatch(r"[-dlcbpsDLCBPS].{9}", s):
            return None
        s = s[1:]
    if len(s) != 9:
        return None
    if not re.fullmatch(r"[-rwxsStT]{9}", s):
        return None

    mode = 0

    # Owner
    if s[0] == "r":
        mode |= PERM_BIT["read"] << WHO_OFFSET["owner"]
    elif s[0] != "-":
        return None
    if s[1] == "w":
        mode |= PERM_BIT["write"] << WHO_OFFSET["owner"]
    elif s[1] != "-":
        return None
    if s[2] == "x":
        mode |= PERM_BIT["execute"] << WHO_OFFSET["owner"]
    elif s[2] == "s":
        mode |= PERM_BIT["execute"] << WHO_OFFSET["owner"]
        mode |= SPECIAL_BIT["setuid"]
    elif s[2] == "S":
        mode |= SPECIAL_BIT["setuid"]
    elif s[2] != "-":
        return None

    # Group
    if s[3] == "r":
        mode |= PERM_BIT["read"] << WHO_OFFSET["group"]
    elif s[3] != "-":
        return None
    if s[4] == "w":
        mode |= PERM_BIT["write"] << WHO_OFFSET["group"]
    elif s[4] != "-":
        return None
    if s[5] == "x":
        mode |= PERM_BIT["execute"] << WHO_OFFSET["group"]
    elif s[5] == "s":
        mode |= PERM_BIT["execute"] << WHO_OFFSET["group"]
        mode |= SPECIAL_BIT["setgid"]
    elif s[5] == "S":
        mode |= SPECIAL_BIT["setgid"]
    elif s[5] != "-":
        return None

    # Other
    if s[6] == "r":
        mode |= PERM_BIT["read"] << WHO_OFFSET["other"]
    elif s[6] != "-":
        return None
    if s[7] == "w":
        mode |= PERM_BIT["write"] << WHO_OFFSET["other"]
    elif s[7] != "-":
        return None
    if s[8] == "x":
        mode |= PERM_BIT["execute"] << WHO_OFFSET["other"]
    elif s[8] == "t":
        mode |= PERM_BIT["execute"] << WHO_OFFSET["other"]
        mode |= SPECIAL_BIT["sticky"]
    elif s[8] == "T":
        mode |= SPECIAL_BIT["sticky"]
    elif s[8] != "-":
        return None

    return mode


# ── POSIX symbolic notation parser ────────────────────────────────


@dataclass
class _Clause:
    who: Set[str] = field(default_factory=set)
    op: str = "+"
    perms: Set[str] = field(default_factory=set)
    setuid: bool = False
    setgid: bool = False
    sticky: bool = False
    copy_from: Optional[str] = None
    conditional_execute: bool = False


def _expand_who(s: str) -> Set[str]:
    out: Set[str] = set()
    for c in s:
        if c == "u":
            out.add("owner")
        elif c == "g":
            out.add("group")
        elif c == "o":
            out.add("other")
        elif c == "a":
            out.update(("owner", "group", "other"))
    return out


_CLAUSE_RE = re.compile(r"^([ugoa]*)([+\-=])([rwxXstugo]*)$")


def _parse_clause(raw: str) -> Optional[_Clause]:
    m = _CLAUSE_RE.match(raw)
    if not m:
        return None
    who_str, op, perm_str = m.group(1), m.group(2), m.group(3)
    who = _expand_who("a") if not who_str else _expand_who(who_str)
    clause = _Clause(who=who, op=op)
    for c in perm_str:
        if c == "r":
            clause.perms.add("read")
        elif c == "w":
            clause.perms.add("write")
        elif c == "x":
            clause.perms.add("execute")
        elif c == "X":
            clause.conditional_execute = True
        elif c == "s":
            clause.setuid = True
            clause.setgid = True
        elif c == "t":
            clause.sticky = True
        elif c in ("u", "g", "o"):
            clause.copy_from = (
                "owner" if c == "u" else "group" if c == "g" else "other"
            )
    return clause


def _get_perms(mode: int, who: str) -> Set[str]:
    s: Set[str] = set()
    if has_perm(mode, who, "read"):
        s.add("read")
    if has_perm(mode, who, "write"):
        s.add("write")
    if has_perm(mode, who, "execute"):
        s.add("execute")
    return s


def _apply_clause(mode: int, clause: _Clause, is_dir: bool) -> int:
    next_mode = mode
    base_perms = (
        _get_perms(next_mode, clause.copy_from)
        if clause.copy_from
        else set(clause.perms)
    )
    for w in clause.who:
        perms = set(base_perms)
        if clause.conditional_execute:
            any_exec = (
                has_perm(next_mode, "owner", "execute")
                or has_perm(next_mode, "group", "execute")
                or has_perm(next_mode, "other", "execute")
            )
            if is_dir or any_exec:
                perms.add("execute")
        if clause.op == "=":
            next_mode = set_perm(next_mode, w, "read", False)
            next_mode = set_perm(next_mode, w, "write", False)
            next_mode = set_perm(next_mode, w, "execute", False)
            for p in perms:
                next_mode = set_perm(next_mode, w, p, True)
            if w == "owner":
                next_mode = set_special(next_mode, "setuid", False)
            if w == "group":
                next_mode = set_special(next_mode, "setgid", False)
        elif clause.op == "+":
            for p in perms:
                next_mode = set_perm(next_mode, w, p, True)
        else:
            for p in perms:
                next_mode = set_perm(next_mode, w, p, False)

    who_is_all = (
        "owner" in clause.who and "group" in clause.who and "other" in clause.who
    )
    if clause.setuid:
        if "owner" in clause.who or who_is_all:
            on = clause.op in ("+", "=")
            next_mode = set_special(next_mode, "setuid", on)
    if clause.setgid:
        if "group" in clause.who or who_is_all:
            on = clause.op in ("+", "=")
            next_mode = set_special(next_mode, "setgid", on)
    if clause.sticky:
        on = clause.op in ("+", "=")
        next_mode = set_special(next_mode, "sticky", on)

    return next_mode


def apply_symbolic(base_mode: int, symbolic: str, is_dir: bool = False) -> int:
    """Apply a POSIX-style symbolic notation to a base mode.

    Raises ValueError on invalid input.
    """
    s = symbolic.strip()
    if not s:
        raise ValueError("Empty symbolic notation")
    mode = clamp_mode(base_mode)
    for raw in s.split(","):
        clause = _parse_clause(raw.strip())
        if clause is None:
            raise ValueError(f"Invalid symbolic clause: {raw.strip()!r}")
        mode = _apply_clause(mode, clause, is_dir)
    return mode


def to_symbolic_equals(mode: int) -> str:
    m = clamp_mode(mode)
    parts = []
    for label, who in (("u", "owner"), ("g", "group"), ("o", "other")):
        s = ""
        if has_perm(m, who, "read"):
            s += "r"
        if has_perm(m, who, "write"):
            s += "w"
        if has_perm(m, who, "execute"):
            s += "x"
        parts.append(f"{label}={s}")
    if has_special(m, "setuid"):
        parts.append("u+s")
    if has_special(m, "setgid"):
        parts.append("g+s")
    if has_special(m, "sticky"):
        parts.append("+t")
    return ",".join(parts)


def to_symbolic_delta(mode: int) -> str:
    m = clamp_mode(mode)
    parts = []
    o = ""
    if has_perm(m, "owner", "read"):
        o += "r"
    if has_perm(m, "owner", "write"):
        o += "w"
    if has_perm(m, "owner", "execute"):
        o += "x"
    if has_special(m, "setuid"):
        o += "s"
    if o:
        parts.append(f"u+{o}")
    g = ""
    if has_perm(m, "group", "read"):
        g += "r"
    if has_perm(m, "group", "write"):
        g += "w"
    if has_perm(m, "group", "execute"):
        g += "x"
    if has_special(m, "setgid"):
        g += "s"
    if g:
        parts.append(f"g+{g}")
    other = ""
    if has_perm(m, "other", "read"):
        other += "r"
    if has_perm(m, "other", "write"):
        other += "w"
    if has_perm(m, "other", "execute"):
        other += "x"
    if has_special(m, "sticky"):
        other += "t"
    if other:
        parts.append(f"o+{other}")
    return ",".join(parts) if parts else "a-rwx"


# ── Warnings ──────────────────────────────────────────────────────


@dataclass
class Warning:
    level: str  # info | warn | danger
    title: str
    detail: str


def get_warnings(mode: int) -> List[Warning]:
    m = clamp_mode(mode)
    out: List[Warning] = []
    world_write = has_perm(m, "other", "write")
    sticky = has_special(m, "sticky")
    suid = has_special(m, "setuid")
    sgid = has_special(m, "setgid")

    if (
        has_perm(m, "other", "read")
        and has_perm(m, "other", "write")
        and has_perm(m, "other", "execute")
        and has_perm(m, "group", "write")
        and not sticky
    ):
        out.append(
            Warning(
                "danger",
                "World-writable and world-executable (mode 777)",
                "Any local user can read, modify, and execute. Use 1777 for /tmp-style shared dirs.",
            )
        )
    elif world_write and not sticky:
        out.append(
            Warning(
                "warn",
                "World-writable without sticky bit",
                "Any local user can modify or delete. For shared directories use sticky (1xxx).",
            )
        )

    if suid:
        out.append(
            Warning(
                "warn",
                "Setuid bit is set",
                "Binary runs with file owner's privileges. Hunt with: find / -perm -4000 -type f 2>/dev/null",
            )
        )
        if world_write:
            out.append(
                Warning(
                    "danger",
                    "Setuid + world-writable",
                    "Immediate privilege-escalation vector. Remove world-write or clear setuid.",
                )
            )
    if sgid:
        out.append(
            Warning(
                "info",
                "Setgid bit is set",
                "On binaries: runs as file group. On dirs: new files inherit dir's group.",
            )
        )
    if sticky and not has_perm(m, "other", "execute"):
        out.append(
            Warning(
                "info",
                "Sticky bit set without other-execute",
                "Sticky only affects directories where others have execute. Capital T flags this.",
            )
        )
    if (
        not has_perm(m, "owner", "read")
        and not has_perm(m, "owner", "write")
        and not has_perm(m, "owner", "execute")
    ):
        out.append(
            Warning(
                "warn",
                "Owner has no permissions",
                "Owner cannot read, write, or execute. Almost certainly a misconfiguration.",
            )
        )
    return out


# ── Presets ───────────────────────────────────────────────────────


@dataclass
class Preset:
    octal: str
    mode: int
    label: str
    detail: str


PRESETS: List[Preset] = [
    Preset("755", 0o755, "Directories / executables", "Owner full, group/other read+execute."),
    Preset("644", 0o644, "Regular files", "Owner read+write, group/other read-only."),
    Preset("700", 0o700, "Private directory (.ssh)", "Owner-only access. Required for the user's .ssh directory."),
    Preset("600", 0o600, "Private file (SSH key)", "Owner read+write only. Required for SSH private keys."),
    Preset("640", 0o640, "Group-readable config", "Owner rw, group r, other none. Common for service configs."),
    Preset("777", 0o777, "Fully open (avoid)", "Anyone can read, write, execute. Use 1777 for shared writable dirs."),
    Preset("1777", 0o1777, "Sticky world-writable (/tmp)", "Used by /tmp; users cannot delete each other's files."),
    Preset("4755", 0o4755, "Setuid binary", "Runs as owner. Common for /usr/bin/sudo, /usr/bin/passwd."),
    Preset("2755", 0o2755, "Setgid binary / dir", "Binary runs as group; dir makes new files inherit group."),
]


# ── Bit / digit breakdown ─────────────────────────────────────────


@dataclass
class BitRow:
    octal: int
    weight: int
    label: str
    meaning: str
    set: bool


def get_bit_breakdown(mode: int) -> List[BitRow]:
    m = clamp_mode(mode)
    rows: List[BitRow] = []
    spec = [
        (0o4000, "setuid", "Run with file owner's privileges. Privesc target if owned by root."),
        (0o2000, "setgid", "On binaries: run with file group. On dirs: new files inherit dir's group."),
        (0o1000, "sticky", "Only file owner can delete files in dir."),
        (0o0400, "owner read", "Owner can read."),
        (0o0200, "owner write", "Owner can modify."),
        (0o0100, "owner execute", "Owner can execute / traverse."),
        (0o0040, "group read", "Group members can read."),
        (0o0020, "group write", "Group members can modify."),
        (0o0010, "group execute", "Group members can execute / traverse."),
        (0o0004, "other read", "Anyone can read."),
        (0o0002, "other write", "Anyone can modify."),
        (0o0001, "other execute", "Anyone can execute / traverse."),
    ]
    for weight, label, meaning in spec:
        rows.append(
            BitRow(weight, weight, label, meaning, (m & weight) != 0)
        )
    return rows


def explain_octal_digits(mode: int) -> List[dict]:
    m = clamp_mode(mode)
    labels = ["special", "owner", "group", "other"]
    out = []
    for i in range(4):
        shift = (3 - i) * 3
        digit = (m >> shift) & 0o7
        components: List[str] = []
        rwx = ""
        if i == 0:
            if digit & 4:
                components.append("4 (setuid)")
                rwx += "s"
            if digit & 2:
                components.append("2 (setgid)")
                rwx += "s"
            if digit & 1:
                components.append("1 (sticky)")
                rwx += "t"
            if not rwx:
                rwx = "---"
        else:
            if digit & 4:
                components.append("4 (read)")
                rwx += "r"
            else:
                rwx += "-"
            if digit & 2:
                components.append("2 (write)")
                rwx += "w"
            else:
                rwx += "-"
            if digit & 1:
                components.append("1 (execute)")
                rwx += "x"
            else:
                rwx += "-"
        out.append(
            {
                "label": labels[i],
                "digit": digit,
                "components": components,
                "rwx": rwx,
            }
        )
    return out


# ── High-level "describe a mode" helper ──────────────────────────


def describe_mode(mode: int) -> dict:
    m = clamp_mode(mode)
    return {
        "octal": to_octal(m),
        "octal_padded": to_octal4(m),
        "rwx": to_rwx_string(m),
        "symbolic_equals": to_symbolic_equals(m),
        "symbolic_delta": to_symbolic_delta(m),
        "owner": {
            "read": has_perm(m, "owner", "read"),
            "write": has_perm(m, "owner", "write"),
            "execute": has_perm(m, "owner", "execute"),
        },
        "group": {
            "read": has_perm(m, "group", "read"),
            "write": has_perm(m, "group", "write"),
            "execute": has_perm(m, "group", "execute"),
        },
        "other": {
            "read": has_perm(m, "other", "read"),
            "write": has_perm(m, "other", "write"),
            "execute": has_perm(m, "other", "execute"),
        },
        "setuid": has_special(m, "setuid"),
        "setgid": has_special(m, "setgid"),
        "sticky": has_special(m, "sticky"),
        "warnings": [
            {"level": w.level, "title": w.title, "detail": w.detail}
            for w in get_warnings(m)
        ],
        "digits": explain_octal_digits(m),
    }


# ── Input dispatcher ──────────────────────────────────────────────


def parse_any(value: str) -> Optional[int]:
    """Parse octal, ls-style rwx, or POSIX symbolic notation (against 0).

    Returns None on failure.
    """
    s = value.strip()
    if not s:
        return None
    # Octal
    n = parse_octal(s)
    if n is not None:
        return n
    # rwx
    n = parse_rwx_string(s)
    if n is not None:
        return n
    # POSIX symbolic against base 0
    try:
        return apply_symbolic(0, s)
    except ValueError:
        return None


def is_risky(mode: int) -> bool:
    return any(w.level in ("warn", "danger") for w in get_warnings(mode))


# ── Convenience iterables ────────────────────────────────────────


def iter_presets() -> Iterable[Preset]:
    return iter(PRESETS)
