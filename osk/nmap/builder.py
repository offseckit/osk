"""Nmap command builder logic."""


# ── Scan types ─────────────────────────────────────────────────────

SCAN_TYPES = {
    "syn": {"flag": "-sS", "name": "SYN Scan (Stealth)", "root": True,
            "desc": "Default stealth scan. Sends SYN without completing handshake."},
    "connect": {"flag": "-sT", "name": "TCP Connect", "root": False,
                "desc": "Full TCP handshake. Works without root."},
    "udp": {"flag": "-sU", "name": "UDP Scan", "root": True,
            "desc": "Scan UDP ports. Slower but essential for DNS, SNMP, DHCP."},
    "null": {"flag": "-sN", "name": "NULL Scan", "root": True,
             "desc": "No TCP flags set. Can bypass some firewalls."},
    "fin": {"flag": "-sF", "name": "FIN Scan", "root": True,
            "desc": "Only FIN flag. Can bypass SYN-filtering firewalls."},
    "xmas": {"flag": "-sX", "name": "Xmas Scan", "root": True,
             "desc": "FIN+PSH+URG flags. Can bypass some firewalls."},
    "ack": {"flag": "-sA", "name": "ACK Scan", "root": True,
            "desc": "Map firewall rules. Shows filtered vs unfiltered ports."},
    "window": {"flag": "-sW", "name": "Window Scan", "root": True,
               "desc": "Like ACK scan but uses TCP Window to differentiate ports."},
}

# ── Timing templates ───────────────────────────────────────────────

TIMING_TEMPLATES = {
    0: {"name": "Paranoid", "desc": "Extremely slow. For IDS evasion."},
    1: {"name": "Sneaky", "desc": "Slow, 15-second probe delay."},
    2: {"name": "Polite", "desc": "Slower to reduce bandwidth usage."},
    3: {"name": "Normal", "desc": "Default timing."},
    4: {"name": "Aggressive", "desc": "Fast. Good for internal networks."},
    5: {"name": "Insane", "desc": "Fastest. May miss ports on slow networks."},
}

# ── NSE script categories ─────────────────────────────────────────

NSE_CATEGORIES = [
    "default", "safe", "vuln", "discovery", "auth",
    "brute", "exploit", "intrusive", "broadcast", "malware",
]

# ── Presets ─────────────────────────────────────────────────────────

PRESETS = {
    "quick": {
        "name": "Quick Recon",
        "desc": "Top 100 ports with version detection",
        "args": ["-sS", "-sV", "-F", "-T4", "--open"],
    },
    "full": {
        "name": "Full Port Scan",
        "desc": "All 65535 TCP ports with version detection",
        "args": ["-sS", "-sV", "-p-", "-T4", "--open"],
    },
    "stealth": {
        "name": "Stealth Scan",
        "desc": "Low-noise scan for monitored environments",
        "args": ["-sS", "-T2", "--open"],
    },
    "vuln": {
        "name": "Vulnerability Scan",
        "desc": "Version detection + vulnerability scripts",
        "args": ["-sS", "-sV", "-O", "-sC", "--script", "vuln", "-T4", "--open"],
    },
    "aggressive": {
        "name": "Aggressive Scan",
        "desc": "OS detection, versions, scripts, traceroute",
        "args": ["-A", "-T4"],
    },
    "udp": {
        "name": "UDP Scan",
        "desc": "Top 100 UDP ports with version detection",
        "args": ["-sU", "-sV", "--top-ports", "100", "-T4", "--open"],
    },
}


def build_command(
    target,
    scan_type="syn",
    ports=None,
    top_ports=None,
    all_ports=False,
    fast=False,
    service_version=False,
    os_detection=False,
    default_scripts=False,
    aggressive=False,
    timing=None,
    scripts=None,
    script_categories=None,
    no_ping=False,
    open_only=False,
    verbose=False,
    output_format=None,
    output_file=None,
    fragment=False,
    decoys=None,
    source_port=None,
    ipv6=False,
    reason=False,
    traceroute=False,
):
    """Build an nmap command string from options.

    Returns the command as a string for display.
    """
    parts = ["nmap"]

    # Scan type
    if not aggressive:
        st = SCAN_TYPES.get(scan_type, SCAN_TYPES["syn"])
        parts.append(st["flag"])

    # Ports
    if ports:
        parts.extend(["-p", ports])
    elif top_ports:
        parts.extend(["--top-ports", str(top_ports)])
    elif all_ports:
        parts.append("-p-")
    elif fast:
        parts.append("-F")

    # Detection
    if aggressive:
        parts.append("-A")
    else:
        if service_version:
            parts.append("-sV")
        if os_detection:
            parts.append("-O")
        if default_scripts:
            parts.append("-sC")
        if traceroute:
            parts.append("--traceroute")

    # NSE scripts
    script_parts = []
    if script_categories:
        script_parts.extend(script_categories)
    if scripts:
        script_parts.extend(scripts)
    if script_parts:
        parts.extend(["--script", ",".join(script_parts)])

    # Timing
    if timing is not None and timing != 3:
        parts.append(f"-T{timing}")

    # Host discovery
    if no_ping:
        parts.append("-Pn")

    # IPv6
    if ipv6:
        parts.append("-6")

    # Output modifiers
    if open_only:
        parts.append("--open")
    if verbose:
        parts.append("-v")
    if reason:
        parts.append("--reason")

    # Evasion
    if fragment:
        parts.append("-f")
    if decoys:
        parts.extend(["-D", decoys])
    if source_port:
        parts.extend(["--source-port", str(source_port)])

    # Output format
    if output_format and output_file:
        fmt_map = {"normal": "-oN", "xml": "-oX", "grepable": "-oG", "all": "-oA"}
        flag = fmt_map.get(output_format)
        if flag:
            parts.extend([flag, output_file])

    # Target
    parts.append(target if target else "<target>")

    return " ".join(parts)
