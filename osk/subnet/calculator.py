"""IPv4 subnet/CIDR calculation logic.

Uses Python's ipaddress stdlib module for reliable, well-tested IP math.
"""

import ipaddress
import math


def parse_cidr(cidr_str):
    """Parse a CIDR string and return an IPv4Network. Returns None on failure."""
    try:
        return ipaddress.IPv4Network(cidr_str.strip(), strict=False)
    except (ValueError, TypeError):
        return None


def parse_ip(ip_str):
    """Parse an IPv4 address string. Returns None on failure."""
    try:
        return ipaddress.IPv4Address(ip_str.strip())
    except (ValueError, TypeError):
        return None


def calculate(cidr_str):
    """Calculate full subnet details from a CIDR string.

    Returns a dict with all network details, or None on invalid input.
    """
    net = parse_cidr(cidr_str)
    if net is None:
        return None

    prefix = net.prefixlen
    total = net.num_addresses

    if prefix == 32:
        first_host = str(net.network_address)
        last_host = str(net.network_address)
        usable = 1
    elif prefix == 31:
        first_host = str(net.network_address)
        last_host = str(net.broadcast_address)
        usable = 2
    else:
        first_host = str(net.network_address + 1)
        last_host = str(net.broadcast_address - 1)
        usable = total - 2

    first_octet = int(net.network_address) >> 24
    if first_octet < 128:
        ip_class = "A"
    elif first_octet < 192:
        ip_class = "B"
    elif first_octet < 224:
        ip_class = "C"
    elif first_octet < 240:
        ip_class = "D (Multicast)"
    else:
        ip_class = "E (Reserved)"

    return {
        "cidr": str(net),
        "network": str(net.network_address),
        "broadcast": str(net.broadcast_address),
        "mask": str(net.netmask),
        "wildcard": str(net.hostmask),
        "first_host": first_host,
        "last_host": last_host,
        "total": total,
        "usable": max(0, usable),
        "prefix": prefix,
        "ip_class": ip_class,
        "private": net.is_private,
    }


def split_network(cidr_str, count):
    """Split a network into `count` equal subnets. Count must be a power of 2.

    Returns a list of dicts, or None on error.
    """
    net = parse_cidr(cidr_str)
    if net is None:
        return None

    if count < 2 or (count & (count - 1)) != 0:
        return None

    bits_needed = int(math.log2(count))
    new_prefix = net.prefixlen + bits_needed
    if new_prefix > 32:
        return None

    subnets = []
    for subnet in net.subnets(prefixlen_diff=bits_needed):
        total = subnet.num_addresses
        if new_prefix == 32:
            first_host = str(subnet.network_address)
            last_host = str(subnet.network_address)
            usable = 1
        elif new_prefix == 31:
            first_host = str(subnet.network_address)
            last_host = str(subnet.broadcast_address)
            usable = 2
        else:
            first_host = str(subnet.network_address + 1)
            last_host = str(subnet.broadcast_address - 1)
            usable = total - 2

        subnets.append({
            "cidr": str(subnet),
            "network": str(subnet.network_address),
            "broadcast": str(subnet.broadcast_address),
            "first_host": first_host,
            "last_host": last_host,
            "usable": max(0, usable),
        })

    return subnets


def contains(cidr_str, ip_str):
    """Check if an IP address is within a CIDR range.

    Returns True/False, or None on invalid input.
    """
    net = parse_cidr(cidr_str)
    addr = parse_ip(ip_str)
    if net is None or addr is None:
        return None
    return addr in net


def list_hosts(cidr_str, limit=256):
    """List all host IPs in a CIDR range, up to `limit`.

    Returns (list_of_ips, total_count, truncated).
    """
    net = parse_cidr(cidr_str)
    if net is None:
        return None, 0, False

    hosts = list(net.hosts())
    total = len(hosts)
    truncated = total > limit
    return [str(h) for h in hosts[:limit]], total, truncated
