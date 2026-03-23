"""Encoding and decoding operations."""

import base64
import codecs
import html
import re
from urllib.parse import quote, unquote


def base64_encode(data: str) -> str:
    """Encode text to Base64."""
    return base64.b64encode(data.encode("utf-8")).decode("ascii")


def base64_decode(data: str) -> str:
    """Decode Base64 to text."""
    return base64.b64decode(data.strip()).decode("utf-8")


def url_encode(data: str) -> str:
    """Percent-encode special characters."""
    return quote(data, safe="")


def url_decode(data: str) -> str:
    """Decode percent-encoded text."""
    return unquote(data)


def url_encode_full(data: str) -> str:
    """Encode all characters as percent-encoded hex."""
    return "".join(f"%{b:02X}" for b in data.encode("utf-8"))


def hex_encode(data: str) -> str:
    """Convert text to hexadecimal."""
    return data.encode("utf-8").hex()


def hex_decode(data: str) -> str:
    """Convert hexadecimal to text."""
    clean = data.replace(" ", "").replace(":", "").replace("0x", "").replace(",", "")
    return bytes.fromhex(clean).decode("utf-8")


def hex_encode_prefixed(data: str) -> str:
    r"""Convert text to \x prefixed hex bytes."""
    return "".join(f"\\x{b:02x}" for b in data.encode("utf-8"))


def html_encode(data: str) -> str:
    """Encode special characters as HTML entities."""
    return html.escape(data, quote=True)


def html_decode(data: str) -> str:
    """Decode HTML entities to characters."""
    return html.unescape(data)


def html_encode_all(data: str) -> str:
    """Encode all characters as numeric HTML entities."""
    return "".join(f"&#{ord(c)};" for c in data)


def unicode_escape(data: str) -> str:
    r"""Convert text to \uXXXX escape sequences."""
    result = []
    for c in data:
        cp = ord(c)
        if cp > 0xFFFF:
            result.append(f"\\u{{{cp:x}}}")
        else:
            result.append(f"\\u{cp:04x}")
    return "".join(result)


def unicode_unescape(data: str) -> str:
    r"""Convert \uXXXX sequences to text."""
    return codecs.decode(data, "unicode_escape")


def binary_encode(data: str) -> str:
    """Convert text to 8-bit binary."""
    return " ".join(f"{b:08b}" for b in data.encode("utf-8"))


def binary_decode(data: str) -> str:
    """Convert binary to text."""
    parts = data.strip().split()
    return bytes(int(b, 2) for b in parts).decode("utf-8")


def decimal_encode(data: str) -> str:
    """Convert text to decimal byte values."""
    return " ".join(str(b) for b in data.encode("utf-8"))


def decimal_decode(data: str) -> str:
    """Convert decimal byte values to text."""
    parts = data.strip().replace(",", " ").split()
    return bytes(int(b) for b in parts).decode("utf-8")


def octal_encode(data: str) -> str:
    """Convert text to octal byte values."""
    return " ".join(f"{b:03o}" for b in data.encode("utf-8"))


def octal_decode(data: str) -> str:
    """Convert octal byte values to text."""
    parts = data.strip().split()
    return bytes(int(b, 8) for b in parts).decode("utf-8")


def base64url_encode(data: str) -> str:
    """Encode text to URL-safe Base64 (used in JWTs)."""
    return base64.urlsafe_b64encode(data.encode("utf-8")).rstrip(b"=").decode("ascii")


def base64url_decode(data: str) -> str:
    """Decode URL-safe Base64 to text."""
    s = data.strip()
    # Add back padding
    s += "=" * (4 - len(s) % 4) if len(s) % 4 else ""
    return base64.urlsafe_b64decode(s).decode("utf-8")


def base32_encode(data: str) -> str:
    """Encode text to Base32 (used in TOTP, DNS tunneling)."""
    return base64.b32encode(data.encode("utf-8")).decode("ascii")


def base32_decode(data: str) -> str:
    """Decode Base32 to text."""
    s = data.strip().upper()
    # Add back padding if needed
    while len(s) % 8:
        s += "="
    return base64.b32decode(s).decode("utf-8")


def base58_encode(data: str) -> str:
    """Encode text to Base58 (used in Bitcoin, IPFS)."""
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    raw = data.encode("utf-8")
    num = int.from_bytes(raw, "big") if raw else 0
    result = ""
    while num > 0:
        num, remainder = divmod(num, 58)
        result = alphabet[remainder] + result
    # Preserve leading zero bytes
    for byte in raw:
        if byte == 0:
            result = "1" + result
        else:
            break
    return result or "1"


def base58_decode(data: str) -> str:
    """Decode Base58 to text."""
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    s = data.strip()
    num = 0
    for c in s:
        idx = alphabet.index(c)
        if idx < 0:
            raise ValueError(f"Invalid Base58 character: {c}")
        num = num * 58 + idx
    # Count leading '1's (zero bytes)
    leading_zeros = 0
    for c in s:
        if c == "1":
            leading_zeros += 1
        else:
            break
    if num == 0:
        raw = b""
    else:
        hex_str = format(num, "x")
        if len(hex_str) % 2:
            hex_str = "0" + hex_str
        raw = bytes.fromhex(hex_str)
    return (b"\x00" * leading_zeros + raw).decode("utf-8")


def punycode_encode(data: str) -> str:
    """Encode domain to Punycode (IDN homograph attack analysis)."""
    return data.encode("idna").decode("ascii")


def punycode_decode(data: str) -> str:
    """Decode Punycode to Unicode domain."""
    return data.strip().encode("ascii").decode("idna")


def rot47(data: str) -> str:
    """Rotate printable ASCII characters by 47 positions."""
    result = []
    for c in data:
        code = ord(c)
        if 33 <= code <= 126:
            result.append(chr(((code - 33 + 47) % 94) + 33))
        else:
            result.append(c)
    return "".join(result)


def rot13(data: str) -> str:
    """Rotate letters by 13 positions."""
    return codecs.decode(data, "rot_13")


def reverse_str(data: str) -> str:
    """Reverse the input string."""
    return data[::-1]


def to_uppercase(data: str) -> str:
    """Convert text to uppercase."""
    return data.upper()


def to_lowercase(data: str) -> str:
    """Convert text to lowercase."""
    return data.lower()


OPERATIONS = {
    "base64-encode": {"name": "Base64 Encode", "fn": base64_encode, "category": "encode"},
    "base64-decode": {"name": "Base64 Decode", "fn": base64_decode, "category": "decode"},
    "base64url-encode": {"name": "Base64url Encode", "fn": base64url_encode, "category": "encode"},
    "base64url-decode": {"name": "Base64url Decode", "fn": base64url_decode, "category": "decode"},
    "base32-encode": {"name": "Base32 Encode", "fn": base32_encode, "category": "encode"},
    "base32-decode": {"name": "Base32 Decode", "fn": base32_decode, "category": "decode"},
    "base58-encode": {"name": "Base58 Encode", "fn": base58_encode, "category": "encode"},
    "base58-decode": {"name": "Base58 Decode", "fn": base58_decode, "category": "decode"},
    "url-encode": {"name": "URL Encode", "fn": url_encode, "category": "encode"},
    "url-decode": {"name": "URL Decode", "fn": url_decode, "category": "decode"},
    "url-encode-full": {"name": "URL Encode (Full)", "fn": url_encode_full, "category": "encode"},
    "hex-encode": {"name": "Hex Encode", "fn": hex_encode, "category": "encode"},
    "hex-decode": {"name": "Hex Decode", "fn": hex_decode, "category": "decode"},
    "hex-encode-prefixed": {"name": "Hex Encode (\\x prefix)", "fn": hex_encode_prefixed, "category": "encode"},
    "html-encode": {"name": "HTML Entity Encode", "fn": html_encode, "category": "encode"},
    "html-decode": {"name": "HTML Entity Decode", "fn": html_decode, "category": "decode"},
    "html-encode-all": {"name": "HTML Entity Encode (All)", "fn": html_encode_all, "category": "encode"},
    "unicode-escape": {"name": "Unicode Escape", "fn": unicode_escape, "category": "encode"},
    "unicode-unescape": {"name": "Unicode Unescape", "fn": unicode_unescape, "category": "decode"},
    "punycode-encode": {"name": "Punycode Encode", "fn": punycode_encode, "category": "encode"},
    "punycode-decode": {"name": "Punycode Decode", "fn": punycode_decode, "category": "decode"},
    "binary-encode": {"name": "Binary Encode", "fn": binary_encode, "category": "encode"},
    "binary-decode": {"name": "Binary Decode", "fn": binary_decode, "category": "decode"},
    "decimal-encode": {"name": "Decimal Encode", "fn": decimal_encode, "category": "encode"},
    "decimal-decode": {"name": "Decimal Decode", "fn": decimal_decode, "category": "decode"},
    "octal-encode": {"name": "Octal Encode", "fn": octal_encode, "category": "encode"},
    "octal-decode": {"name": "Octal Decode", "fn": octal_decode, "category": "decode"},
    "rot13": {"name": "ROT13", "fn": rot13, "category": "encode"},
    "rot47": {"name": "ROT47", "fn": rot47, "category": "encode"},
    "reverse": {"name": "Reverse String", "fn": reverse_str, "category": "encode"},
    "uppercase": {"name": "Uppercase", "fn": to_uppercase, "category": "encode"},
    "lowercase": {"name": "Lowercase", "fn": to_lowercase, "category": "encode"},
}


def run_operation(op_id: str, data: str) -> str:
    """Run a single encoding/decoding operation."""
    if op_id not in OPERATIONS:
        raise ValueError(f"Unknown operation: {op_id}. Use 'encode list' to see available operations.")
    return OPERATIONS[op_id]["fn"](data)


def run_chain(data: str, op_ids: list) -> list:
    """Run a chain of operations, returning intermediate results."""
    results = []
    current = data
    for op_id in op_ids:
        current = run_operation(op_id, current)
        results.append({"operation": op_id, "name": OPERATIONS[op_id]["name"], "output": current})
    return results


def list_operations() -> list:
    """List all available operations."""
    return [
        {"id": op_id, "name": op["name"], "category": op["category"]}
        for op_id, op in OPERATIONS.items()
    ]


def detect_encoding(data: str) -> list:
    """Analyze input and suggest what encoding(s) it might be."""
    results = []
    trimmed = data.strip()
    if not trimmed:
        return results

    # Base64: valid chars, length divisible by 4 (with padding)
    if re.match(r"^[A-Za-z0-9+/]+=*$", trimmed) and len(trimmed) >= 4:
        try:
            base64.b64decode(trimmed)
            confidence = "high" if len(trimmed) % 4 == 0 else "medium"
            results.append({"id": "base64-decode", "name": "Base64 Decode", "confidence": confidence})
        except Exception:
            pass

    # Base64url: valid chars with - and _ instead of + and /
    if re.match(r"^[A-Za-z0-9_-]+$", trimmed) and len(trimmed) >= 4 and ("-" in trimmed or "_" in trimmed):
        try:
            s = trimmed + "=" * (4 - len(trimmed) % 4) if len(trimmed) % 4 else trimmed
            base64.urlsafe_b64decode(s)
            results.append({"id": "base64url-decode", "name": "Base64url Decode", "confidence": "medium"})
        except Exception:
            pass

    # URL-encoded: contains %XX patterns
    pct_matches = re.findall(r"%[0-9A-Fa-f]{2}", trimmed)
    if pct_matches:
        confidence = "high" if len(pct_matches) > 3 else "medium"
        results.append({"id": "url-decode", "name": "URL Decode", "confidence": confidence})

    # Hex: only hex chars, even length
    hex_clean = re.sub(r"[\s:,]", "", trimmed).replace("0x", "")
    if re.match(r"^[0-9A-Fa-f]+$", hex_clean) and len(hex_clean) >= 4 and len(hex_clean) % 2 == 0:
        confidence = "medium" if len(trimmed) > 8 else "low"
        results.append({"id": "hex-decode", "name": "Hex Decode", "confidence": confidence})

    # Hex with \x prefix
    if re.search(r"\\x[0-9A-Fa-f]{2}", trimmed):
        results.append({"id": "hex-decode", "name": "Hex Decode (\\x prefixed)", "confidence": "high"})

    # HTML entities
    if re.search(r"&(?:#\d+|#x[0-9a-fA-F]+|[a-zA-Z]+);", trimmed):
        entity_count = len(re.findall(r"&(?:#\d+|#x[0-9a-fA-F]+|[a-zA-Z]+);", trimmed))
        confidence = "high" if entity_count > 2 else "medium"
        results.append({"id": "html-decode", "name": "HTML Entity Decode", "confidence": confidence})

    # Unicode escape
    if re.search(r"\\u[0-9a-fA-F]{4}|\\u\{[0-9a-fA-F]+\}", trimmed):
        results.append({"id": "unicode-unescape", "name": "Unicode Unescape", "confidence": "high"})

    # Binary: 8-bit groups of 0s and 1s
    if re.match(r"^[01]{8}(\s+[01]{8})*$", trimmed):
        results.append({"id": "binary-decode", "name": "Binary Decode", "confidence": "high"})

    # Decimal: space/comma-separated numbers 0-255
    dec_parts = re.split(r"[\s,]+", trimmed)
    if len(dec_parts) >= 2 and all(
        re.match(r"^\d+$", p) and 0 <= int(p) <= 255 for p in dec_parts
    ):
        results.append({"id": "decimal-decode", "name": "Decimal (ASCII) Decode", "confidence": "medium"})

    # Octal: space-separated 3-digit octal values
    if re.match(r"^[0-7]{3}(\s+[0-7]{3})*$", trimmed):
        results.append({"id": "octal-decode", "name": "Octal Decode", "confidence": "medium"})

    # Base32: only A-Z2-7 with optional = padding
    if re.match(r"^[A-Z2-7]+=*$", trimmed.upper()) and len(trimmed) >= 4:
        if re.search(r"[2-7]", trimmed) or trimmed.endswith("="):
            confidence = "high" if trimmed.endswith("=") else "low"
            results.append({"id": "base32-decode", "name": "Base32 Decode", "confidence": confidence})

    # Base58: only Base58 alphabet chars
    if re.match(r"^[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+$", trimmed) and len(trimmed) >= 20:
        results.append({"id": "base58-decode", "name": "Base58 Decode", "confidence": "low"})

    # Punycode: xn-- prefix
    if re.search(r"xn--", trimmed, re.IGNORECASE):
        results.append({"id": "punycode-decode", "name": "Punycode Decode", "confidence": "high"})

    # ROT13: only letters and common punctuation
    if re.match(r"^[a-zA-Z\s.,!?;:\'\"()-]+$", trimmed) and len(trimmed) >= 4:
        results.append({"id": "rot13", "name": "ROT13", "confidence": "low"})

    return results
