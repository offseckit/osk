"""Encoding and decoding operations."""

import base64
import codecs
import html
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
    "binary-encode": {"name": "Binary Encode", "fn": binary_encode, "category": "encode"},
    "binary-decode": {"name": "Binary Decode", "fn": binary_decode, "category": "decode"},
    "decimal-encode": {"name": "Decimal Encode", "fn": decimal_encode, "category": "encode"},
    "decimal-decode": {"name": "Decimal Decode", "fn": decimal_decode, "category": "decode"},
    "octal-encode": {"name": "Octal Encode", "fn": octal_encode, "category": "encode"},
    "octal-decode": {"name": "Octal Decode", "fn": octal_decode, "category": "decode"},
    "rot13": {"name": "ROT13", "fn": rot13, "category": "encode"},
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
