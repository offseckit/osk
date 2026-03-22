"""Hash identification and generation logic."""

import hashlib
import re
import struct


# ── Hash type definitions ────────────────────────────────────────────

HASH_TYPES = [
    {
        "id": "md5",
        "name": "MD5",
        "length": 32,
        "bits": 128,
        "description": "128-bit hash, widely used but cryptographically broken",
    },
    {
        "id": "sha1",
        "name": "SHA-1",
        "length": 40,
        "bits": 160,
        "description": "160-bit hash, deprecated for security use",
    },
    {
        "id": "sha256",
        "name": "SHA-256",
        "length": 64,
        "bits": 256,
        "description": "256-bit hash from the SHA-2 family",
    },
    {
        "id": "sha384",
        "name": "SHA-384",
        "length": 96,
        "bits": 384,
        "description": "384-bit hash from the SHA-2 family",
    },
    {
        "id": "sha512",
        "name": "SHA-512",
        "length": 128,
        "bits": 512,
        "description": "512-bit hash from the SHA-2 family",
    },
    {
        "id": "ntlm",
        "name": "NTLM",
        "length": 32,
        "bits": 128,
        "description": "Windows NT LAN Manager hash (MD4 of UTF-16LE input)",
    },
    {
        "id": "sha3-256",
        "name": "SHA3-256",
        "length": 64,
        "bits": 256,
        "description": "256-bit hash from the SHA-3 (Keccak) family",
    },
    {
        "id": "sha3-512",
        "name": "SHA3-512",
        "length": 128,
        "bits": 512,
        "description": "512-bit hash from the SHA-3 (Keccak) family",
    },
]


# ── Hash identification ──────────────────────────────────────────────

def identify_hash(hash_string):
    """Identify a hash by its format, length, and character set.

    Returns a list of dicts with keys: type, confidence, reason.
    """
    trimmed = hash_string.strip()
    if not trimmed:
        return []

    matches = []

    # Check for $NT$ prefix
    if trimmed.upper().startswith("$NT$"):
        hash_part = trimmed[4:]
        if re.match(r"^[a-f0-9]{32}$", hash_part, re.IGNORECASE):
            ntlm = next(h for h in HASH_TYPES if h["id"] == "ntlm")
            return [{
                "type": ntlm,
                "confidence": "high",
                "reason": "32 hex chars with $NT$ prefix",
            }]

    # Strip 0x prefix
    clean = trimmed
    if clean.startswith(("0x", "0X")):
        clean = clean[2:]

    # Must be valid hex
    if not re.match(r"^[a-f0-9]+$", clean, re.IGNORECASE):
        return matches

    hex_len = len(clean)

    for hash_type in HASH_TYPES:
        if hash_type["length"] != hex_len:
            continue

        same_length = [h for h in HASH_TYPES if h["length"] == hex_len]
        if len(same_length) == 1:
            confidence = "high"
            reason = f"{hex_len} hex characters (unique length for {hash_type['name']})"
        else:
            confidence = "medium"
            names = " or ".join(h["name"] for h in same_length)
            reason = f"{hex_len} hex characters — could be {names}"

        matches.append({
            "type": hash_type,
            "confidence": confidence,
            "reason": reason,
        })

    return matches


# ── Hash generation ──────────────────────────────────────────────────

def _md4(data):
    """Minimal MD4 implementation for NTLM hash generation."""
    msg_len = len(data)
    bit_len = msg_len * 8

    # Padding
    padded_len = ((msg_len + 9 + 63) // 64) * 64
    padded = bytearray(padded_len)
    padded[:msg_len] = data
    padded[msg_len] = 0x80
    struct.pack_into("<Q", padded, padded_len - 8, bit_len)

    # Initial state
    a0, b0, c0, d0 = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476
    mask = 0xFFFFFFFF

    def rotl(x, n):
        return ((x << n) | (x >> (32 - n))) & mask

    for offset in range(0, padded_len, 64):
        X = list(struct.unpack_from("<16I", padded, offset))
        a, b, c, d = a0, b0, c0, d0

        # Round 1
        r1_idx = list(range(16))
        r1_shift = [3, 7, 11, 19]
        for i in range(16):
            f = (b & c) | (~b & d) & mask
            val = (a + f + X[r1_idx[i]]) & mask
            a, b, c, d = d, rotl(val, r1_shift[i % 4]), b, c

        # Round 2
        r2_idx = [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15]
        r2_shift = [3, 5, 9, 13]
        for i in range(16):
            f = (b & c) | (b & d) | (c & d)
            val = (a + (f & mask) + X[r2_idx[i]] + 0x5A827999) & mask
            a, b, c, d = d, rotl(val, r2_shift[i % 4]), b, c

        # Round 3
        r3_idx = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15]
        r3_shift = [3, 9, 11, 15]
        for i in range(16):
            f = b ^ c ^ d
            val = (a + (f & mask) + X[r3_idx[i]] + 0x6ED9EBA1) & mask
            a, b, c, d = d, rotl(val, r3_shift[i % 4]), b, c

        a0 = (a0 + a) & mask
        b0 = (b0 + b) & mask
        c0 = (c0 + c) & mask
        d0 = (d0 + d) & mask

    return struct.pack("<4I", a0, b0, c0, d0)


def generate_ntlm(text):
    """Generate an NTLM hash (MD4 of UTF-16LE input)."""
    utf16 = text.encode("utf-16-le")
    return _md4(utf16).hex()


def generate_hash(algorithm, text):
    """Generate a hash of the given text using the specified algorithm.

    Supported algorithms: md5, sha1, sha256, sha384, sha512, ntlm, sha3-256, sha3-512
    """
    if algorithm == "ntlm":
        return generate_ntlm(text)

    algo_map = {
        "md5": "md5",
        "sha1": "sha1",
        "sha256": "sha256",
        "sha384": "sha384",
        "sha512": "sha512",
        "sha3-256": "sha3_256",
        "sha3-512": "sha3_512",
    }

    hashlib_name = algo_map.get(algorithm)
    if not hashlib_name:
        raise ValueError(f"Unsupported algorithm: {algorithm}")

    h = hashlib.new(hashlib_name)
    h.update(text.encode("utf-8"))
    return h.hexdigest()


def list_algorithms():
    """Return a list of supported hash algorithms."""
    return [{"id": h["id"], "name": h["name"], "bits": h["bits"]} for h in HASH_TYPES]
