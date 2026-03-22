"""JWT decoding and analysis logic."""

import base64
import json
import time


# ── Standard claims reference ───────────────────────────────────────

STANDARD_CLAIMS = {
    "iss": "Issuer",
    "sub": "Subject",
    "aud": "Audience",
    "exp": "Expiration Time",
    "nbf": "Not Before",
    "iat": "Issued At",
    "jti": "JWT ID",
}

# ── Algorithm definitions ───────────────────────────────────────────

ALGORITHMS = {
    "none": {"type": "none", "strength": "none", "desc": "No signature — unsigned token"},
    "HS256": {"type": "HMAC", "strength": "acceptable", "desc": "HMAC-SHA256 (symmetric)"},
    "HS384": {"type": "HMAC", "strength": "acceptable", "desc": "HMAC-SHA384 (symmetric)"},
    "HS512": {"type": "HMAC", "strength": "strong", "desc": "HMAC-SHA512 (symmetric)"},
    "RS256": {"type": "RSA", "strength": "strong", "desc": "RSASSA-PKCS1-v1_5 SHA-256 (asymmetric)"},
    "RS384": {"type": "RSA", "strength": "strong", "desc": "RSASSA-PKCS1-v1_5 SHA-384 (asymmetric)"},
    "RS512": {"type": "RSA", "strength": "strong", "desc": "RSASSA-PKCS1-v1_5 SHA-512 (asymmetric)"},
    "ES256": {"type": "ECDSA", "strength": "strong", "desc": "ECDSA P-256 SHA-256 (asymmetric)"},
    "ES384": {"type": "ECDSA", "strength": "strong", "desc": "ECDSA P-384 SHA-384 (asymmetric)"},
    "ES512": {"type": "ECDSA", "strength": "strong", "desc": "ECDSA P-521 SHA-512 (asymmetric)"},
    "PS256": {"type": "RSA", "strength": "strong", "desc": "RSASSA-PSS SHA-256 (asymmetric)"},
    "PS384": {"type": "RSA", "strength": "strong", "desc": "RSASSA-PSS SHA-384 (asymmetric)"},
    "PS512": {"type": "RSA", "strength": "strong", "desc": "RSASSA-PSS SHA-512 (asymmetric)"},
    "EdDSA": {"type": "EdDSA", "strength": "strong", "desc": "Edwards-curve DSA (asymmetric)"},
}

PRIVILEGE_CLAIMS = [
    "admin", "role", "roles", "scope", "permissions",
    "is_admin", "isAdmin", "is_superuser",
]


# ── Base64URL decode ────────────────────────────────────────────────

def _base64url_decode(data):
    """Decode a Base64URL-encoded string."""
    # Add padding
    padding = 4 - len(data) % 4
    if padding != 4:
        data += "=" * padding
    # Replace URL-safe chars
    data = data.replace("-", "+").replace("_", "/")
    return base64.b64decode(data)


# ── Decode ──────────────────────────────────────────────────────────

def decode_jwt(token):
    """Decode a JWT token into its components.

    Returns a dict with keys: header, payload, signature, header_raw, payload_raw.
    Raises ValueError on invalid tokens.
    """
    token = token.strip()
    parts = token.split(".")

    if len(parts) != 3:
        raise ValueError(f"Invalid JWT: expected 3 parts, got {len(parts)}")

    header_b64, payload_b64, signature_b64 = parts

    try:
        header = json.loads(_base64url_decode(header_b64).decode("utf-8"))
    except Exception:
        raise ValueError("Invalid JWT header: could not decode or parse as JSON")

    try:
        payload = json.loads(_base64url_decode(payload_b64).decode("utf-8"))
    except Exception:
        raise ValueError("Invalid JWT payload: could not decode or parse as JSON")

    return {
        "header": header,
        "payload": payload,
        "signature": signature_b64,
        "header_raw": header_b64,
        "payload_raw": payload_b64,
    }


# ── Timestamp helpers ───────────────────────────────────────────────

def format_relative_time(timestamp):
    """Format a Unix timestamp as a human-readable relative time."""
    now = time.time()
    diff = timestamp - now
    abs_diff = abs(diff)

    if abs_diff < 60:
        return "just now" if diff >= 0 else "just now"
    if abs_diff < 3600:
        mins = int(abs_diff // 60)
        unit = "minute" if mins == 1 else "minutes"
        return f"in {mins} {unit}" if diff >= 0 else f"{mins} {unit} ago"
    if abs_diff < 86400:
        hours = int(abs_diff // 3600)
        unit = "hour" if hours == 1 else "hours"
        return f"in {hours} {unit}" if diff >= 0 else f"{hours} {unit} ago"
    days = int(abs_diff // 86400)
    if days < 365:
        unit = "day" if days == 1 else "days"
        return f"in {days} {unit}" if diff >= 0 else f"{days} {unit} ago"
    years = int(days // 365)
    unit = "year" if years == 1 else "years"
    return f"in {years} {unit}" if diff >= 0 else f"{years} {unit} ago"


def get_expiration_status(payload):
    """Get the expiration status of a token payload.

    Returns: 'valid', 'expired', 'not-yet-valid', or 'no-expiry'.
    """
    now = time.time()

    nbf = payload.get("nbf")
    if isinstance(nbf, (int, float)) and now < nbf:
        return "not-yet-valid"

    exp = payload.get("exp")
    if isinstance(exp, (int, float)):
        return "expired" if now > exp else "valid"

    return "no-expiry"


# ── Security analysis ───────────────────────────────────────────────

def analyze_security(decoded):
    """Analyze a decoded JWT for security issues.

    Returns a list of dicts with keys: severity, title, description.
    severity is one of: critical, warning, info.
    """
    findings = []
    header = decoded["header"]
    payload = decoded["payload"]
    alg = str(header.get("alg", ""))

    # alg: none
    if alg.lower() == "none":
        findings.append({
            "severity": "critical",
            "title": 'Algorithm set to "none"',
            "description": "The token has no cryptographic signature. An attacker can modify the payload without detection (CVE-2015-9235).",
        })

    # Empty signature with signed algorithm
    if decoded["signature"] == "" and alg.lower() != "none":
        findings.append({
            "severity": "critical",
            "title": "Empty signature with signed algorithm",
            "description": f'Algorithm is "{alg}" but signature is empty. Possible alg:none bypass attempt.',
        })

    # Symmetric algorithm advisory
    if alg == "HS256":
        findings.append({
            "severity": "info",
            "title": "Symmetric signing (HS256)",
            "description": "Uses a shared secret for signing and verification. Consider RS256/ES256 for better key separation.",
        })

    # Missing expiration
    if "exp" not in payload:
        findings.append({
            "severity": "warning",
            "title": "No expiration (exp)",
            "description": "Token has no expiry — it remains valid indefinitely if compromised.",
        })

    # Long lifetime
    if isinstance(payload.get("exp"), (int, float)) and isinstance(payload.get("iat"), (int, float)):
        lifetime_days = (payload["exp"] - payload["iat"]) / 86400
        if lifetime_days > 30:
            findings.append({
                "severity": "warning",
                "title": f"Long lifetime ({int(lifetime_days)} days)",
                "description": "Token lifetime exceeds 30 days. Consider shorter lifetimes with refresh tokens.",
            })

    # Missing issuer
    if "iss" not in payload:
        findings.append({
            "severity": "info",
            "title": "No issuer (iss)",
            "description": "No issuer claim — cannot validate token origin.",
        })

    # Missing audience
    if "aud" not in payload:
        findings.append({
            "severity": "info",
            "title": "No audience (aud)",
            "description": "No audience claim — any service could accept this token.",
        })

    # iat in the future
    if isinstance(payload.get("iat"), (int, float)):
        if payload["iat"] > time.time() + 60:
            findings.append({
                "severity": "warning",
                "title": "Issued in the future",
                "description": "The iat timestamp is in the future — possible clock skew or manipulation.",
            })

    # Unknown algorithm
    if alg and alg.lower() != "none" and alg not in ALGORITHMS:
        findings.append({
            "severity": "info",
            "title": f"Unknown algorithm: {alg}",
            "description": f'"{alg}" is not a standard JOSE algorithm.',
        })

    # Privilege claims
    found_priv = [c for c in PRIVILEGE_CLAIMS if c in payload]
    if found_priv:
        findings.append({
            "severity": "info",
            "title": f"Privilege claims: {', '.join(found_priv)}",
            "description": "Token contains privilege-related claims that could be escalation targets if forgeable.",
        })

    return findings
