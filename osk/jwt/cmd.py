"""JWT subcommand for osk."""

import json
import sys
import time

import click

from .decoder import (
    ALGORITHMS,
    STANDARD_CLAIMS,
    decode_jwt,
    analyze_security,
    get_expiration_status,
    format_relative_time,
)


@click.group(invoke_without_command=True)
@click.pass_context
def jwt(ctx):
    """Decode and analyze JWT tokens.

    \b
    Examples:
      osk jwt decode eyJhbGciOiJIUzI1NiIs...
      osk jwt decode -i "eyJhbGciOiJIUzI1NiIs..."
      echo "eyJ..." | osk jwt decode
      osk jwt analyze eyJhbGciOiJIUzI1NiIs...
      osk jwt algorithms
    """
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


@jwt.command("decode")
@click.argument("token", nargs=-1)
@click.option("-i", "--input", "input_text", default=None, help="JWT token (reads stdin if omitted)")
@click.option("--json-output", "json_out", is_flag=True, help="Output as JSON")
def decode(token, input_text, json_out):
    """Decode a JWT token and display header, payload, and signature."""
    data = _get_input(token, input_text)

    try:
        decoded = decode_jwt(data)
    except ValueError as e:
        raise click.ClickException(str(e))

    if json_out:
        click.echo(json.dumps({
            "header": decoded["header"],
            "payload": decoded["payload"],
            "signature": decoded["signature"],
        }, indent=2))
        return

    # Header
    click.secho("\n  # Header", fg="bright_magenta")
    _print_json(decoded["header"])

    # Algorithm info
    alg = decoded["header"].get("alg", "")
    alg_info = ALGORITHMS.get(alg) or (ALGORITHMS.get("none") if str(alg).lower() == "none" else None)
    if alg_info:
        strength_color = {
            "none": "red", "weak": "yellow", "acceptable": "yellow", "strong": "green"
        }.get(alg_info["strength"], "white")
        click.secho(f"  Algorithm: {alg}", fg="cyan", nl=False)
        click.secho(f" [{alg_info['strength']}]", fg=strength_color, nl=False)
        click.secho(f" — {alg_info['desc']}", fg="bright_black")

    # Payload
    click.secho("\n  # Payload", fg="green")
    _print_json(decoded["payload"])

    # Annotate standard claims
    payload = decoded["payload"]
    for key, value in payload.items():
        if key in STANDARD_CLAIMS:
            label = STANDARD_CLAIMS[key]
            if key in ("exp", "iat", "nbf") and isinstance(value, (int, float)):
                ts = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(value))
                rel = format_relative_time(value)
                click.secho(f"    {key}", fg="cyan", nl=False)
                click.secho(f" ({label})", fg="bright_black", nl=False)
                click.secho(f": {ts}", nl=False)
                click.secho(f"  {rel}", fg="yellow")
            else:
                click.secho(f"    {key}", fg="cyan", nl=False)
                click.secho(f" ({label})", fg="bright_black")

    # Expiration status
    status = get_expiration_status(payload)
    status_color = {
        "valid": "green", "expired": "red",
        "not-yet-valid": "yellow", "no-expiry": "yellow",
    }.get(status, "white")
    status_label = {
        "valid": "VALID", "expired": "EXPIRED",
        "not-yet-valid": "NOT YET VALID", "no-expiry": "NO EXPIRATION SET",
    }.get(status, status)
    click.secho(f"\n  Status: {status_label}", fg=status_color)

    # Signature
    sig = decoded["signature"]
    click.secho("\n  # Signature", fg="cyan")
    click.secho(f"  {sig if sig else '(empty)'}", fg="bright_black")
    click.echo()


@jwt.command("analyze")
@click.argument("token", nargs=-1)
@click.option("-i", "--input", "input_text", default=None, help="JWT token (reads stdin if omitted)")
@click.option("--json-output", "json_out", is_flag=True, help="Output as JSON")
def analyze(token, input_text, json_out):
    """Analyze a JWT token for security issues."""
    data = _get_input(token, input_text)

    try:
        decoded = decode_jwt(data)
    except ValueError as e:
        raise click.ClickException(str(e))

    findings = analyze_security(decoded)

    if json_out:
        click.echo(json.dumps(findings, indent=2))
        return

    if not findings:
        click.secho("\n  No security findings.", fg="green")
        click.echo()
        return

    severity_order = {"critical": 0, "warning": 1, "info": 2}
    findings.sort(key=lambda f: severity_order.get(f["severity"], 3))

    click.secho(f"\n  # Security Analysis ({len(findings)} finding{'s' if len(findings) != 1 else ''})", fg="red")
    click.echo()

    for finding in findings:
        sev = finding["severity"]
        color = {"critical": "red", "warning": "yellow", "info": "cyan"}.get(sev, "white")
        icon = {"critical": "!!!", "warning": " ! ", "info": " i "}.get(sev, " ? ")
        click.secho(f"  [{icon}]", fg=color, nl=False)
        click.secho(f" {finding['title']}", fg=color, bold=True)
        click.secho(f"       {finding['description']}", fg="bright_black")
        click.echo()


@jwt.command("algorithms")
def algorithms_cmd():
    """List all known JWT signing algorithms."""
    click.secho(f"  {'Algorithm':<10} {'Type':<8} {'Strength':<12} Description", fg="bright_black")
    click.secho(f"  {'─' * 10} {'─' * 8} {'─' * 12} {'─' * 30}", fg="bright_black")

    for name, info in ALGORITHMS.items():
        strength_color = {
            "none": "red", "weak": "yellow", "acceptable": "yellow", "strong": "green"
        }.get(info["strength"], "white")
        click.secho(f"  {name:<10}", fg="cyan", nl=False)
        click.secho(f" {info['type']:<8}", nl=False)
        click.secho(f" {info['strength']:<12}", fg=strength_color, nl=False)
        click.echo(f" {info['desc']}")


# ── Helpers ─────────────────────────────────────────────────────────

def _get_input(token_args, input_option):
    """Resolve input from argument, option, or stdin."""
    if input_option is not None:
        return input_option.strip()
    if token_args:
        return " ".join(token_args).strip()
    if not sys.stdin.isatty():
        return sys.stdin.read().strip()
    raise click.ClickException(
        "No token provided. Pass a JWT as an argument, use -i, or pipe via stdin."
    )


def _print_json(data):
    """Pretty-print a dict as indented JSON."""
    formatted = json.dumps(data, indent=2)
    for line in formatted.split("\n"):
        click.echo(f"  {line}")
