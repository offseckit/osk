"""Headers subcommand for osk."""

import sys

import click

from .analyzer import analyze, list_headers


@click.group(invoke_without_command=True)
@click.pass_context
def headers(ctx):
    """Analyze HTTP response headers for security misconfigurations.

    \b
    Paste headers, read from a file, or fetch directly from a URL.

    \b
    Examples:
      osk headers analyze -u https://example.com
      curl -sI https://example.com | osk headers analyze
      osk headers analyze -f response.txt
      osk headers list
    """
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


@headers.command("analyze")
@click.option("-u", "--url", default=None, help="Fetch headers from a URL")
@click.option("-f", "--file", "file_path", default=None,
              type=click.Path(exists=True),
              help="Read headers from a file instead of stdin")
@click.option("--json", "json_output", is_flag=True, default=False,
              help="Output results as JSON")
def analyze_cmd(url, file_path, json_output):
    """Analyze HTTP response headers for security issues.

    \b
    Fetch from a URL, read from stdin/file, or pipe from curl.

    \b
    Examples:
      osk headers analyze -u https://example.com
      curl -sI https://example.com | osk headers analyze
      osk headers analyze -f response-headers.txt
      osk headers analyze --json -u https://example.com
    """
    if url:
        import urllib.request
        import urllib.error
        try:
            req = urllib.request.Request(url, method="HEAD")
            req.add_header("User-Agent", "osk/0.1.0")
            with urllib.request.urlopen(req, timeout=10) as resp:
                raw = "\r\n".join(f"{k}: {v}" for k, v in resp.getheaders())
        except urllib.error.URLError as e:
            raise click.ClickException(f"Failed to fetch {url}: {e}")
        except Exception as e:
            raise click.ClickException(f"Failed to fetch {url}: {e}")
    elif file_path:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            raw = f.read()
    elif not sys.stdin.isatty():
        raw = sys.stdin.read()
    else:
        raise click.ClickException(
            "No input. Use -u to fetch from a URL, pipe via stdin, or use -f for a file.\n"
            "  Example: osk headers analyze -u https://example.com"
        )

    raw = raw.strip()
    if not raw:
        raise click.ClickException("Empty input. Provide HTTP response headers.")

    result = analyze(raw)

    if json_output:
        import json
        out = {
            "grade": result["grade"],
            "score": result["score"],
            "summary": result["summary"],
            "checks": [
                {"severity": s, "header": h, "description": d, "recommendation": r}
                for s, h, d, r in result["checks"]
            ],
            "csp_findings": [
                {"severity": s, "directive": di, "description": d}
                for s, di, d in result["csp_findings"]
            ],
        }
        click.echo(json.dumps(out, indent=2))
        return

    if not result["headers"]:
        click.secho("  No valid headers found in input.", fg="yellow")
        return

    # Grade banner
    click.echo()
    grade_colors = {
        "A+": "green", "A": "green", "B": "yellow",
        "C": "yellow", "D": "red", "F": "red",
    }
    color = grade_colors.get(result["grade"], "white")
    click.secho(f"  Grade: {result['grade']}  Score: {result['score']}/100", fg=color, bold=True)
    s = result["summary"]
    click.secho(
        f"  {s['pass']} pass | {s['warn']} warn | {s['fail']} fail | {s['info']} info",
        fg="bright_black",
    )
    click.echo()

    # Security checks
    severity_order = {"fail": 0, "warn": 1, "pass": 2, "info": 3}
    severity_colors = {"pass": "green", "warn": "yellow", "fail": "red", "info": "cyan"}
    severity_icons = {"pass": "+", "warn": "!", "fail": "x", "info": "i"}

    sorted_checks = sorted(result["checks"], key=lambda c: severity_order.get(c[0], 4))

    for sev, header, desc, rec in sorted_checks:
        icon = severity_icons[sev]
        color = severity_colors[sev]
        click.secho(f"  [{icon}] ", fg=color, nl=False)
        click.secho(header, fg="cyan", nl=False)
        click.secho(f"  {desc}", fg="bright_black")
        if rec:
            click.secho(f"      Fix: {header}: {rec}", fg="green")
        click.echo()

    # CSP findings
    if result["csp_findings"]:
        click.secho("  # CSP Analysis", fg="yellow")
        click.echo()
        for sev, directive, desc in result["csp_findings"]:
            color = severity_colors.get(sev, "white")
            click.secho(f"    [{sev}] ", fg=color, nl=False)
            click.secho(directive, fg="cyan", nl=False)
            click.secho(f"  {desc}", fg="bright_black")
        click.echo()


@headers.command("list")
def list_cmd():
    """List all security headers checked by this tool."""
    click.echo()
    click.secho(f"  {'Header':<38} {'Type':<6} Description", fg="bright_black")
    click.secho(f"  {'─' * 38} {'─' * 6} {'─' * 50}", fg="bright_black")

    for h in list_headers():
        tag = "core" if h["core"] else "extra"
        tag_color = "green" if h["core"] else "bright_black"
        click.secho(f"  {h['name']:<38}", fg="cyan", nl=False)
        click.secho(f" {tag:<6}", fg=tag_color, nl=False)
        click.echo(f" {h['description']}")
    click.echo()
