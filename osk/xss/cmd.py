"""XSS subcommand for osk."""

import click

from .payloads import (
    CONTEXTS,
    ACTIONS,
    ENCODINGS,
    WAF_PROFILES,
    generate,
    get_polyglots,
)


@click.group(invoke_without_command=True)
@click.pass_context
def xss(ctx):
    """Generate context-aware XSS payloads with WAF bypass variants.

    \b
    Examples:
      osk xss gen
      osk xss gen -c attr-double -a cookie
      osk xss gen -c html --waf cloudflare
      osk xss gen -c js-single -e url
      osk xss gen -c html --blocked "<>"
      osk xss polyglots
      osk xss contexts
      osk xss encodings
    """
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


@xss.command("gen")
@click.option("-c", "--context", "context", default="html",
              type=click.Choice(list(CONTEXTS.keys())),
              help="Injection context")
@click.option("-a", "--action", default="alert",
              type=click.Choice(list(ACTIONS.keys())),
              help="Payload action (what the JS does)")
@click.option("--custom-js", default=None,
              help="Custom JavaScript to execute (overrides --action)")
@click.option("-e", "--encoding", default="none",
              type=click.Choice(list(ENCODINGS.keys())),
              help="Encoding to apply")
@click.option("--waf", default=None,
              type=click.Choice(list(WAF_PROFILES.keys())),
              help="WAF bypass profile")
@click.option("--blocked", default=None,
              help="Blocked characters to filter out (e.g. '<>\"')")
def gen(context, action, custom_js, encoding, waf, blocked):
    """Generate XSS payloads for a specific injection context."""
    ctx_info = CONTEXTS[context]
    results = generate(
        context=context,
        action=action,
        custom_js=custom_js,
        encoding=encoding,
        waf=waf,
        blocked=blocked,
    )

    click.echo()
    click.secho(f"  # XSS Payloads — {ctx_info['name']}", fg="green")
    click.secho(f"  # {ctx_info['desc']}", fg="bright_black")

    if encoding != "none":
        click.secho(f"  # Encoding: {encoding}", fg="bright_black")
    if waf:
        click.secho(f"  # WAF: {WAF_PROFILES[waf]}", fg="bright_black")
    if blocked:
        click.secho(f"  # Blocked: {blocked}", fg="bright_black")

    click.echo()

    if not results:
        click.secho("  No payloads match the current filters.", fg="yellow")
        click.echo()
        return

    for name, payload in results:
        click.secho(f"  {name}", fg="cyan")
        click.secho(f"    {payload}", fg="green")
        click.echo()


@xss.command("polyglots")
@click.option("-a", "--action", default="alert",
              type=click.Choice(list(ACTIONS.keys())),
              help="Payload action")
@click.option("--custom-js", default=None,
              help="Custom JavaScript")
def polyglots(action, custom_js):
    """Show polyglot XSS payloads that work across multiple contexts."""
    js = custom_js if custom_js else ACTIONS.get(action, "alert(1)")
    results = get_polyglots(js)

    click.echo()
    click.secho("  # Polyglot XSS Payloads", fg="green")
    click.secho("  # Work across multiple injection contexts", fg="bright_black")
    click.echo()

    for name, payload in results:
        click.secho(f"  {name}", fg="cyan")
        click.secho(f"    {payload}", fg="green")
        click.echo()


@xss.command("contexts")
def contexts_cmd():
    """List all supported injection contexts."""
    click.echo()
    click.secho(f"  {'Context':<16} Description", fg="bright_black")
    click.secho(f"  {'─' * 16} {'─' * 50}", fg="bright_black")

    for key, info in CONTEXTS.items():
        click.secho(f"  {key:<16}", fg="cyan", nl=False)
        click.echo(f" {info['desc']}")
    click.echo()


@xss.command("encodings")
def encodings_cmd():
    """List available encoding methods."""
    click.echo()
    names = {
        "none": "No encoding",
        "url": "URL percent-encoding",
        "double-url": "Double URL encoding",
        "html-entities": "HTML character references",
        "hex": "JavaScript hex escapes (\\x)",
        "unicode": "JavaScript unicode escapes (\\u)",
        "fromcharcode": "String.fromCharCode()",
        "base64": "Base64 with atob() wrapper",
    }
    click.secho(f"  {'Encoding':<16} Description", fg="bright_black")
    click.secho(f"  {'─' * 16} {'─' * 40}", fg="bright_black")

    for key in ENCODINGS:
        desc = names.get(key, key)
        click.secho(f"  {key:<16}", fg="cyan", nl=False)
        click.echo(f" {desc}")
    click.echo()


@xss.command("wafs")
def wafs_cmd():
    """List available WAF bypass profiles."""
    click.echo()
    click.secho(f"  {'Profile':<16} WAF Name", fg="bright_black")
    click.secho(f"  {'─' * 16} {'─' * 30}", fg="bright_black")

    for key, name in WAF_PROFILES.items():
        click.secho(f"  {key:<16}", fg="cyan", nl=False)
        click.echo(f" {name}")
    click.echo()
