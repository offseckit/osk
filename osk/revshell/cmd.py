"""Reverse shell subcommand for osk."""

import click

from .shells import SHELLS, generate, get_listener, list_languages


@click.group(invoke_without_command=True)
@click.option("-i", "--ip", default=None, help="Attacker IP address")
@click.option("-p", "--port", default="4444", help="Attacker port (default: 4444)")
@click.option("-l", "--lang", default="bash", help="Language (bash, python, powershell, php, ...)")
@click.option("-v", "--variant", default=None, help="Specific variant (e.g., bash-i, nc-mkfifo)")
@click.option("-e", "--encoding", default="raw",
              type=click.Choice(["raw", "base64", "url", "double-url"]),
              help="Output encoding")
@click.option("--listener/--no-listener", default=True, help="Show listener command")
@click.option("--all", "show_all", is_flag=True, help="Show all variants for the language")
@click.pass_context
def revshell(ctx, ip, port, lang, variant, encoding, listener, show_all):
    """Generate reverse shell one-liners.

    \b
    Examples:
      osk revshell -i 10.10.10.10 -p 4444
      osk revshell -i 10.10.10.10 -l python
      osk revshell -i 10.10.10.10 -l bash -e base64
      osk revshell -i 10.10.10.10 -l php --all
      osk revshell list
    """
    if ctx.invoked_subcommand is not None:
        return

    if ip is None:
        click.echo(ctx.get_help())
        return

    if show_all:
        _show_all_variants(ip, port, lang, encoding, listener)
    else:
        _show_single(ip, port, lang, variant, encoding, listener)


def _show_single(ip, port, lang, variant, encoding, show_listener):
    try:
        cmd = generate(ip, port, lang, variant, encoding)
    except ValueError as e:
        raise click.ClickException(str(e))

    shell = SHELLS[lang]
    v_id = variant or next(iter(shell["variants"]))
    v_name = shell["variants"][v_id]["name"]

    click.secho(f"# {v_name}", fg="bright_magenta")
    click.echo(cmd)

    if show_listener:
        click.echo()
        click.secho("# Listener", fg="green")
        click.echo(get_listener(lang, port))


def _show_all_variants(ip, port, lang, encoding, show_listener):
    if lang not in SHELLS:
        raise click.ClickException(f"Unknown language: {lang}. Use: {', '.join(SHELLS)}")

    shell = SHELLS[lang]
    click.secho(f"# {shell['name']} — all variants\n", fg="bright_magenta")

    for v_id, v in shell["variants"].items():
        click.secho(f"## {v['name']}", fg="cyan")
        cmd = generate(ip, port, lang, v_id, encoding)
        click.echo(cmd)
        click.echo()

    if show_listener:
        click.secho("# Listener", fg="green")
        click.echo(get_listener(lang, port))


@revshell.command("list")
def list_cmd():
    """List all available languages and variants."""
    languages = list_languages()
    for lang in languages:
        click.secho(f"{lang['id']}", fg="cyan", nl=False)
        click.secho(f"  ({lang['name']})", fg="bright_black")
        for v in lang["variants"]:
            click.echo(f"  {v['id']}")
