"""Reverse shell subcommand for osk."""

import click

from .shells import (
    SHELLS, BIND_SHELLS, TARGET_SHELLS, DEFAULT_SHELL,
    generate, get_listener, list_languages,
)


@click.group(invoke_without_command=True)
@click.option("-i", "--ip", default=None, help="Attacker IP (reverse) or target IP (bind)")
@click.option("-p", "--port", default="4444", help="Port (default: 4444)")
@click.option("-l", "--lang", default="bash", help="Language (bash, python, powershell, php, ...)")
@click.option("-v", "--variant", default=None, help="Specific variant (e.g., bash-i, nc-mkfifo)")
@click.option("-e", "--encoding", default="raw",
              type=click.Choice(["raw", "base64", "url", "double-url"]),
              help="Output encoding")
@click.option("-s", "--shell", "target_shell", default=DEFAULT_SHELL,
              type=click.Choice(TARGET_SHELLS),
              help=f"Target shell binary (default: {DEFAULT_SHELL})")
@click.option("--bind", "bind_mode", is_flag=True, help="Generate bind shell instead of reverse shell")
@click.option("--listener/--no-listener", default=True, help="Show listener command")
@click.option("--all", "show_all", is_flag=True, help="Show all variants for the language")
@click.pass_context
def revshell(ctx, ip, port, lang, variant, encoding, target_shell, bind_mode,
             listener, show_all):
    """Generate reverse shell one-liners.

    \b
    Examples:
      osk revshell -i 10.10.10.10 -p 4444
      osk revshell -i 10.10.10.10 -l python
      osk revshell -i 10.10.10.10 -l bash -s /bin/sh
      osk revshell -i 10.10.10.10 -l bash -e base64
      osk revshell -i 10.10.10.10 -l php --all
      osk revshell -i 10.10.10.10 --bind -l bind-netcat
      osk revshell list
      osk revshell list --bind
    """
    if ctx.invoked_subcommand is not None:
        return

    if ip is None:
        click.echo(ctx.get_help())
        return

    if show_all:
        _show_all_variants(ip, port, lang, encoding, target_shell, bind_mode, listener)
    else:
        _show_single(ip, port, lang, variant, encoding, target_shell, bind_mode, listener)


def _show_single(ip, port, lang, variant, encoding, target_shell, bind_mode,
                 show_listener):
    try:
        cmd = generate(ip, port, lang, variant, encoding, shell=target_shell,
                       bind=bind_mode)
    except ValueError as e:
        raise click.ClickException(str(e))

    source = BIND_SHELLS if bind_mode else SHELLS
    shell = source[lang]
    v_id = variant or next(iter(shell["variants"]))
    v_name = shell["variants"][v_id]["name"]

    mode_label = "Bind" if bind_mode else "Reverse"
    click.secho(f"# {v_name} ({mode_label})", fg="bright_magenta")
    click.echo(cmd)

    if show_listener:
        click.echo()
        label = "Connect" if bind_mode else "Listener"
        click.secho(f"# {label}", fg="green")
        click.echo(get_listener(lang, port, ip=ip, bind=bind_mode))


def _show_all_variants(ip, port, lang, encoding, target_shell, bind_mode,
                       show_listener):
    source = BIND_SHELLS if bind_mode else SHELLS
    if lang not in source:
        raise click.ClickException(
            f"Unknown language: {lang}. Use: {', '.join(source)}")

    shell = source[lang]
    mode_label = "Bind" if bind_mode else "Reverse"
    click.secho(f"# {shell['name']} -- all {mode_label.lower()} variants\n",
                fg="bright_magenta")

    for v_id in shell["variants"]:
        v = shell["variants"][v_id]
        click.secho(f"## {v['name']}", fg="cyan")
        cmd = generate(ip, port, lang, v_id, encoding, shell=target_shell,
                       bind=bind_mode)
        click.echo(cmd)
        click.echo()

    if show_listener:
        label = "Connect" if bind_mode else "Listener"
        click.secho(f"# {label}", fg="green")
        click.echo(get_listener(lang, port, ip=ip, bind=bind_mode))


@revshell.command("list")
@click.option("--bind", "bind_mode", is_flag=True,
              help="List bind shell languages instead of reverse shells")
def list_cmd(bind_mode):
    """List all available languages and variants."""
    languages = list_languages(bind=bind_mode)
    label = "Bind shells" if bind_mode else "Reverse shells"
    click.secho(f"# {label}\n", fg="bright_magenta")
    for lang in languages:
        click.secho(f"{lang['id']}", fg="cyan", nl=False)
        click.secho(f"  ({lang['name']}) [{lang['os']}]", fg="bright_black")
        for v in lang["variants"]:
            click.echo(f"  {v['id']}")
