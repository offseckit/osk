"""Chmod / Linux permissions calculator subcommand for osk."""

from __future__ import annotations

import json as json_mod

import click

from .calculator import (
    PRESETS,
    apply_symbolic,
    describe_mode,
    explain_octal_digits,
    get_bit_breakdown,
    get_warnings,
    is_risky,
    parse_any,
    parse_octal,
    to_octal,
    to_rwx_string,
    to_symbolic_delta,
    to_symbolic_equals,
)


class _ChmodGroup(click.Group):
    """Group that falls through to `calc` when the first arg is not a subcommand.

    Lets `osk chmod 755` work as shorthand for `osk chmod calc 755`.
    """

    def resolve_command(self, ctx, args):
        try:
            return super().resolve_command(ctx, args)
        except click.UsageError:
            # Not a known subcommand. Re-dispatch through `calc`.
            if args and not args[0].startswith("-"):
                cmd = self.get_command(ctx, "calc")
                if cmd is not None:
                    return "calc", cmd, args
            raise


@click.group(cls=_ChmodGroup, invoke_without_command=True)
@click.pass_context
def chmod(ctx):
    """Convert and explain Linux file permissions.

    \b
    Subcommands:
      osk chmod calc <mode>      Show octal/symbolic + warnings
      osk chmod presets          List common permission presets
      osk chmod hunt             Pentest privesc-hunting find recipes

    \b
    For convenience the bare form
      osk chmod 755
    is shorthand for
      osk chmod calc 755

    \b
    MODE values for `calc` can be:
      - octal:       755 or 4755
      - ls -l style: rwxr-xr-x or -rwxr-xr-x
      - POSIX:       u=rwx,go=rx (applied against mode 0)

    \b
    Examples:
      osk chmod 755
      osk chmod rwxr-xr-x
      osk chmod calc 4755 --explain
      osk chmod calc 644 --apply u+x
      osk chmod calc 777 --warnings
      osk chmod calc 755 --json
      osk chmod presets
      osk chmod hunt
    """
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


@chmod.command("calc")
@click.argument("mode_input")
@click.option(
    "--json", "json_output", is_flag=True, default=False,
    help="Output results as JSON",
)
@click.option(
    "--explain", is_flag=True, default=False,
    help="Print the long-form bit-by-bit breakdown",
)
@click.option(
    "--apply", "apply_notation", default=None, metavar="NOTATION",
    help="Apply POSIX symbolic notation (e.g. 'u+x,go-w') to MODE_INPUT",
)
@click.option(
    "--warnings", "warnings_only", is_flag=True, default=False,
    help="Only print risky-permission warnings",
)
def calc_cmd(mode_input, json_output, explain, apply_notation, warnings_only):
    """Calculate, convert, and explain a permission mode.

    \b
    Examples:
      osk chmod calc 755
      osk chmod calc rwxr-xr-x
      osk chmod calc 4755 --explain
      osk chmod calc 644 --apply u+x
      osk chmod calc 777 --warnings
      osk chmod calc 755 --json
    """
    mode = parse_any(mode_input)
    if mode is None:
        raise click.ClickException(
            f"Could not parse mode: {mode_input!r}\n"
            "  Try octal (e.g. 755 or 4755), ls -l (rwxr-xr-x), or POSIX (u=rwx,go=rx)"
        )

    if apply_notation:
        try:
            mode = apply_symbolic(mode, apply_notation)
        except ValueError as e:
            raise click.ClickException(str(e))

    if json_output:
        click.echo(json_mod.dumps(describe_mode(mode), indent=2))
        return

    if warnings_only:
        _print_warnings(mode)
        return

    _print_summary(mode)
    if explain:
        click.echo()
        _print_digits(mode)
        click.echo()
        _print_bits(mode)
    _print_warnings(mode, only_if_any=True)


@chmod.command("presets")
@click.option(
    "--json", "json_output", is_flag=True, default=False,
    help="Output presets as JSON",
)
def presets_cmd(json_output):
    """List common chmod presets with use cases.

    \b
    Examples:
      osk chmod presets
      osk chmod presets --json
    """
    if json_output:
        click.echo(
            json_mod.dumps(
                [
                    {
                        "octal": p.octal,
                        "rwx": to_rwx_string(p.mode),
                        "label": p.label,
                        "detail": p.detail,
                    }
                    for p in PRESETS
                ],
                indent=2,
            )
        )
        return

    click.echo()
    click.secho("  Common Linux permission presets", bold=True)
    click.echo()
    for p in PRESETS:
        click.secho(f"  {p.octal:<6}", fg="green", bold=True, nl=False)
        click.secho(f"{to_rwx_string(p.mode):<11}", fg="cyan", nl=False)
        click.secho(p.label, fg="white")
        click.secho(f"          {p.detail}", fg="bright_black")
    click.echo()


@chmod.command("hunt")
def hunt_cmd():
    """Print pentest privilege-escalation hunting commands.

    Lists the common find(1) recipes for setuid/setgid binaries,
    world-writable files, and other risky permission patterns.
    """
    click.echo()
    click.secho("  Privilege-escalation hunting commands", bold=True)
    click.echo()
    rows = [
        ("Setuid binaries",
         "find / -perm -4000 -type f 2>/dev/null"),
        ("Setgid binaries",
         "find / -perm -2000 -type f 2>/dev/null"),
        ("World-writable dirs without sticky",
         "find / -perm -2 -type d -not -perm -1000 2>/dev/null"),
        ("World-writable files",
         "find / -perm -2 -type f -not -path '/proc/*' 2>/dev/null"),
        ("Files writable by current user",
         "find / -writable -not -path '/proc/*' 2>/dev/null"),
    ]
    for label, cmd in rows:
        click.secho(f"  {label}", fg="white")
        click.secho(f"    {cmd}", fg="cyan")
        click.echo()


# ── Pretty-printers ──────────────────────────────────────────────


def _print_summary(mode):
    click.echo()
    click.secho(f"  octal     ", fg="bright_black", nl=False)
    click.secho(to_octal(mode), fg="green", bold=True)
    click.secho(f"  symbolic  ", fg="bright_black", nl=False)
    click.secho(to_rwx_string(mode), fg="cyan", bold=True)
    click.secho(f"  equals    ", fg="bright_black", nl=False)
    click.secho(to_symbolic_equals(mode), fg="white")
    click.secho(f"  delta     ", fg="bright_black", nl=False)
    click.secho(to_symbolic_delta(mode), fg="white")
    click.echo()
    click.secho(f"  $ chmod {to_octal(mode)} <file>", fg="yellow")
    click.secho(f"  $ chmod {to_symbolic_equals(mode)} <file>", fg="yellow")
    click.echo()


def _print_digits(mode):
    click.secho("  Octal digit breakdown", bold=True)
    click.echo()
    click.secho(f"  {'pos':<8} {'digit':<6} {'components':<28} rwx", fg="bright_black")
    for row in explain_octal_digits(mode):
        components = " + ".join(row["components"]) if row["components"] else "-"
        click.secho(f"  {row['label']:<8} ", nl=False)
        click.secho(f"{row['digit']:<6}", fg="green", nl=False)
        click.secho(f"{components:<28} ", fg="bright_black", nl=False)
        click.secho(row["rwx"], fg="cyan")


def _print_bits(mode):
    click.secho("  Bit reference (set bits highlighted)", bold=True)
    click.echo()
    for row in get_bit_breakdown(mode):
        marker = click.style("[x]", fg="green") if row.set else click.style("[ ]", fg="bright_black")
        weight = f"{row.weight:o}"
        label_color = "white" if row.set else "bright_black"
        click.secho(f"  {marker} ", nl=False)
        click.secho(f"{weight:<5}", fg="green" if row.set else "bright_black", nl=False)
        click.secho(f"{row.label:<16}", fg=label_color, nl=False)
        click.secho(row.meaning, fg="bright_black")


def _print_warnings(mode, only_if_any=False):
    warnings = get_warnings(mode)
    if not warnings:
        if not only_if_any:
            click.secho("  No risky-permission warnings.", fg="green")
            click.echo()
        return
    click.echo()
    click.secho("  Warnings", bold=True)
    click.echo()
    for w in warnings:
        color = (
            "red" if w.level == "danger"
            else "yellow" if w.level == "warn"
            else "cyan"
        )
        click.secho(f"  [{w.level.upper()}] {w.title}", fg=color, bold=True)
        click.secho(f"    {w.detail}", fg="bright_black")
        click.echo()


# Suppress unused warning for parse_octal which is re-exported for tests
_ = parse_octal
_ = is_risky
