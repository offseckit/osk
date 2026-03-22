"""Nmap subcommand for osk."""

import click

from .builder import (
    SCAN_TYPES,
    TIMING_TEMPLATES,
    NSE_CATEGORIES,
    PRESETS,
    build_command,
)


@click.group(invoke_without_command=True)
@click.pass_context
def nmap(ctx):
    """Build nmap commands visually from the terminal.

    \b
    Examples:
      osk nmap build -t 10.10.10.10
      osk nmap build -t 10.10.10.10 -s syn -p 22,80,443 -sV
      osk nmap build -t 192.168.1.0/24 --preset quick
      osk nmap preset vuln -t 10.10.10.10
      osk nmap scans
      osk nmap scripts
    """
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


@nmap.command("build")
@click.option("-t", "--target", required=True, help="Target IP, hostname, or CIDR range")
@click.option("-s", "--scan-type", "scan_type", default="syn",
              type=click.Choice(list(SCAN_TYPES.keys())), help="Scan type")
@click.option("-p", "--ports", default=None, help="Port specification (e.g., 22,80,443 or 1-1000)")
@click.option("--top-ports", default=None, type=int, help="Scan top N most common ports")
@click.option("--all-ports", is_flag=True, help="Scan all 65535 ports (-p-)")
@click.option("-F", "--fast", is_flag=True, help="Fast mode — top 100 ports")
@click.option("-sV", "--service-version", "service_version", is_flag=True, help="Detect service versions")
@click.option("-O", "--os-detect", "os_detection", is_flag=True, help="OS detection")
@click.option("-sC", "--default-scripts", "default_scripts", is_flag=True, help="Run default NSE scripts")
@click.option("-A", "--aggressive", is_flag=True, help="Aggressive mode (-A)")
@click.option("-T", "--timing", default=None, type=click.IntRange(0, 5), help="Timing template (0-5)")
@click.option("--script", multiple=True, help="NSE script(s) to run")
@click.option("--script-cat", "script_categories", multiple=True, help="NSE script category(ies)")
@click.option("-Pn", "--no-ping", "no_ping", is_flag=True, help="Skip host discovery")
@click.option("--open", "open_only", is_flag=True, help="Show only open ports")
@click.option("-v", "--verbose", is_flag=True, help="Verbose output")
@click.option("-f", "--fragment", is_flag=True, help="Fragment packets for evasion")
@click.option("-D", "--decoys", default=None, help="Decoy addresses (e.g., RND:5)")
@click.option("--source-port", default=None, help="Spoof source port")
@click.option("-6", "--ipv6", is_flag=True, help="IPv6 scanning")
@click.option("--reason", is_flag=True, help="Show port state reason")
@click.option("--traceroute", is_flag=True, help="Trace hop path to each host")
@click.option("-oN", "--output-normal", "output_normal", default=None, help="Normal output file")
@click.option("-oX", "--output-xml", "output_xml", default=None, help="XML output file")
@click.option("-oG", "--output-grep", "output_grep", default=None, help="Grepable output file")
@click.option("-oA", "--output-all", "output_all", default=None, help="All output formats (base name)")
def build(target, scan_type, ports, top_ports, all_ports, fast,
          service_version, os_detection, default_scripts, aggressive,
          timing, script, script_categories, no_ping, open_only, verbose,
          fragment, decoys, source_port, ipv6, reason, traceroute,
          output_normal, output_xml, output_grep, output_all):
    """Build an nmap command from options."""
    # Determine output format
    output_format = None
    output_file = None
    if output_all:
        output_format, output_file = "all", output_all
    elif output_normal:
        output_format, output_file = "normal", output_normal
    elif output_xml:
        output_format, output_file = "xml", output_xml
    elif output_grep:
        output_format, output_file = "grepable", output_grep

    cmd = build_command(
        target=target,
        scan_type=scan_type,
        ports=ports,
        top_ports=top_ports,
        all_ports=all_ports,
        fast=fast,
        service_version=service_version,
        os_detection=os_detection,
        default_scripts=default_scripts,
        aggressive=aggressive,
        timing=timing,
        scripts=list(script) if script else None,
        script_categories=list(script_categories) if script_categories else None,
        no_ping=no_ping,
        open_only=open_only,
        verbose=verbose,
        output_format=output_format,
        output_file=output_file,
        fragment=fragment,
        decoys=decoys,
        source_port=source_port,
        ipv6=ipv6,
        reason=reason,
        traceroute=traceroute,
    )

    click.echo()
    click.secho("  # Generated Command", fg="green")
    click.secho(f"  {cmd}", fg="cyan")

    # Show notes
    st = SCAN_TYPES.get(scan_type, SCAN_TYPES["syn"])
    if st["root"] and not aggressive:
        click.secho("  Requires root/sudo", fg="yellow")
    click.echo()


@nmap.command("preset")
@click.argument("preset_name", type=click.Choice(list(PRESETS.keys())))
@click.option("-t", "--target", required=True, help="Target IP, hostname, or CIDR range")
def preset(preset_name, target):
    """Generate a command from a preset profile."""
    p = PRESETS[preset_name]
    args = " ".join(p["args"])
    cmd = f"nmap {args} {target}"

    click.echo()
    click.secho(f"  # {p['name']}", fg="green")
    click.secho(f"  # {p['desc']}", fg="bright_black")
    click.secho(f"  {cmd}", fg="cyan")
    click.echo()


@nmap.command("presets")
def presets_cmd():
    """List all available scan presets."""
    click.echo()
    for key, p in PRESETS.items():
        click.secho(f"  {key:<12}", fg="cyan", nl=False)
        click.secho(f" {p['name']}", fg="green")
        click.secho(f"  {'':12} {p['desc']}", fg="bright_black")
        args = " ".join(p["args"])
        click.secho(f"  {'':12} nmap {args} <target>", fg="bright_black")
        click.echo()


@nmap.command("scans")
def scans_cmd():
    """List all supported scan types."""
    click.echo()
    click.secho(f"  {'Type':<10} {'Flag':<6} {'Root':<6} Description", fg="bright_black")
    click.secho(f"  {'─' * 10} {'─' * 6} {'─' * 6} {'─' * 40}", fg="bright_black")

    for key, st in SCAN_TYPES.items():
        root_label = "yes" if st["root"] else "no"
        root_color = "yellow" if st["root"] else "green"
        click.secho(f"  {key:<10}", fg="cyan", nl=False)
        click.secho(f" {st['flag']:<6}", fg="bright_magenta", nl=False)
        click.secho(f" {root_label:<6}", fg=root_color, nl=False)
        click.echo(f" {st['desc']}")
    click.echo()


@nmap.command("scripts")
def scripts_cmd():
    """List NSE script categories."""
    click.echo()
    click.secho("  NSE Script Categories", fg="green")
    click.secho("  Use with: --script <category> or --script-cat <category>", fg="bright_black")
    click.echo()

    for cat in NSE_CATEGORIES:
        click.secho(f"  {cat}", fg="cyan")
    click.echo()


@nmap.command("timing")
def timing_cmd():
    """List timing templates (T0-T5)."""
    click.echo()
    click.secho(f"  {'Template':<10} {'Name':<12} Description", fg="bright_black")
    click.secho(f"  {'─' * 10} {'─' * 12} {'─' * 40}", fg="bright_black")

    for t, info in TIMING_TEMPLATES.items():
        click.secho(f"  T{t:<9}", fg="cyan", nl=False)
        click.secho(f" {info['name']:<12}", fg="green", nl=False)
        click.echo(f" {info['desc']}")
    click.echo()
