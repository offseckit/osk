"""Subnet subcommand for osk."""

import json as json_mod

import click

from .calculator import calculate, split_network, contains, list_hosts


@click.group(invoke_without_command=True)
@click.pass_context
def subnet(ctx):
    """Calculate subnet details from CIDR notation.

    \b
    Compute network addresses, broadcast addresses, host ranges,
    split subnets, check containment, and list hosts.

    \b
    Examples:
      osk subnet calc 192.168.1.0/24
      osk subnet calc 10.0.0.0/8 --json
      osk subnet split 10.0.0.0/16 --into 4
      osk subnet contains 192.168.1.0/24 192.168.1.100
      osk subnet list 192.168.1.0/28
    """
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


@subnet.command("calc")
@click.argument("cidr")
@click.option("--json", "json_output", is_flag=True, default=False,
              help="Output results as JSON")
def calc_cmd(cidr, json_output):
    """Calculate subnet details for a CIDR range.

    \b
    Displays network address, broadcast, mask, wildcard, host range,
    total addresses, usable hosts, IP class, and private/public status.

    \b
    Examples:
      osk subnet calc 192.168.1.0/24
      osk subnet calc 10.10.10.0/26
      osk subnet calc 172.16.0.0/12 --json
    """
    result = calculate(cidr)
    if result is None:
        raise click.ClickException(
            f"Invalid CIDR: {cidr}\n"
            "  Use format: 192.168.1.0/24"
        )

    if json_output:
        click.echo(json_mod.dumps(result, indent=2))
        return

    _print_result(result)


@subnet.command("split")
@click.argument("cidr")
@click.option("--into", "count", type=int, default=4,
              help="Number of subnets (must be power of 2)")
@click.option("--json", "json_output", is_flag=True, default=False,
              help="Output results as JSON")
def split_cmd(cidr, count, json_output):
    """Split a network into equal subnets.

    \b
    The count must be a power of 2 (2, 4, 8, 16, ...).

    \b
    Examples:
      osk subnet split 10.0.0.0/24 --into 4
      osk subnet split 192.168.0.0/16 --into 256
      osk subnet split 10.0.0.0/24 --into 8 --json
    """
    subnets = split_network(cidr, count)
    if subnets is None:
        raise click.ClickException(
            f"Cannot split {cidr} into {count} subnets.\n"
            "  Count must be a power of 2 and resulting prefix must be <= /32."
        )

    if json_output:
        click.echo(json_mod.dumps(subnets, indent=2))
        return

    click.echo()
    click.secho(f"  {cidr} split into {count} subnets", bold=True)
    click.echo()

    for i, s in enumerate(subnets):
        click.secho(f"  {i + 1:>3}. ", fg="bright_black", nl=False)
        click.secho(f"{s['cidr']:<20}", fg="cyan", nl=False)
        click.secho(f"{s['first_host']} - {s['last_host']}", fg="white", nl=False)
        click.secho(f"  ({s['usable']} hosts)", fg="green")

    click.echo()


@subnet.command("contains")
@click.argument("cidr")
@click.argument("ip")
def contains_cmd(cidr, ip):
    """Check if an IP address is within a CIDR range.

    \b
    Examples:
      osk subnet contains 192.168.1.0/24 192.168.1.100
      osk subnet contains 10.0.0.0/8 10.10.10.10
      osk subnet contains 192.168.1.0/24 10.0.0.1
    """
    result = contains(cidr, ip)
    if result is None:
        raise click.ClickException(
            f"Invalid input.\n"
            f"  CIDR: {cidr}\n"
            f"  IP: {ip}\n"
            "  Use format: osk subnet contains 192.168.1.0/24 192.168.1.100"
        )

    click.echo()
    if result:
        click.secho(f"  {ip} ", fg="green", bold=True, nl=False)
        click.secho("is within ", nl=False)
        click.secho(cidr, fg="cyan")
    else:
        click.secho(f"  {ip} ", fg="red", bold=True, nl=False)
        click.secho("is NOT within ", nl=False)
        click.secho(cidr, fg="cyan")
    click.echo()


@subnet.command("list")
@click.argument("cidr")
@click.option("--limit", "limit", type=int, default=256,
              help="Maximum number of IPs to display (default: 256)")
@click.option("--json", "json_output", is_flag=True, default=False,
              help="Output results as JSON")
def list_cmd(cidr, limit, json_output):
    """List all usable host IPs in a CIDR range.

    \b
    Examples:
      osk subnet list 192.168.1.0/28
      osk subnet list 10.0.0.0/24 --limit 10
      osk subnet list 192.168.1.0/28 --json
    """
    hosts, total, truncated = list_hosts(cidr, limit)
    if hosts is None:
        raise click.ClickException(
            f"Invalid CIDR: {cidr}\n"
            "  Use format: 192.168.1.0/24"
        )

    if json_output:
        click.echo(json_mod.dumps({
            "cidr": cidr,
            "hosts": hosts,
            "total": total,
            "truncated": truncated,
        }, indent=2))
        return

    click.echo()
    click.secho(f"  Hosts in {cidr} ({total} total)", bold=True)
    click.echo()

    for ip in hosts:
        click.secho(f"  {ip}", fg="cyan")

    if truncated:
        click.echo()
        click.secho(
            f"  ... truncated at {limit} (showing {limit} of {total})",
            fg="bright_black",
        )

    click.echo()


# ── Helpers ────────────────────────────────────────────────────────

def _print_result(result):
    """Pretty-print subnet calculation results."""
    click.echo()
    click.secho(f"  {result['cidr']}", fg="cyan", bold=True)
    click.echo()

    rows = [
        ("Network Address", result["network"]),
        ("Broadcast Address", result["broadcast"]),
        ("Subnet Mask", result["mask"]),
        ("Wildcard Mask", result["wildcard"]),
        ("First Usable Host", result["first_host"]),
        ("Last Usable Host", result["last_host"]),
        ("Total Addresses", f"{result['total']:,}"),
        ("Usable Hosts", f"{result['usable']:,}"),
        ("Prefix Length", f"/{result['prefix']}"),
        ("IP Class", result["ip_class"]),
        ("Private Address", "Yes (RFC 1918)" if result["private"] else "No (Public)"),
    ]

    for label, value in rows:
        click.secho(f"  {label:<20} ", fg="bright_black", nl=False)
        click.secho(value, fg="white")

    click.echo()
