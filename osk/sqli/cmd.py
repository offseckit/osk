"""SQLi subcommand for osk."""

import click

from .payloads import (
    DB_TYPES,
    CONTEXTS,
    COMMENTS,
    WAF_METHODS,
    generate,
    get_auth_bypass,
)


INJECTION_TYPES = {
    "union": "UNION-based injection",
    "boolean-blind": "Boolean blind injection",
    "time-blind": "Time-based blind injection",
    "error-based": "Error-based injection",
    "stacked": "Stacked queries",
}


@click.group(invoke_without_command=True)
@click.pass_context
def sqli(ctx):
    """Generate context-aware SQL injection payloads.

    \b
    Examples:
      osk sqli gen
      osk sqli gen -d mssql -t error-based
      osk sqli gen -d mysql -t union -c 5
      osk sqli gen -d postgresql --waf case-swap
      osk sqli gen --context string-single --table users --column password
      osk sqli auth
      osk sqli dbs
      osk sqli types
    """
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


@sqli.command("gen")
@click.option("-d", "--db", default="mysql",
              type=click.Choice(list(DB_TYPES.keys())),
              help="Database type")
@click.option("-t", "--type", "injection_type", default="union",
              type=click.Choice(list(INJECTION_TYPES.keys())),
              help="Injection type")
@click.option("--context", default="string-single",
              type=click.Choice(list(CONTEXTS.keys())),
              help="Injection context")
@click.option("--comment", default="--",
              type=click.Choice(list(COMMENTS.keys())),
              help="Comment style")
@click.option("-c", "--columns", default=3, type=int,
              help="Number of columns (for UNION)")
@click.option("--table", default="users",
              help="Target table name")
@click.option("--column", default="password",
              help="Target column name")
@click.option("--waf", default=None,
              type=click.Choice(list(WAF_METHODS.keys())),
              help="WAF bypass method")
def gen(db, injection_type, context, comment, columns, table, column, waf):
    """Generate SQL injection payloads for a specific configuration."""
    results = generate(
        db=db,
        context=context,
        injection_type=injection_type,
        comment=comment,
        columns=columns,
        table=table,
        column=column,
        waf=waf,
    )

    db_name = DB_TYPES[db]
    type_name = INJECTION_TYPES[injection_type]

    click.echo()
    click.secho(f"  # SQLi Payloads — {db_name}", fg="green")
    click.secho(f"  # {type_name}", fg="bright_black")
    click.secho(f"  # Context: {CONTEXTS[context]['name']}", fg="bright_black")

    if waf:
        click.secho(f"  # WAF bypass: {WAF_METHODS[waf]}", fg="bright_black")

    click.echo()

    if not results:
        click.secho("  No payloads for this configuration.", fg="yellow")
        click.echo()
        return

    for name, payload in results:
        click.secho(f"  {name}", fg="cyan")
        click.secho(f"    {payload}", fg="green")
        click.echo()


@sqli.command("auth")
def auth_cmd():
    """Show authentication bypass payloads."""
    results = get_auth_bypass()

    click.echo()
    click.secho("  # SQL Injection Authentication Bypass Payloads", fg="green")
    click.secho("  # Common login form bypass techniques", fg="bright_black")
    click.echo()

    for name, payload in results:
        click.secho(f"  {name}", fg="cyan")
        click.secho(f"    {payload}", fg="green")
        click.echo()


@sqli.command("dbs")
def dbs_cmd():
    """List supported database types."""
    click.echo()
    click.secho(f"  {'DB Type':<16} Description", fg="bright_black")
    click.secho(f"  {'─' * 16} {'─' * 30}", fg="bright_black")

    for key, desc in DB_TYPES.items():
        click.secho(f"  {key:<16}", fg="cyan", nl=False)
        click.echo(f" {desc}")
    click.echo()


@sqli.command("types")
def types_cmd():
    """List supported injection types."""
    click.echo()
    click.secho(f"  {'Type':<20} Description", fg="bright_black")
    click.secho(f"  {'─' * 20} {'─' * 35}", fg="bright_black")

    for key, desc in INJECTION_TYPES.items():
        click.secho(f"  {key:<20}", fg="cyan", nl=False)
        click.echo(f" {desc}")
    click.echo()


@sqli.command("comments")
def comments_cmd():
    """List comment styles by database."""
    click.echo()
    click.secho(f"  {'Style':<10} Description", fg="bright_black")
    click.secho(f"  {'─' * 10} {'─' * 30}", fg="bright_black")

    for key, desc in COMMENTS.items():
        click.secho(f"  {key:<10}", fg="cyan", nl=False)
        click.echo(f" {desc}")
    click.echo()


@sqli.command("wafs")
def wafs_cmd():
    """List available WAF bypass methods."""
    click.echo()
    click.secho(f"  {'Method':<18} Description", fg="bright_black")
    click.secho(f"  {'─' * 18} {'─' * 40}", fg="bright_black")

    for key, desc in WAF_METHODS.items():
        click.secho(f"  {key:<18}", fg="cyan", nl=False)
        click.echo(f" {desc}")
    click.echo()
