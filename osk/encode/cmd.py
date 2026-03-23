"""Encode/decode subcommand for osk."""

import sys

import click

from .encoders import OPERATIONS, detect_encoding, list_operations, run_chain, run_operation


@click.group(invoke_without_command=True)
@click.option("-o", "--op", multiple=True,
              help="Operation(s) to apply, in order (e.g., -o base64-encode -o url-encode)")
@click.option("-i", "--input", "input_text", default=None, help="Input text (reads stdin if omitted)")
@click.option("-s", "--steps", is_flag=True, help="Show intermediate results for chained operations")
@click.argument("text", nargs=-1)
@click.pass_context
def encode(ctx, op, input_text, steps, text):
    """Encode and decode text with 24+ operations. Chain multiple operations together.

    \b
    Examples:
      osk encode -o base64-encode "Hello World"
      osk encode -o base64-decode "SGVsbG8gV29ybGQ="
      osk encode -o url-encode -o base64-encode "test payload"
      echo "data" | osk encode -o base64-decode
      osk encode list
    """
    if ctx.invoked_subcommand is not None:
        return

    if not op:
        click.echo(ctx.get_help())
        return

    if input_text is not None:
        data = input_text
    elif text:
        data = " ".join(text)
    elif not sys.stdin.isatty():
        data = sys.stdin.read().rstrip("\n")
    else:
        raise click.ClickException("No input provided. Pass text as an argument, use -i, or pipe via stdin.")

    ops = list(op)

    try:
        if len(ops) == 1 and not steps:
            result = run_operation(ops[0], data)
            op_name = OPERATIONS[ops[0]]["name"]
            click.secho(f"# {op_name}", fg="bright_magenta")
            click.echo(result)
        else:
            results = run_chain(data, ops)
            if steps:
                for j, r in enumerate(results):
                    click.secho(f"# Step {j + 1}: {r['name']}", fg="cyan")
                    click.echo(r["output"])
                    if j < len(results) - 1:
                        click.echo()
            else:
                final = results[-1]
                chain_desc = " -> ".join(OPERATIONS[o]["name"] for o in ops)
                click.secho(f"# {chain_desc}", fg="bright_magenta")
                click.echo(final["output"])
    except (ValueError, Exception) as e:
        raise click.ClickException(str(e))


@encode.command("list")
@click.option("-c", "--category", default=None,
              type=click.Choice(["encode", "decode"]),
              help="Filter by category")
def list_cmd(category):
    """List all available encoding/decoding operations."""
    operations = list_operations()
    if category:
        operations = [op for op in operations if op["category"] == category]

    current_cat = None
    for op in operations:
        cat = op["category"]
        if cat != current_cat:
            if current_cat is not None:
                click.echo()
            click.secho(f"[{cat}]", fg="bright_black")
            current_cat = cat
        click.secho(f"  {op['id']}", fg="cyan", nl=False)
        click.secho(f"  {op['name']}", fg="bright_black")


@encode.command("detect")
@click.option("-i", "--input", "input_text", default=None, help="Input text (reads stdin if omitted)")
@click.argument("text", nargs=-1)
def detect_cmd(input_text, text):
    """Analyze input and suggest what encoding it might be.

    \b
    Examples:
      osk encode detect "SGVsbG8gV29ybGQ="
      osk encode detect "%48%65%6C%6C%6F"
      echo "01001000 01101001" | osk encode detect
      osk encode detect "xn--n3h.com"
    """
    if input_text is not None:
        data = input_text
    elif text:
        data = " ".join(text)
    elif not sys.stdin.isatty():
        data = sys.stdin.read().rstrip("\n")
    else:
        raise click.ClickException("No input provided. Pass text as an argument, use -i, or pipe via stdin.")

    results = detect_encoding(data)

    if not results:
        click.secho("No encoding patterns detected.", fg="bright_black")
        return

    click.secho("# Detected Encodings", fg="bright_magenta")
    click.echo()

    confidence_colors = {"high": "green", "medium": "yellow", "low": "bright_black"}

    for r in results:
        color = confidence_colors.get(r["confidence"], "white")
        click.secho(f"  [{r['confidence']}]", fg=color, nl=False)
        click.secho(f"  {r['id']}", fg="cyan", nl=False)
        click.secho(f"  {r['name']}", fg="bright_black")

    click.echo()
    click.secho("Tip: ", fg="bright_black", nl=False)
    click.secho(f"osk encode -o {results[0]['id']} \"your input\"", fg="cyan")
