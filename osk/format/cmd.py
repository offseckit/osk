"""Format subcommand for osk."""

import json as json_mod

import click

from .formatter import read_input, format_output, strip_ansi, get_stats


@click.group(invoke_without_command=True)
@click.pass_context
def format(ctx):
    """Format and beautify CLI/terminal output.

    \b
    Pipe terminal output through the formatter to add a styled
    terminal window frame, or strip ANSI codes for clean text.

    \b
    Examples:
      nmap -sV 10.10.10.10 | osk format render
      osk format render -f output.txt --title "Nmap Scan"
      echo "\\033[31mred text\\033[0m" | osk format render
      cat output.log | osk format strip
      cat output.log | osk format stats
    """
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


@format.command("render")
@click.argument("text", required=False)
@click.option("-f", "--file", "file_path", type=click.Path(exists=True),
              help="Read input from a file")
@click.option("-t", "--title", default=None,
              help="Window title (default: Terminal)")
@click.option("-n", "--line-numbers", is_flag=True, default=False,
              help="Show line numbers")
@click.option("-w", "--width", default=0, type=int,
              help="Fixed width in characters (0 = auto-fit content)")
@click.option("--theme", type=click.Choice(["dracula", "monokai"]),
              default="dracula", help="Color theme")
def render_cmd(text, file_path, title, line_numbers, width, theme):
    """Render terminal output with a styled window frame.

    \b
    Reads input from an argument, file (-f), or stdin (pipe).
    Outputs styled text with a terminal window frame to stdout.

    \b
    Examples:
      nmap -sV 10.10.10.10 | osk format render
      osk format render -f scan-output.txt --title "Nmap Results"
      osk format render "\\033[32mSuccess\\033[0m" --title "Status"
      cat results.log | osk format render -n --title "Log"
    """
    content = read_input(text, file_path)
    if content is None:
        raise click.ClickException(
            "No input provided.\n"
            "  Pass text as argument, use -f <file>, or pipe from stdin.\n"
            "  Example: nmap -sV 10.10.10.10 | osk format render"
        )

    result = format_output(content, title=title, line_numbers=line_numbers,
                           theme_name=theme, width=width)
    click.echo(result)


@format.command("strip")
@click.argument("text", required=False)
@click.option("-f", "--file", "file_path", type=click.Path(exists=True),
              help="Read input from a file")
def strip_cmd(text, file_path):
    """Strip all ANSI escape codes from terminal output.

    \b
    Removes color codes, bold/italic/underline, and other ANSI
    sequences to produce clean plain text.

    \b
    Examples:
      cat colored-output.log | osk format strip
      osk format strip -f output.txt
      osk format strip "\\033[31mred text\\033[0m"
    """
    content = read_input(text, file_path)
    if content is None:
        raise click.ClickException(
            "No input provided.\n"
            "  Pass text as argument, use -f <file>, or pipe from stdin."
        )

    click.echo(strip_ansi(content), nl=False)


@format.command("stats")
@click.argument("text", required=False)
@click.option("-f", "--file", "file_path", type=click.Path(exists=True),
              help="Read input from a file")
@click.option("--json", "json_output", is_flag=True, default=False,
              help="Output as JSON")
def stats_cmd(text, file_path, json_output):
    """Show statistics about terminal output.

    \b
    Displays line count, character count, number of ANSI codes,
    raw byte size, and maximum line width.

    \b
    Examples:
      cat output.log | osk format stats
      osk format stats -f output.txt --json
    """
    content = read_input(text, file_path)
    if content is None:
        raise click.ClickException(
            "No input provided.\n"
            "  Pass text as argument, use -f <file>, or pipe from stdin."
        )

    result = get_stats(content)

    if json_output:
        click.echo(json_mod.dumps(result, indent=2))
        return

    click.echo()
    click.secho("  Terminal Output Stats", bold=True)
    click.echo()

    rows = [
        ("Lines", str(result["lines"])),
        ("Characters", f"{result['characters']:,}"),
        ("ANSI Codes", str(result["ansi_codes"])),
        ("Raw Bytes", f"{result['raw_bytes']:,}"),
        ("Max Line Width", str(result["max_line_width"])),
    ]

    for label, value in rows:
        click.secho(f"  {label:<20} ", fg="bright_black", nl=False)
        click.secho(value, fg="white")

    click.echo()
