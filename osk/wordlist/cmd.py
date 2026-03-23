"""Wordlist subcommand for osk."""

import sys

import click

from .mutations import (
    generate_wordlist,
    LEET_MAPPINGS,
    ALL_SYMBOLS,
    COMMON_SUFFIXES,
)


@click.group(invoke_without_command=True)
@click.pass_context
def wordlist(ctx):
    """Generate custom wordlists from base words with mutations.

    \b
    Examples:
      osk wordlist gen password admin
      osk wordlist gen -f words.txt --leet --numbers
      osk wordlist gen company -o wordlist.txt --case --leet --numbers --symbols
      echo "password" | osk wordlist gen --leet --suffixes
      osk wordlist leet
    """
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


@wordlist.command("gen")
@click.argument("words", nargs=-1)
@click.option("-f", "--file", "input_file", default=None, help="Read base words from file (one per line)")
@click.option("-o", "--output", "output_file", default=None, help="Write wordlist to file")
@click.option("--case/--no-case", default=True, help="Enable case variations (default: on)")
@click.option("--case-modes", default="original,lower,upper,capitalize",
              help="Comma-separated case modes: original,lower,upper,capitalize,toggle")
@click.option("--leet/--no-leet", default=False, help="Enable leet speak substitutions")
@click.option("--leet-chars", default="a,e,i,o,s",
              help="Comma-separated characters to leet (default: a,e,i,o,s)")
@click.option("--numbers/--no-numbers", default=False, help="Append numbers")
@click.option("--number-range", default="0-9",
              help="Comma-separated ranges: 0-9, 00-99, years (default: 0-9)")
@click.option("--year-start", default=2020, type=int, help="Start year for year range (default: 2020)")
@click.option("--year-end", default=2026, type=int, help="End year for year range (default: 2026)")
@click.option("--symbols/--no-symbols", default=False, help="Append symbols")
@click.option("--symbol-set", default="!,@,#,$",
              help="Comma-separated symbols to append")
@click.option("--suffixes/--no-suffixes", default=False, help="Append common suffixes (123, 1234, !, etc.)")
@click.option("--suffix-set", default=None,
              help="Comma-separated custom suffixes")
@click.option("--combine/--no-combine", default=False, help="Combine base words with separators")
@click.option("--separators", default="",
              help="Comma-separated separators for combine (default: empty string)")
@click.option("--max", "max_results", default=100000, type=int, help="Maximum words to generate (default: 100000)")
@click.option("--count", is_flag=True, help="Only show word count, don't output words")
def gen(words, input_file, output_file, case, case_modes, leet, leet_chars,
        numbers, number_range, year_start, year_end, symbols, symbol_set,
        suffixes, suffix_set, combine, separators, max_results, count):
    """Generate a mutated wordlist from base words."""
    # Collect base words
    base_words = list(words)

    if input_file:
        try:
            with open(input_file) as f:
                base_words.extend(line.strip() for line in f if line.strip())
        except FileNotFoundError:
            raise click.ClickException(f"File not found: {input_file}")

    if not base_words and not sys.stdin.isatty():
        base_words.extend(line.strip() for line in sys.stdin if line.strip())

    if not base_words:
        raise click.ClickException(
            "No base words provided. Pass words as arguments, use -f, or pipe via stdin."
        )

    result = generate_wordlist(
        base_words=base_words,
        enable_case=case,
        case_variations=[m.strip() for m in case_modes.split(",")],
        enable_leet=leet,
        leet_chars=[c.strip() for c in leet_chars.split(",")],
        enable_numbers=numbers,
        number_ranges=[r.strip() for r in number_range.split(",")],
        year_start=year_start,
        year_end=year_end,
        enable_symbols=symbols,
        symbols=[s.strip() for s in symbol_set.split(",")],
        enable_suffixes=suffixes,
        suffixes=[s.strip() for s in suffix_set.split(",")] if suffix_set else None,
        enable_combine=combine,
        separators=[s.strip() for s in separators.split(",")],
        max_results=max_results,
    )

    if count:
        click.echo(len(result))
        return

    if output_file:
        with open(output_file, "w") as f:
            f.write("\n".join(result) + "\n")
        click.secho(f"# Wrote {len(result)} words to {output_file}", fg="green")
    else:
        for word in result:
            click.echo(word)

        if sys.stdout.isatty():
            click.secho(f"\n# {len(result)} words generated", fg="bright_black")


@wordlist.command("leet")
def leet_cmd():
    """Show leet speak character mappings."""
    click.secho("  Leet Speak Mappings\n", fg="cyan")
    click.secho(f"  {'Char':<8} {'Replacements'}", fg="bright_black")
    click.secho(f"  {'─' * 8} {'─' * 20}", fg="bright_black")

    for char, replacements in LEET_MAPPINGS.items():
        click.secho(f"  {char:<8}", fg="cyan", nl=False)
        click.echo(f" {', '.join(replacements)}")


@wordlist.command("suffixes")
def suffixes_cmd():
    """Show common password suffixes."""
    click.secho("  Common Password Suffixes\n", fg="cyan")
    for s in COMMON_SUFFIXES:
        click.echo(f"  {s}")


@wordlist.command("symbols")
def symbols_cmd():
    """Show available symbols for appending."""
    click.secho("  Available Symbols\n", fg="cyan")
    click.echo(f"  {' '.join(ALL_SYMBOLS)}")
