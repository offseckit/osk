"""CVSS subcommand for osk."""

import json as json_mod

import click

from .scorer import (
    parse_cvss31,
    parse_cvss40,
    calc_cvss31,
    calc_cvss40,
    build_vector_31,
    build_vector_40,
    PRESETS,
    SEV_COLORS,
)


@click.group(invoke_without_command=True)
@click.pass_context
def cvss(ctx):
    """Calculate CVSS 3.1 and 4.0 vulnerability scores.

    \b
    Parse an existing vector or build one from individual metrics.

    \b
    Examples:
      osk cvss calc CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
      osk cvss calc CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N
      osk cvss presets
      osk cvss compare <vector1> <vector2>
    """
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


@cvss.command("calc")
@click.argument("vector")
@click.option("--json", "json_output", is_flag=True, default=False,
              help="Output results as JSON")
def calc_cmd(vector, json_output):
    """Calculate the CVSS score for a vector string.

    \b
    Accepts CVSS 3.1 (CVSS:3.1/...) and CVSS 4.0 (CVSS:4.0/...) vectors.

    \b
    Examples:
      osk cvss calc CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
      osk cvss calc CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N
      osk cvss calc CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N --json
    """
    vector = vector.strip()

    # Try CVSS 3.1
    metrics = parse_cvss31(vector)
    if metrics:
        result = calc_cvss31(metrics)
        vec_str = build_vector_31(metrics)

        if json_output:
            out = {
                "version": "3.1",
                "vector": vec_str,
                "baseScore": result["base"],
                "impactScore": result["impact"],
                "exploitabilityScore": result["exploitability"],
                "severity": result["severity"],
            }
            if result.get("temporal") is not None and any(metrics.get(k, "X") != "X" for k in ["E", "RL", "RC"]):
                out["temporalScore"] = result["temporal"]
            if result.get("environmental") is not None:
                out["environmentalScore"] = result["environmental"]
            click.echo(json_mod.dumps(out, indent=2))
            return

        _print_31_result(vec_str, result, metrics)
        return

    # Try CVSS 4.0
    metrics = parse_cvss40(vector)
    if metrics:
        result = calc_cvss40(metrics)
        vec_str = build_vector_40(metrics)

        if json_output:
            click.echo(json_mod.dumps({
                "version": "4.0",
                "vector": vec_str,
                "score": result["score"],
                "severity": result["severity"],
            }, indent=2))
            return

        _print_40_result(vec_str, result)
        return

    raise click.ClickException(
        f"Invalid CVSS vector: {vector}\n"
        "  Must start with CVSS:3.1/ or CVSS:4.0/ and include all required base metrics."
    )


@cvss.command("presets")
@click.option("--version", "ver", type=click.Choice(["3.1", "4.0"]), default="3.1",
              help="CVSS version for preset vectors")
def presets_cmd(ver):
    """Show CVSS vectors for common vulnerability types.

    \b
    Examples:
      osk cvss presets
      osk cvss presets --version 4.0
    """
    click.echo()
    click.secho(f"  Common Vulnerability Presets (CVSS {ver})", bold=True)
    click.echo()

    for slug, label, v31, v40 in PRESETS:
        vec = v31 if ver == "3.1" else v40
        metrics = parse_cvss31(vec) if ver == "3.1" else parse_cvss40(vec)
        if not metrics:
            continue

        if ver == "3.1":
            result = calc_cvss31(metrics)
            score = result["base"]
            sev = result["severity"]
        else:
            result = calc_cvss40(metrics)
            score = result["score"]
            sev = result["severity"]

        color = SEV_COLORS.get(sev, "white")
        click.secho(f"  {score:>4.1f} ", fg=color, bold=True, nl=False)
        click.secho(f"[{sev:<8}] ", fg=color, nl=False)
        click.secho(f"{label:<30}", fg="cyan", nl=False)
        click.secho(vec, fg="bright_black")

    click.echo()


@cvss.command("compare")
@click.argument("vector1")
@click.argument("vector2")
def compare_cmd(vector1, vector2):
    """Compare two CVSS vectors side by side.

    \b
    Both vectors must be the same version (3.1 or 4.0).

    \b
    Examples:
      osk cvss compare CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:H
    """
    r1, v1_ver = _calc_any(vector1)
    r2, v2_ver = _calc_any(vector2)

    if r1 is None:
        raise click.ClickException(f"Invalid vector: {vector1}")
    if r2 is None:
        raise click.ClickException(f"Invalid vector: {vector2}")

    s1 = r1["base"] if v1_ver == "3.1" else r1["score"]
    s2 = r2["base"] if v2_ver == "3.1" else r2["score"]
    sev1 = r1["severity"]
    sev2 = r2["severity"]

    click.echo()
    click.secho("  Vector 1:", bold=True)
    click.secho(f"    {vector1}", fg="cyan")
    click.secho(f"    Score: ", nl=False)
    click.secho(f"{s1:.1f} ({sev1})", fg=SEV_COLORS.get(sev1, "white"), bold=True)
    click.echo()

    click.secho("  Vector 2:", bold=True)
    click.secho(f"    {vector2}", fg="cyan")
    click.secho(f"    Score: ", nl=False)
    click.secho(f"{s2:.1f} ({sev2})", fg=SEV_COLORS.get(sev2, "white"), bold=True)
    click.echo()

    diff = s1 - s2
    if abs(diff) < 0.05:
        click.secho("  Difference: 0.0 (identical scores)", fg="bright_black")
    elif diff > 0:
        click.secho(f"  Difference: +{diff:.1f} (Vector 1 is more severe)", fg="red")
    else:
        click.secho(f"  Difference: {diff:.1f} (Vector 2 is more severe)", fg="red")
    click.echo()


# ── Helpers ────────────────────────────────────────────────────────

def _calc_any(vector):
    """Parse and calculate any CVSS version. Returns (result, version) or (None, None)."""
    vector = vector.strip()
    m = parse_cvss31(vector)
    if m:
        return calc_cvss31(m), "3.1"
    m = parse_cvss40(vector)
    if m:
        return calc_cvss40(m), "4.0"
    return None, None


def _print_31_result(vector, result, metrics):
    sev = result["severity"]
    color = SEV_COLORS.get(sev, "white")

    click.echo()
    click.secho(f"  CVSS 3.1", bold=True)
    click.secho(f"  {vector}", fg="cyan")
    click.echo()

    click.secho(f"  Base Score:     ", nl=False)
    click.secho(f"{result['base']:.1f}", fg=color, bold=True, nl=False)
    click.secho(f"  ({sev})", fg=color)

    click.secho(f"  Impact:         {result['impact']:.1f}", fg="bright_black")
    click.secho(f"  Exploitability: {result['exploitability']:.1f}", fg="bright_black")

    has_temporal = any(metrics.get(k, "X") != "X" for k in ["E", "RL", "RC"])
    if has_temporal:
        click.secho(f"  Temporal Score: {result['temporal']:.1f}", fg="bright_black")

    if result.get("environmental") is not None:
        click.secho(f"  Environmental:  {result['environmental']:.1f}", fg="bright_black")

    click.echo()


def _print_40_result(vector, result):
    sev = result["severity"]
    color = SEV_COLORS.get(sev, "white")

    click.echo()
    click.secho(f"  CVSS 4.0", bold=True)
    click.secho(f"  {vector}", fg="cyan")
    click.echo()

    click.secho(f"  Score: ", nl=False)
    click.secho(f"{result['score']:.1f}", fg=color, bold=True, nl=False)
    click.secho(f"  ({sev})", fg=color)
    click.echo()
