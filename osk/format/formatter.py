"""CLI output formatter logic.

Parses ANSI escape codes and re-renders terminal output with
styled coloring for the terminal. Can also strip ANSI codes
or convert output to styled plain text.
"""

import re
import sys


# ── ANSI Regex ────────────────────────────────────────────────────

ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-9;]*m")
ESCAPED_ANSI_RE = re.compile(r"(?:\\033|\\x1[bB]|\\e)\[([0-9;]*)m")


# ── Dracula color palette ─────────────────────────────────────────

THEMES = {
    "dracula": {
        "bg": "#282a36",
        "fg": "#f8f8f2",
        "colors": {
            "0": "#21222c",    # black
            "1": "#ff5555",    # red
            "2": "#50fa7b",    # green
            "3": "#f1fa8c",    # yellow
            "4": "#6272a4",    # blue
            "5": "#ff79c6",    # magenta
            "6": "#8be9fd",    # cyan
            "7": "#f8f8f2",    # white
            "8": "#6272a4",    # bright black
            "9": "#ff6e6e",    # bright red
            "10": "#69ff94",   # bright green
            "11": "#ffffa5",   # bright yellow
            "12": "#d6acff",   # bright blue
            "13": "#ff92df",   # bright magenta
            "14": "#a4ffff",   # bright cyan
            "15": "#ffffff",   # bright white
        },
    },
    "monokai": {
        "bg": "#272822",
        "fg": "#f8f8f2",
        "colors": {
            "0": "#272822",
            "1": "#f92672",
            "2": "#a6e22e",
            "3": "#e6db74",
            "4": "#66d9ef",
            "5": "#ae81ff",
            "6": "#66d9ef",
            "7": "#f8f8f2",
            "8": "#75715e",
            "9": "#f92672",
            "10": "#a6e22e",
            "11": "#e6db74",
            "12": "#66d9ef",
            "13": "#ae81ff",
            "14": "#66d9ef",
            "15": "#f9f8f5",
        },
    },
}


# ── ANSI mapping to click colors ─────────────────────────────────

ANSI_TO_CLICK = {
    30: "black",
    31: "red",
    32: "green",
    33: "yellow",
    34: "blue",
    35: "magenta",
    36: "cyan",
    37: "white",
    90: "bright_black",
    91: "bright_red",
    92: "bright_green",
    93: "bright_yellow",
    94: "bright_blue",
    95: "bright_magenta",
    96: "bright_cyan",
    97: "bright_white",
}


def unescape_ansi(text):
    """Convert escaped ANSI representations to actual escape characters.

    Handles: \\033[, \\x1b[, \\e[
    """
    text = text.replace("\\033[", "\x1b[")
    text = text.replace("\\x1b[", "\x1b[")
    text = text.replace("\\x1B[", "\x1b[")
    text = text.replace("\\e[", "\x1b[")
    return text


def strip_ansi(text):
    """Remove all ANSI escape codes from text."""
    return ANSI_ESCAPE_RE.sub("", text)


def read_input(text=None, file_path=None):
    """Read input from argument, file, or stdin.

    Returns the raw text content.
    """
    if text:
        return text
    if file_path:
        with open(file_path, "r") as f:
            return f.read()
    if not sys.stdin.isatty():
        return sys.stdin.read()
    return None


def format_output(text, title=None, line_numbers=False, theme_name="dracula", width=0):
    """Format terminal output with a styled terminal frame.

    Returns formatted string for terminal display.
    width: fixed width in characters (0 = auto-fit content).
    """
    text = unescape_ansi(text)
    lines = text.rstrip("\n").split("\n")

    # Terminal frame
    max_width = max(len(strip_ansi(line)) for line in lines) if lines else 0
    max_width = max(max_width, 40)  # Minimum width
    if width > 0:
        max_width = max(width, 40)

    frame_width = max_width + 4  # padding

    # Line number width
    num_width = len(str(len(lines))) if line_numbers else 0
    if line_numbers:
        frame_width += num_width + 2

    output_lines = []

    # Title bar
    title_text = title or "Terminal"
    title_pad = (frame_width - len(title_text)) // 2
    output_lines.append("")
    output_lines.append(
        f"  \033[90m{'─' * frame_width}\033[0m"
    )
    output_lines.append(
        f"  \033[90m│\033[0m"
        f" \033[31m●\033[0m \033[33m●\033[0m \033[32m●\033[0m"
        f"  \033[90m{title_text:^{frame_width - 12}}\033[0m"
        f" \033[90m│\033[0m"
    )
    output_lines.append(
        f"  \033[90m{'─' * frame_width}\033[0m"
    )

    # Content lines
    for i, line in enumerate(lines):
        prefix = ""
        if line_numbers:
            num_str = str(i + 1).rjust(num_width)
            prefix = f"\033[90m{num_str} │\033[0m "

        # Pad line to frame width
        visible_len = len(strip_ansi(line))
        pad_needed = max_width - visible_len
        padded_line = line + " " * pad_needed

        output_lines.append(
            f"  \033[90m│\033[0m {prefix}{padded_line} \033[90m│\033[0m"
        )

    # Bottom border
    output_lines.append(
        f"  \033[90m{'─' * frame_width}\033[0m"
    )
    output_lines.append("")

    return "\n".join(output_lines)


def get_stats(text):
    """Get statistics about the terminal output.

    Returns a dict with line count, char count, ANSI code count, etc.
    """
    text = unescape_ansi(text)
    lines = text.rstrip("\n").split("\n")
    ansi_codes = ANSI_ESCAPE_RE.findall(text)
    stripped = strip_ansi(text)

    return {
        "lines": len(lines),
        "characters": len(stripped),
        "ansi_codes": len(ansi_codes),
        "raw_bytes": len(text.encode("utf-8")),
        "max_line_width": max(len(line) for line in stripped.split("\n")) if stripped else 0,
    }
