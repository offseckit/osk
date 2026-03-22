"""Unified CLI for OffSecKit."""

import click

from . import __version__
from .revshell.cmd import revshell
from .encode.cmd import encode
from .hash.cmd import hash

BANNER = f"""\
\033[32m>_\033[0m \033[1mosk\033[0m \033[90mv{__version__}\033[0m
\033[90m   offseckit.com\033[0m
"""


@click.group()
@click.version_option(__version__, prog_name="osk")
def main():
    """OffSecKit — free offensive security toolkit for your terminal.

    \b
    Tools:
      osk revshell   Generate reverse shell one-liners
      osk encode     Encode and decode text (Base64, URL, Hex, ...)
      osk hash       Identify and generate hashes

    \b
    Examples:
      osk revshell -i 10.10.10.10 -l python
      osk encode -o base64-encode "Hello World"
      osk hash id 5d41402abc4b2a76b9719d911017c592
      osk hash generate -a sha256 "password"

    \b
    https://offseckit.com
    """


main.add_command(revshell)
main.add_command(encode)
main.add_command(hash)


if __name__ == "__main__":
    main()
