"""Unified CLI for OffSecKit."""

import click

from . import __version__
from .revshell.cmd import revshell
from .encode.cmd import encode
from .hash.cmd import hash
from .jwt.cmd import jwt
from .nmap.cmd import nmap
from .xss.cmd import xss

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
      osk jwt        Decode and analyze JWT tokens
      osk nmap       Build nmap commands visually
      osk xss        Generate XSS payloads with WAF bypass

    \b
    Examples:
      osk revshell -i 10.10.10.10 -l python
      osk encode -o base64-encode "Hello World"
      osk hash id 5d41402abc4b2a76b9719d911017c592
      osk hash generate -a sha256 "password"
      osk jwt decode eyJhbGciOiJIUzI1NiIs...
      osk jwt analyze eyJhbGciOiJIUzI1NiIs...
      osk nmap build -t 10.10.10.10 -sV --open
      osk xss gen -c html -a alert
      osk xss gen -c attr-double --waf cloudflare

    \b
    https://offseckit.com
    """


main.add_command(revshell)
main.add_command(encode)
main.add_command(hash)
main.add_command(jwt)
main.add_command(nmap)
main.add_command(xss)


if __name__ == "__main__":
    main()
