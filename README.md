# >_ osk

**Free offensive security toolkit for your terminal — reverse shells, encoding, hashing, JWT analysis, nmap building, XSS payloads, header security analysis, CVSS scoring, subnet calculation, terminal output formatting, and more.**

Part of [OffSecKit](https://offseckit.com) — all tools also available as [browser tools](https://offseckit.com/tools).

## Install

```bash
pip install offseckit
```

Or clone and install locally:

```bash
git clone https://github.com/offseckit/osk.git
cd osk
pip install .
```

## Quick Start

```bash
# Generate a reverse shell
osk revshell -i 10.10.10.10 -l python

# Encode text to Base64
osk encode -o base64-encode "Hello World"

# Identify a hash
osk hash id 5d41402abc4b2a76b9719d911017c592

# Decode a JWT token
osk jwt decode eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

# Build an nmap command
osk nmap build -t 10.10.10.0/24 --syn --top-ports 1000

# Generate XSS payloads
osk xss gen --context html-attr --action alert

# Analyze security headers
curl -sI https://example.com | osk headers analyze

# Calculate a CVSS score
osk cvss calc CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

# Calculate subnet details
osk subnet calc 192.168.1.0/24

# Format terminal output with a styled frame
nmap -sV 10.10.10.10 | osk format render
```

## Tools

| Command | Description |
|---------|-------------|
| `osk revshell` | Generate reverse shell one-liners in 12+ languages |
| `osk encode` | Encode/decode text (Base64, URL, Hex, HTML, Unicode, Binary, ROT13, ...) |
| `osk hash` | Identify hash types and generate hashes (MD5, SHA1, SHA256, NTLM, ...) |
| `osk jwt` | Decode and analyze JWT tokens for security issues |
| `osk nmap` | Build nmap commands with scan types, scripts, timing, and evasion |
| `osk xss` | Generate context-aware XSS payloads with WAF bypass and encoding |
| `osk headers` | Analyze HTTP response headers for security misconfigurations |
| `osk cvss` | Calculate CVSS 3.1 and 4.0 vulnerability scores |
| `osk subnet` | Calculate subnet details, split networks, check IP containment |
| `osk format` | Format and beautify terminal output with styled window frames |

## Reverse Shells

```bash
# Bash reverse shell
osk revshell -i 10.10.10.10 -p 4444

# Python reverse shell with Base64 encoding
osk revshell -i 10.10.10.10 -l python -e base64

# PowerShell reverse shell
osk revshell -i 10.10.10.10 -l powershell

# Show all netcat variants
osk revshell -i 10.10.10.10 -l netcat --all

# List all supported languages
osk revshell list
```

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `-i, --ip` | Attacker IP address | (required) |
| `-p, --port` | Attacker port | `4444` |
| `-l, --lang` | Language | `bash` |
| `-v, --variant` | Specific variant | first available |
| `-e, --encoding` | `raw`, `base64`, `url`, `double-url` | `raw` |
| `--all` | Show all variants | — |
| `--no-listener` | Hide listener command | — |

## Encoding & Decoding

```bash
# Base64 encode
osk encode -o base64-encode "Hello World"

# URL decode
osk encode -o url-decode "%48%65%6C%6C%6F"

# Chain: Base64 then URL encode
osk encode -o base64-encode -o url-encode "test payload"

# Double URL encode for WAF bypass
osk encode -o url-encode -o url-encode "<script>alert(1)</script>"

# Show intermediate steps
osk encode -o base64-encode -o url-encode -o hex-encode "test" --steps

# Pipe from stdin
echo "secret" | osk encode -o hex-encode

# List all operations
osk encode list
```

## Hash Identification & Generation

```bash
# Identify a hash
osk hash id 5d41402abc4b2a76b9719d911017c592

# Generate MD5 + SHA-256 + NTLM
osk hash generate -a md5 -a sha256 -a ntlm "password"

# Generate all default hashes
osk hash generate "hello"

# List supported algorithms
osk hash list
```

## JWT Decoder & Analyzer

```bash
# Decode a JWT token
osk jwt decode eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U

# Analyze for security issues
osk jwt analyze eyJhbGciOiJIUzI1NiIs...

# List supported algorithms
osk jwt algorithms
```

## Nmap Command Builder

```bash
# Quick recon scan
osk nmap preset quick-recon -t 10.10.10.0/24

# Full port SYN scan with service detection
osk nmap build -t 10.10.10.10 --syn --all-ports --service-version

# Stealth scan with evasion
osk nmap build -t 10.10.10.10 --syn --timing T2 --fragment

# List presets
osk nmap presets

# List scan types
osk nmap scans
```

## XSS Payload Generator

```bash
# Generate payloads for HTML attribute context
osk xss gen --context html-attr --action alert

# Generate with WAF bypass encoding
osk xss gen --context js-string --waf cloudflare

# Generate with blocked characters
osk xss gen --context html-tag --block "<" --block ">"

# Show polyglot payloads
osk xss polyglots

# List all contexts
osk xss contexts
```

## HTTP Header Security Analyzer

```bash
# Fetch headers directly from a URL
osk headers analyze -u https://example.com

# Pipe headers from curl
curl -sI https://example.com | osk headers analyze

# Read from a file
osk headers analyze -f response-headers.txt

# Output as JSON for CI/CD
osk headers analyze -u https://example.com --json

# List all security headers checked
osk headers list
```

## CVSS Calculator

```bash
# Calculate CVSS 3.1 score from a vector
osk cvss calc CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

# Calculate CVSS 4.0 score
osk cvss calc CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N

# Output as JSON for CI/CD
osk cvss calc CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H --json

# Show common vulnerability presets
osk cvss presets

# Compare two vectors
osk cvss compare CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:H
```

## Subnet Calculator

```bash
# Calculate subnet details from CIDR
osk subnet calc 192.168.1.0/24

# Calculate with JSON output for scripting
osk subnet calc 10.10.10.0/26 --json

# Split a network into equal subnets
osk subnet split 10.0.0.0/16 --into 4

# Check if an IP is within a CIDR range
osk subnet contains 192.168.1.0/24 192.168.1.100

# List all usable hosts in a subnet
osk subnet list 192.168.1.0/28
```

## CLI Output Formatter

```bash
# Render terminal output with a styled window frame
nmap -sV 10.10.10.10 | osk format render

# Render from a file with a custom title
osk format render -f output.txt --title "Nmap Scan Results"

# Add line numbers
cat output.log | osk format render -n --title "Server Logs"

# Strip all ANSI escape codes
cat colored-output.log | osk format strip

# Get output statistics
cat output.log | osk format stats --json
```

## Requirements

- Python 3.8+

## Related

- [OffSecKit](https://offseckit.com) — free browser-based security toolkit
- [Reverse Shell Generator](https://offseckit.com/tools/revshell) — browser version
- [Encoding Multi-Tool](https://offseckit.com/tools/encode) — browser version
- [Hash Identifier](https://offseckit.com/tools/hash) — browser version
- [JWT Decoder](https://offseckit.com/tools/jwt) — browser version
- [Nmap Builder](https://offseckit.com/tools/nmap) — browser version
- [XSS Generator](https://offseckit.com/tools/xss) — browser version
- [Header Security Analyzer](https://offseckit.com/tools/headers) — browser version
- [CVSS Calculator](https://offseckit.com/tools/cvss) — browser version
- [Subnet Calculator](https://offseckit.com/tools/subnet) — browser version
- [CLI Output Formatter](https://offseckit.com/tools/cli-format) — browser version

## License

MIT
