# >_ osk

**Free offensive security toolkit for your terminal — reverse shells, encoding, hashing, and more.**

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

# Generate SHA-256 hash
osk hash generate -a sha256 "password"
```

## Tools

| Command | Description |
|---------|-------------|
| `osk revshell` | Generate reverse shell one-liners in 12+ languages |
| `osk encode` | Encode/decode text (Base64, URL, Hex, HTML, Unicode, Binary, ROT13, ...) |
| `osk hash` | Identify hash types and generate hashes (MD5, SHA1, SHA256, NTLM, ...) |

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

### Options

| Flag | Description |
|------|-------------|
| `-o, --op` | Operation to apply (repeatable, chained in order) |
| `-i, --input` | Input text (alternative to positional arg) |
| `-s, --steps` | Show intermediate results for chains |

## Hash Identification & Generation

```bash
# Identify a hash
osk hash id 5d41402abc4b2a76b9719d911017c592

# Generate MD5 + SHA-256 + NTLM
osk hash generate -a md5 -a sha256 -a ntlm "password"

# Generate all default hashes
osk hash generate "hello"

# Pipe from stdin
echo "admin" | osk hash generate -a sha512

# List supported algorithms
osk hash list
```

### Supported Algorithms

| Algorithm | Bits |
|-----------|------|
| MD5 | 128 |
| SHA-1 | 160 |
| SHA-256 | 256 |
| SHA-384 | 384 |
| SHA-512 | 512 |
| NTLM | 128 |
| SHA3-256 | 256 |
| SHA3-512 | 512 |

## Requirements

- Python 3.8+
- click

## Related

- [OffSecKit](https://offseckit.com) — free browser-based security toolkit
- [Reverse Shell Generator](https://offseckit.com/tools/revshell) — browser version
- [Encoding Multi-Tool](https://offseckit.com/tools/encode) — browser version
- [Hash Identifier](https://offseckit.com/tools/hash) — browser version

## License

MIT
