# Leakparser

Leakparser is a data breach analysis tool that parses Leak-Lookup JSON files to extract credential data. It identifies email addresses, distinguishes between plaintext passwords and hashed credentials (MD5/NTLM, SHA1, SHA256, SHA512, bcrypt), and generates a formatted summary report using the `rich` library. The tool also exports extracted data to text files for further analysis.

## How to Run

The script requires Python 3 and the `rich` library. If `rich` is not installed, the script will attempt to install it automatically via `pip`.

```bash
# Parse a single JSON file
python leakparser.py -f <path_to_json_file>

# Parse all JSON files in the current directory
python leakparser.py -F
```

### Optional Setup
You can create a global symlink to run the tool as `leakparser` from anywhere:

```bash
./setup.sh
```
*Note: `setup.sh` assumes the script is located at `/opt/leakparser/leakparser.py` and requires `sudo` to create the symlink in `/usr/local/bin`.*

## Key Files

- `leakparser.py`: The primary script for parsing and reporting.
- `setup.sh`: Utility script to create a system-wide symlink.

## Output

Upon execution, the tool prints a summary panel to the console including:
- Detected domains
- Total records, unique emails, and unique passwords
- Split between likely hashes and plaintext passwords
- A per-type hash breakdown (MD5/NTLM, SHA1, SHA256, SHA512, bcrypt)
- A table of the `user:password` combinations (credential values redacted — see below)

### Credential Redaction (client-safe display)

The console table never prints live credential values. Each row shows the email address plus only the credential **kind**:

```
user@example.com: •••••••• (plaintext)
user2@example.com: •••••••• (MD5/NTLM)
```

Plaintext rows are additionally highlighted in bold red so they stand out. This is deliberate: in report workflows the tool's stdout is captured into client-facing report figures, so a real password or hash in that output would itself become a credential leak. The consultant keeps the raw values in the operator-only export files below.

It also creates a `leaklookup` directory in the current working directory containing:
- `users.txt`: Sorted list of unique email addresses
- `passwords.txt`: Sorted list of unique **plaintext** passwords (raw values)
- `hashes.txt`: Sorted list of unique **hashed** passwords (raw values)
- Copies of the source JSON files

> ⚠️ `passwords.txt` and `hashes.txt` contain live credentials. Treat them as operator-only working files: keep them out of client deliverables and report figures, and restrict who can read them.

## Gotchas

- **Input Format**: The tool expects JSON files structured as `{ "domain": [ { "email_address": "...", "password": "..." }, ... ] }`.
- **Hash Detection**: Hash types are inferred based on string length and prefix (e.g., 32 hex chars = MD5/NTLM). This is a heuristic and not a cryptographic verification.
- **Null Passwords**: Entries with empty, `null`/`NULL` (case-insensitive), or `-` passwords are skipped entirely — the email is not captured.
- **Directory Mode**: When using `-F`, the script only looks for `.json` files in the current directory (`os.getcwd()`), not recursively.
