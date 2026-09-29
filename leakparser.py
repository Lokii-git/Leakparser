#!/usr/bin/env python3

import json
import os
import shutil
import argparse
import subprocess
import sys
import re
from collections import Counter
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

# ───── Ensure 'rich' is installed ─────
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
except ImportError:
    print("[*] 'rich' not found. Installing...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "rich"])
        from rich.console import Console
        from rich.table import Table
        from rich.panel import Panel
        from rich.text import Text
        print("[+] 'rich' installed.\n")
    except subprocess.CalledProcessError:
        print("[!] Failed to install 'rich'. Please install manually.")
        sys.exit(1)

console = Console()

# ───── Detect Hash Type ─────

def detect_hash_type(pw):
    if re.fullmatch(r"[a-fA-F0-9]{32}", pw): return "MD5/NTLM"
    if re.fullmatch(r"[a-fA-F0-9]{40}", pw): return "SHA1"
    if re.fullmatch(r"[a-fA-F0-9]{64}", pw): return "SHA256"
    if re.fullmatch(r"[a-fA-F0-9]{128}", pw): return "SHA512"
    if pw.startswith(("$2a$", "$2b$", "$2y$")): return "bcrypt"
    return None

# ───── Parse a Single File ─────

def parse_file(filepath, emails, passwords, hashes, userpass, domains, hash_types):
    with open(filepath, "r") as f:
        data = json.load(f)

    for domain, records in data.items():
        for entry in records:
            email = entry.get("email_address", "").strip().lower()
            password = entry.get("password", "").strip()
            if email and password and password.upper() != "NULL" and password != "-":
                domain_part = email.split("@")[-1]
                domains[domain_part] += 1
                emails.add(email)
                htype = detect_hash_type(password)
                if htype:
                    hashes.add(password)
                    hash_types[htype] += 1
                    userpass.append((email, password, False))  # False = not plaintext
                else:
                    passwords.add(password)
                    userpass.append((email, password, True))   # True = plaintext

# ───── Main Function ─────

def _mask_secret(password: str, is_plaintext: bool) -> str:
    """
    Redact a leaked credential for client-facing display (T11 / E-24).

    The leakparser stdout is captured into the report figure (fig_3.1.16_leakparser.png),
    so a real password or hash in that PNG would be a credential leak. Reveal only the
    credential *kind* (plaintext vs hash type), never the value. The consultant keeps
    the raw values in the operator-only passwords.txt / hashes.txt working files.
    """
    kind = "plaintext" if is_plaintext else (detect_hash_type(password) or "hash")
    return "•••••••• (%s)" % kind

def main():
    parser = argparse.ArgumentParser(description="Leak-Lookup JSON parser")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-f", "--file", help="Single Leak-Lookup JSON file")
    group.add_argument("-F", "--folder", action="store_true", help="Parse all JSON files in current folder")
    args = parser.parse_args()

    emails = set()
    passwords = set()
    hashes = set()
    userpass = []
    domains = Counter()
    hash_types = Counter()

    if args.file:
        if not os.path.isfile(args.file):
            console.print(f"[bold red][!] File not found: {args.file}[/bold red]")
            return
        parse_file(args.file, emails, passwords, hashes, userpass, domains, hash_types)
        source_files = [args.file]
    elif args.folder:
        json_files = [f for f in os.listdir(os.getcwd()) if f.endswith(".json")]
        if not json_files:
            console.print("[bold red][!] No JSON files found in current directory.[/bold red]")
            return
        source_files = []
        for f in json_files:
            parse_file(f, emails, passwords, hashes, userpass, domains, hash_types)
            source_files.append(f)

    inferred_domains = ", ".join(sorted(domains)) if domains else "Unknown"
    total_records = len(userpass)
    unique_emails = len(emails)
    unique_passwords = len(passwords) + len(hashes)
    hash_count = len(hashes)
    plaintext_count = len(passwords)

    hash_breakdown = "\n".join([f" - {k.ljust(10)} {str(v).rjust(3)}" for k, v in sorted(hash_types.items())]) if hash_types else "None"

    stats = [
        ("Total Records:", total_records),
        ("Unique Emails:", unique_emails),
        ("Unique Passwords:", unique_passwords),
        ("→ Likely Hashes:", hash_count),
        ("→ Plaintext Passwords:", plaintext_count),
    ]

    stat_lines = "\n".join([f"[bold]{label.ljust(24)}[/bold] {str(value).rjust(5)}" for label, value in stats])

    banner = Panel.fit(f"""
[bold]Leak-Lookup Results[/bold]

[bold cyan]Domains Detected:[/bold cyan]        {inferred_domains}

{stat_lines}

[bold]Hash Type Breakdown:[/bold]
{hash_breakdown}
""", title="📊 Summary", border_style="bright_blue")

    console.print(banner)

    table = Table(title="User:Password Combos", show_lines=True)
    table.add_column("User:Password", style="cyan", overflow="fold")
    for email, password, is_plaintext in userpass:
        # T11/E-24: shown redacted — the value is secret; the kind is informative.
        line = f"{email}: {_mask_secret(password, is_plaintext)}"
        if is_plaintext:
            table.add_row(Text(line, style="bold red"))
        else:
            table.add_row(line)
    console.print(table)

    output_dir = os.path.join(os.getcwd(), "leaklookup")
    os.makedirs(output_dir, exist_ok=True)

    for f in source_files:
        dst = os.path.join(output_dir, os.path.basename(f))
        try:
            shutil.copy2(f, dst)
        except shutil.SameFileError:
            pass  # source JSON is already inside the output dir

    with open(os.path.join(output_dir, "users.txt"), "w") as f:
        f.write("\n".join(sorted(emails)))
    with open(os.path.join(output_dir, "passwords.txt"), "w") as f:
        f.write("\n".join(sorted(passwords)))
    with open(os.path.join(output_dir, "hashes.txt"), "w") as f:
        f.write("\n".join(sorted(hashes)))

    console.print(f"\n[bold green]✔ Files saved to:[/bold green] {os.path.relpath(output_dir)}")

if __name__ == "__main__":
    main()
