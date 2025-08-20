# password-analyzer-wordlist
A Python CLI tool to analyze password strength and generate context-aware wordlists with leetspeak, suffixes, and custom patterns. Built for educational and authorized security testing.
Password Strength Analyzer & Custom Wordlist Generator

Overview

A Python CLI tool that evaluates password strength using zxcvbn (with
entropy fallback) and generates context-aware wordlists from
user-provided information such as names, dates of birth, and locations.
This project is intended for educational and authorized use only.

Features

-   Analyze password strength (score 0–4) with feedback and crack time
    estimates.
-   Generate custom wordlists with case variants, leetspeak, years,
    suffixes, and separators.
-   Controlled size limits (e.g., cap at 5,000 candidates).
-   Clean CLI interface; no external services required.

Installation

    git clone <your_repo_url>
    cd password-tool
    python -m venv .venv
    source .venv/bin/activate   # Windows: .venv\Scripts\activate
    pip install -r requirements.txt

Usage

Analyze a Password

    python3 password_tool.py analyze --password 'P@ssw0rd123!' --hints naman patil mumbai

Generate a Custom Wordlist

    python3 password_tool.py generate \
      --keywords "naman,patil,mumbai" \
      --dob 2002-08-09 \
      --years 2018-2025 \
      --suffixes '!,@,123' \
      --leet basic \
      --max 5000 \
      --outfile wordlist.txt

Both (Analyze + Wordlist)

    python3 password_tool.py both \
      --password "Naman@2002" \
      --hints naman patil mumbai \
      --keywords "naman,patil,mumbai" \
      --dob 2002-08-09 \
      --years 2018-2025 \
      --suffixes '!,@,123' \
      --leet basic \
      --max 3000 \
      --outfile wordlist.txt

Repository Structure

    password-tool/
    ├── password_tool.py        # Main script
    ├── requirements.txt        # Dependencies
    ├── samples/                # Sample outputs (e.g., wordlist.txt)
    └── README.md               # Documentation

Ethics

⚠️ This tool is provided for educational and authorized testing only.
Do not attempt to use it against accounts or systems without explicit
permission.

License

MIT License (or your chosen license).
