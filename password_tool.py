#!/usr/bin/env python3
"""
Password Strength Analyzer & Custom Wordlist Generator
Educational tool for authorized security testing and awareness.

Features:
- Strength analysis via zxcvbn (score 0–4) with safe entropy fallback.
- Custom wordlist generation from user context:
  * case variants, leetspeak, years, separators, and suffixes.
- Size controls (max candidates), deduplication, and input validation.

Usage examples:
  Analyze one password:
    python password_tool.py analyze --password "P@ssw0rd123" --hints naman patil mumbai

  Generate a wordlist:
    python password_tool.py generate --keywords "naman,patil" --dob 2002-08-09 \
      --years 2018-2025 --suffixes "!,@,123" --leet aggressive --max 20000 \
      --outfile wordlist.txt
"""

from __future__ import annotations
import argparse, itertools, json, math, re, sys
from datetime import datetime
from typing import Iterable, List, Set, Dict

# -------- Optional zxcvbn import with graceful fallback --------
ZXCVBN_AVAILABLE = True
try:
    from zxcvbn import zxcvbn  # pip install zxcvbn
except Exception:
    ZXCVBN_AVAILABLE = False

def entropy_estimate(password: str) -> float:
    """Very rough fallback: assumes ~94 printable chars."""
    # Avoid division by zero and trivial cases
    if not password:
        return 0.0
    charset = 94.0  # printable ASCII
    # log2(charset^len) = len * log2(charset)
    return len(password) * math.log2(charset)

def analyze_password(password: str, user_inputs: List[str] | None = None) -> Dict:
    """Analyze strength using zxcvbn if available; otherwise entropy fallback."""
    user_inputs = user_inputs or []
    if ZXCVBN_AVAILABLE:
        result = zxcvbn(password, user_inputs=user_inputs)
        # Normalize a compact view for CLI
        return {
            "engine": "zxcvbn",
            "score": result.get("score"),  # 0–4
            "crack_times_display": result.get("crack_times_display", {}),
            "guesses_log10": result.get("guesses_log10"),
            "feedback": result.get("feedback", {}),
        }
    # Fallback mode
    ent = entropy_estimate(password)
    # Heuristic mapping to 0–4
    if ent < 28:
        score = 0
    elif ent < 36:
        score = 1
    elif ent < 60:
        score = 2
    elif ent < 80:
        score = 3
    else:
        score = 4
    return {
        "engine": "entropy_fallback",
        "score": score,
        "entropy_bits_est": round(ent, 2),
        "feedback": {
            "warning": "Using fallback estimator. Install 'zxcvbn' for richer results.",
            "suggestions": [
                "Use longer passphrases (3–5+ random words).",
                "Avoid personal info and common patterns.",
                "Include variety (case, digits, symbols) but prioritize length."
            ],
        },
    }

# ---------------- Wordlist generation utilities ----------------

LEET_MAP = {
    "a": ["a", "4", "@"],
    "e": ["e", "3"],
    "i": ["i", "1", "!"],
    "o": ["o", "0"],
    "s": ["s", "5", "$"],
    "t": ["t", "7"],
    "g": ["g", "9"],
    "b": ["b", "8"],
    "l": ["l", "1"],
}

def case_variants(word: str) -> Set[str]:
    variants = {word}
    variants.add(word.lower())
    variants.add(word.upper())
    variants.add(word.capitalize())
    variants.add(word.title())
    return variants

def leet_variants(word: str, aggressive: bool, cap: int = 16) -> Set[str]:
    """
    Generate leetspeak variants.
    aggressive=False: limit to single-position substitutions to prevent explosion.
    aggressive=True: allow multiple-position substitutions (capped).
    """
    variants = {word}
    positions = [(i, ch) for i, ch in enumerate(word.lower()) if ch in LEET_MAP]

    # No leet candidates
    if not positions:
        return variants

    # For each position, possible replacements (keeping original too)
    choices = []
    for i, ch in positions:
        choices.append(LEET_MAP[ch])

    produced = set()
    def apply_variant(mask: List[int]):
        s = list(word)
        for (idx, (pos, ch)), choice_idx in zip(enumerate(positions), mask):
            s[pos] = LEET_MAP[ch][choice_idx]
        produced.add("".join(s))

    if not aggressive:
        # Single-position substitutions only
        for j, (pos, ch) in enumerate(positions):
            for choice_idx in range(1, min(len(LEET_MAP[ch]), 2)):  # pick a couple
                s = list(word)
                s[pos] = LEET_MAP[ch][choice_idx]
                produced.add("".join(s))
    else:
        # Multi-position combinations, but cap total to avoid blowup
        rngs = [range(min(len(c), 3)) for c in choices]  # limit each position's options
        for mask in itertools.product(*rngs):
            apply_variant(list(mask))
            if len(produced) >= cap:
                break

    variants |= produced
    return variants

def tokenize_keywords(raw: str | None) -> List[str]:
    if not raw:
        return []
    parts = re.split(r"[,\s]+", raw.strip())
    return [p for p in parts if p]

def parse_years(years: str | None, dob: str | None) -> List[str]:
    out: Set[str] = set()
    if years:
        m = re.match(r"^\s*(\d{4})\s*-\s*(\d{4})\s*$", years)
        if m:
            start, end = int(m.group(1)), int(m.group(2))
            for y in range(start, end + 1):
                out.add(str(y))
        else:
            for y in re.split(r"[,\s]+", years.strip()):
                if y.isdigit() and len(y) in (2, 4):
                    out.add(y)
    if dob:
        # Accept YYYY-MM-DD, DD-MM-YYYY, etc.
        m = re.findall(r"(\d{2,4})", dob)
        # Common permutations: DDMMYYYY, MMYYYY, YYYY, YY
        digits = "".join(m)
        if len(digits) >= 8:
            out.add(digits[:8])
        for token in m:
            if len(token) in (2, 4):
                out.add(token)
    return sorted(out)

def build_bases(keywords: List[str], dob: str | None, separators: List[str]) -> Set[str]:
    bases: Set[str] = set()
    kws = [k for k in keywords if k]
    # Single keywords with case/leet variants
    for w in kws:
        for v in case_variants(w):
            bases.add(v)
    # Joins like first+last, first_last
    for sep in separators:
        for i in range(len(kws)):
            for j in range(i + 1, len(kws)):
                bases.add(kws[i] + sep + kws[j])
                bases.add(kws[j] + sep + kws[i])
    # DOB tokens directly
    if dob:
        tokens = re.findall(r"\d+", dob)
        bases.update(tokens)
    return bases

def generate_wordlist(
    keywords: List[str],
    dob: str | None,
    years: List[str],
    leet_mode: str,
    suffixes: List[str],
    separators: List[str],
    max_candidates: int = 20000,
) -> List[str]:
    out: Set[str] = set()
    bases = build_bases(keywords, dob, separators)

    # Leetspeak expansion
    aggressive = (leet_mode.lower() == "aggressive")
    expanded: Set[str] = set()
    for b in bases:
        expanded |= leet_variants(b, aggressive=aggressive, cap=12)
        if len(expanded) > max_candidates:
            break

    # Combine with years, suffixes, and separators
    def maybe_add(candidate: str):
        if 4 <= len(candidate) <= 64:
            out.add(candidate)

    # Plain bases
    for b in expanded:
        maybe_add(b)

    # base + year / year + base
    for b in list(expanded):
        for y in years:
            maybe_add(b + y)
            maybe_add(y + b)

    # base + suffix
    for b in list(expanded):
        for s in suffixes:
            maybe_add(b + s)

    # base + year + suffix
    for b in list(expanded):
        for y in years:
            for s in suffixes:
                maybe_add(b + y + s)

    # Limit size deterministically
    candidates = sorted(out, key=lambda x: (len(x), x))[:max_candidates]
    return candidates

# ----------------------------- CLI -----------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Password Strength Analyzer & Custom Wordlist Generator (Educational)"
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    # analyze
    p_an = sub.add_parser("analyze", help="Analyze password strength")
    p_an.add_argument("--password", required=True, help="Password to analyze")
    p_an.add_argument("--hints", nargs="*", default=[], help="User-specific hints (names, company, pet, etc.)")
    p_an.add_argument("--json", action="store_true", help="Output JSON")

    # generate
    p_ge = sub.add_parser("generate", help="Generate a custom wordlist")
    p_ge.add_argument("--keywords", default="", help="Comma/space separated keywords (name, nick, company, city)")
    p_ge.add_argument("--dob", default=None, help="Date of birth like 2002-08-09 or 09-08-2002")
    p_ge.add_argument("--years", default="2015-2026", help="Range like 2018-2025 or list like 20,21,2022")
    p_ge.add_argument("--leet", choices=["off", "basic", "aggressive"], default="basic")
    p_ge.add_argument("--suffixes", default="!,@,#,123,*", help="Comma-separated suffixes")
    p_ge.add_argument("--separators", default="_,-,.", help="Comma-separated separators for joining keywords")
    p_ge.add_argument("--max", type=int, default=20000, help="Max candidates to output")
    p_ge.add_argument("--outfile", required=True, help="Output file path (.txt)")

    # both (analyze + small list)
    p_bo = sub.add_parser("both", help="Analyze and generate a small contextual list")
    for a in p_an._actions[1:]:
        if a.dest != "json":
            p_bo.add_argument(f"--{a.dest}", **{k: v for k, v in a.__dict__.items() if k in ("required","help")})
    for a in p_ge._actions[1:]:
        if a.dest != "outfile":
            p_bo.add_argument(f"--{a.dest}", **{k: v for k, v in a.__dict__.items() if k in ("help","default","choices","type")})
    p_bo.add_argument("--outfile", required=True, help="Wordlist output file")

    args = parser.parse_args()

    if args.cmd == "analyze":
        res = analyze_password(args.password, user_inputs=args.hints)
        if args.json:
            print(json.dumps(res, indent=2))
        else:
            print(f"Engine: {res.get('engine')}")
            print(f"Score : {res.get('score')} (0=very weak … 4=very strong)")
            fb = res.get("feedback") or {}
            if "warning" in fb and fb["warning"]:
                print("Warning:", fb["warning"])
            if fb.get("suggestions"):
                print("Suggestions:")
                for s in fb["suggestions"]:
                    print(" -", s)
            ct = res.get("crack_times_display") or {}
            if ct:
                print("Crack Times (est.):")
                for k, v in ct.items():
                    print(f" - {k}: {v}")

    elif args.cmd in ("generate", "both"):
        # common params from generate
        keywords = tokenize_keywords(getattr(args, "keywords", ""))
        suffixes = tokenize_keywords(getattr(args, "suffixes", ""))
        separators = tokenize_keywords(getattr(args, "separators", ""))
        years = parse_years(getattr(args, "years", None), getattr(args, "dob", None))
        leet_mode = getattr(args, "leet", "basic")
        maxc = getattr(args, "max", 20000)

        wl = generate_wordlist(
            keywords=keywords,
            dob=getattr(args, "dob", None),
            years=years,
            leet_mode=leet_mode,
            suffixes=suffixes,
            separators=separators,
            max_candidates=maxc,
        )

        with open(args.outfile, "w", encoding="utf-8") as f:
            for line in wl:
                f.write(line + "\n")
        print(f"[+] Wrote {len(wl)} candidates to {args.outfile}")

        if args.cmd == "both":
            res = analyze_password(args.password, user_inputs=getattr(args, "hints", []))
            print("\nAnalysis summary:")
            print(json.dumps(res, indent=2))
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
