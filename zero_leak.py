#!/usr/bin/env python3
import argparse
import base64
import binascii
import json
import math
import re
import subprocess
import sys
from datetime import datetime, timezone
from typing import List, NamedTuple, Tuple

# --- Detection Rules & Patterns ---
JWT_PATTERN = re.compile(r"\bey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*\b")
HEX_KEY_PATTERN = re.compile(r"(?i)\b(?:0x)?[a-f0-9]{64}\b")
EMAIL_PATTERN = re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")
DIFF_HUNK_PATTERN = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")


# --- Safe Email Domains ---
SAFE_EMAIL_DOMAINS = ("@example.com", "@test.com", "@mock.internal")


class Finding(NamedTuple):
    file_path: str
    line_number: int
    issue_type: str
    description: str
    remedy: str


def compute_shannon_entropy(data: str) -> float:
    """Calculates Shannon entropy for string randomness detection."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    for count in [data.count(c) for c in set(data)]:
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def inspect_jwt(token: str) -> Tuple[bool, str]:
    """Validates structure and decodes claims from ephemeral JWTs."""
    parts = token.split(".")
    if len(parts) < 2:
        return False, ""

    payload_segment = parts[1]
    remainder = len(payload_segment) % 4
    if remainder:
        payload_segment += "=" * (4 - remainder)

    try:
        raw_payload = base64.urlsafe_b64decode(payload_segment.encode("ascii"))
        claims = json.loads(raw_payload.decode("utf-8"))
    except (binascii.Error, UnicodeDecodeError, json.JSONDecodeError, ValueError):
        return False, ""

    if not isinstance(claims, dict):
        return False, ""

    details = []
    if "iss" in claims:
        details.append(f"iss={claims['iss']}")
    if "exp" in claims:
        try:
            exp_ts = int(claims["exp"])
            exp_str = datetime.fromtimestamp(exp_ts, tz=timezone.utc).isoformat()
            details.append(f"exp={exp_str}")
        except (ValueError, TypeError):
            pass

    detail_str = f" ({', '.join(details)})" if details else ""
    return True, f"Decodable JWT token found{detail_str}"


def scan_line(file_path: str, line_num: int, line_content: str) -> List[Finding]:
    """Applies privacy and credential heuristics to a single added diff line."""
    findings: List[Finding] = []

    # 1. Ephemeral JWT Leak
    for match in JWT_PATTERN.findall(line_content):
        is_jwt, desc = inspect_jwt(match)
        if is_jwt:
            findings.append(
                Finding(
                    file_path=file_path,
                    line_number=line_num,
                    issue_type="EPHEMERAL_JWT_LEAK",
                    description=desc,
                    remedy="Load tokens at runtime from local env files (.env.local excluded from git).",
                )
            )

    # 2. Raw Cryptographic Private Key / High-Entropy Seed
    for match in HEX_KEY_PATTERN.findall(line_content):
        clean_key = match[2:] if match.lower().startswith("0x") else match
        if compute_shannon_entropy(clean_key) >= 3.5:
            findings.append(
                Finding(
                    file_path=file_path,
                    line_number=line_num,
                    issue_type="RAW_PRIVATE_KEY_OR_SEED",
                    description="High-entropy 64-character hexadecimal string detected",
                    remedy="Externalize cryptographic keys to local vaults or system keychains.",
                )
            )

    # 3. Unhashed / Real PII Email
    for match in EMAIL_PATTERN.findall(line_content):
        if not match.lower().endswith(SAFE_EMAIL_DOMAINS):
            findings.append(
                Finding(
                    file_path=file_path,
                    line_number=line_num,
                    issue_type="UNSALTED_PII_EMAIL",
                    description=f"Plaintext external email detected: {match}",
                    remedy="Anonymize test fixtures using @example.com or deterministic SHA-256 hashes.",
                )
            )

    return findings


def get_staged_diff() -> str:
    """Retrieves staged unified git diff."""
    cmd = ["git", "diff", "--cached", "-U0", "--no-color"]
    result = subprocess.run(cmd, capture_output=True, text=True, check=True)
    return result.stdout


def main() -> int:
    parser = argparse.ArgumentParser(description="Privacy and ephemeral token linter for Git.")
    parser.add_argument("--hook", action="store_true", help="Pre-commit mode (exits with code 1 on findings)")
    args = parser.parse_args()

    try:
        raw_diff = get_staged_diff()
    except subprocess.CalledProcessError as err:
        sys.stderr.write(f"Git execution failed: {err}\n")
        return 1
    except FileNotFoundError:
        sys.stderr.write("Error: 'git' binary not found in PATH.\n")
        return 1

    current_file = ""
    current_line = 0
    findings: List[Finding] = []

    for line in raw_diff.splitlines():
        if line.startswith("+++ b/"):
            current_file = line[6:]
            continue
        if line.startswith("+++ /dev/null"):
            current_file = ""
            continue

        hunk_match = DIFF_HUNK_PATTERN.match(line)
        if hunk_match:
            current_line = int(hunk_match.group(1))
            continue

        if not current_file:
            continue

        if line.startswith("+") and not line.startswith("+++"):
            analyzed_line = line[1:]
            findings.extend(scan_line(current_file, current_line, analyzed_line))
            current_line += 1
        elif line.startswith(" "):
            current_line += 1

    if not findings:
        print("\033[32m✔ zero-leak: No privacy violations or ephemeral secrets detected.\033[0m")
        return 0

    print(f"\n\033[31m✖ zero-leak detected {len(findings)} issue(s):\033[0m\n")
    for f in findings:
        print(f"\033[1m{f.file_path}:{f.line_number}\033[0m [\033[33m{f.issue_type}\033[0m]")
        print(f"  Violation : {f.description}")
        print(f"  Remedy    : {f.remedy}\n")

    return 1 if args.hook else 0


if __name__ == "__main__":
    sys.exit(main())