import re
import sys
from collections import Counter
from pathlib import Path
"""Scans a log file for failed login attempts and reports the most targeted accounts and IP addresses.
I wanted to make a short script project that might relate to NIST SP 800-171. It's not a full compliance tool
but it can help identify issues with failed login attempts."""
#flag any IP with 5 or more failed login
Threshold = 5
MAX_FILE_SIZE = 50_000_000
MAX_LINE_LENGTH = 2000
PATTERN = re.compile(r"Failed password for (?:invalid user )?(\S+) from (\S+)")

#can be used to clean up the output for better readability
def clean(text, limit=40):
    return "".join(ch for ch in text if ch.isprintable())[:limit]
#validate the path
def validate_path(arg):
    path = Path(arg)
    if not path.exists():
        raise ValueError("Path does not exist")
    if path.stat().st_size > MAX_FILE_SIZE:
        raise ValueError("File size exceeds maximum limit")
    return path
#scan the log file for failed login attempts
def scan(path):
    by_ip, by_user = Counter(), Counter()
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            if len(line) > MAX_LINE_LENGTH:
                continue
            match = PATTERN.search(line)
            if match:
                user, ip = match.groups()
                by_ip[ip] += 1
                by_user[user] += 1

    return by_ip, by_user
#catch any exceptions and print the report
def main():
    if len(sys.argv) != 2:
        print("Usage: python failedlogincheck.py <logfile>")
        return 1
    try:
        path = validate_path(sys.argv[1])
        by_ip, by_user = scan(path)
    except (ValueError, FileNotFoundError, PermissionError) as err:
        print(f"Error: {err}")
        return 1
    print("Failed Login Report")
    print("-" * 20)
    flagged = False
    for ip, count in by_ip.most_common():
        if count >= Threshold:
            flagged = True
            print(f"FLAGGED: IP {clean(ip)} had {count} failed login attempts")
    if not flagged:
        print("No IP addresses exceeded the threshold.")

    print("\nMost targeted accounts:")
    for user, count in by_user.most_common(3):
        print(f" {clean(user)}: {count}")
    return 0

if __name__ == "__main__":
    sys.exit(main())