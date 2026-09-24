"""Secret scanning without any dependencies (offline CI-safe).

Patterns modeled on gitleaks default rules; exits 1 if a secret is found so it
can gate a pipeline exactly like `gitleaks detect --exit-code 1`.
"""
import os
import re
import sys

RULES = [
    ("aws-access-key", r"\bAKIA[0-9A-Z]{16}\b"),
    ("aws-secret-key", r"(?i)\baws_secret.{0,30}?([A-Za-z0-9/+=]{40})\b"),
    ("github-token", r"\bghp_[A-Za-z0-9]{36}\b"),
    ("jwt", r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    ("private-key", r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    ("hardcoded-password", r"(?i)(password|passwd|pwd)\s*[:=]\s*[\"'][^\s\"']+[\"']"),
]

SKIP = {".git", "__pycache__", ".venv", "node_modules", ".terraform", "policy"}
SKIP_EXT = {".png", ".jpg", ".jpeg", ".gif", ".pdf", ".pyc"}


def walk(root):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP]
        for fn in filenames:
            if os.path.splitext(fn)[1] in SKIP_EXT:
                continue
            yield os.path.join(dirpath, fn)


def scan(roots, context=80):
    findings = []
    for root in roots:
        for path in walk(root):
            try:
                with open(path, "r", errors="replace") as fh:
                    for lineno, line in enumerate(fh, 1):
                        for rule, pattern in RULES:
                            for m in re.finditer(pattern, line):
                                lo = max(0, m.start() - context)
                                snippet = line[m.start():m.end()]
                                findings.append(
                                    (rule, path, lineno, snippet + ("..." if m.end() < len(line) else "")))
            except (OSError, ValueError):
                continue
    return findings


def main():
    roots = sys.argv[1:] or ["."]
    findings = scan(roots)
    if not findings:
        print("[secrets] clean — no secrets found")
        return 0
    print(f"[secrets] {len(findings)} finding(s):")
    for rule, path, lineno, snippet in findings:
        print(f"  {rule:<18} {path}:{lineno}  {snippet}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
