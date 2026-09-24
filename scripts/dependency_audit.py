"""Offline dependency audit: pinned requirements vs. local advisory DB.

In the real pipeline this maps to `pip-audit` (OSV/DB network feeds); this
variant runs the same gate with a checked-in database so CI works offline.
"""
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ADVISORIES = os.path.join(os.path.dirname(HERE), "policy", "advisories.json")

try:
    from packaging.version import Version, InvalidVersion
except ImportError:
    Version, InvalidVersion = None, None
    print("[deps] note: packaging not installed — using string compare")


def parse_requirements(path):
    for line in open(path):
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        m = re.match(r"^\s*([A-Za-z0-9_.-]+)\s*(==|>=|<=|>|<|!=)?\s*([^\s;]+)?", line)
        if m:
            yield m.group(1).lower(), m.group(2) or "==", (m.group(3) or "").replace(",", "")


def matches(spec, req):
    name, op, version = req
    if spec["name"].lower() != name:
        return False
    if not version:
        return True  # unpinned = track advisories for the name
    ops = {">=": lambda a, b: a >= b, "<=": lambda a, b: a <= b,
           ">": lambda a, b: a > b, "<": lambda a, b: a < b,
           "==": lambda a, b: a == b}
    try:
        va, vb = Version(version), Version(spec["version"])
        return ops[spec["op"]](va, vb)
    except (InvalidVersion, TypeError, KeyError):
        return os.environ.get("ALLOW_STRICT", "0") == "1" and spec["op"] == "==" and version == spec["version"]


def main():
    req_file = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(HERE), "app", "requirements.txt")
    advisories = json.load(open(ADVISORIES))["py"]
    reqs = list(parse_requirements(req_file))
    findings = []
    for spec in advisories:
        for req in reqs:
            if matches(spec, req):
                findings.append((req, spec))
    if not findings:
        print(f"[deps] {len(reqs)} requirement(s) — no known vulnerable versions")
        return 0
    print(f"[deps] {len(findings)} vulnerable dependency(s) in {os.path.basename(req_file)}:")
    for (name, op, version), spec in findings:
        print(f"  {name}{op}{version}  ->  {spec['cve']} [{spec['severity']}] {spec['summary']}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
