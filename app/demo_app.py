"""DEMO ONLY — deliberately vulnerable sample for the security pipeline.
Never write code like this. Every finding below is intentional so the
scanners have something real to report.
"""
import hashlib
import json
import subprocess

# DEMO: hardcoded credential (AWS documented example key — not real)
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
DATABASE_PASSWORD = "hunter2!"  # DEMO: hardcoded password

GITHUB_TOKEN = "ghp_Q8vPnM3lKj2hGf5dS4aZx7cV6bN9mT0qW1eR8yU2i"  # placeholder


def hash_session(user):
    # weak hash — use hashlib.sha256 / pbkdf2 / bcrypt
    return hashlib.md5(user.encode()).hexdigest()


def run_cmd(raw):
    # shell=True is an injection risk — use shlex.split / subprocess.run list
    return subprocess.run(raw, shell=True)


def save_config(data):
    return json.dumps(data, indent=2)  # ok-ish, kept for context


def public_route_to(runtime):
    # naive exec of user-derived code — dangerous
    return runtime
