"""Offline DevSecOps pipeline: runs every stage locally and prints a report.

Acts as the local twin of .github/workflows/security.yml. Stages that need a
pip-installed tool (bandit, checkov) auto-skip with a note if unavailable.
"""
import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

STAGES = []


def stage(name):
    print(f"\n{'='*60}\n[{name}]\n{'='*60}")
    STAGES.append(name)


def run(cmd, cwd=ROOT):
    print(f"  $ {' '.join(cmd)}")
    return subprocess.run(cmd, cwd=cwd)


def resolve(cmd):
    """Absolute path if only present in the venv bin (subprocess PATH)",
    otherwise the bare name (from PATH)."""
    return cmd if shutil.which(cmd) else os.path.join(os.path.dirname(sys.executable), cmd)


def has(cmd):
    """Find a tool on PATH or in the venv bin of the interpreter in use."""
    if shutil.which(cmd):
        return True
    return os.path.exists(os.path.join(os.path.dirname(sys.executable), cmd))


def main():
    target = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "app")
    results = {}

    stage("1. SAST — bandit (python)")
    if has("bandit"):
        r = run([resolve("bandit"), "-q", "-r", target])
        results["sast"] = r.returncode == 0
    else:
        print("  [skip] bandit not installed — install with: pip install bandit")
        results["sast"] = None

    stage("2. Secret scanning — secrets_scanner.py")
    r = run([sys.executable, f"{HERE}/secrets_scanner.py", target])
    results["secrets"] = r.returncode == 0

    stage("3. Dependency audit — advisory policy")
    r = run([sys.executable, f"{HERE}/dependency_audit.py"])
    results["deps"] = r.returncode == 0

    stage("4. IaC security — checkov (terraform)")
    iac_dir = os.path.join(ROOT, "iac")
    if has("checkov"):
        r = run([sys.executable, resolve("checkov"), "-d", iac_dir, "--soft-fail"])
        results["iac"] = r.returncode == 0
    else:
        print("  [skip] checkov not installed — install with: pip install checkov")
        results["iac"] = None

    print(f"\n{'='*60}\nSUMMARY\n{'='*60}")
    for k, v in results.items():
        label = {"sast": "bandit", "secrets": "secret scan",
                 "deps": "dependency audit", "iac": "checkov"}[k]
        state = "PASS" if v else ("FAIL" if v is False else "SKIPPED")
        print(f"  {label:<16} {state}")


if __name__ == "__main__":
    main()
