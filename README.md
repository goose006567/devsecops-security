# DevSecOps — Security Scanning in the CI Pipeline

A shift-left security pipeline: every push/PR runs **SAST**, **secret
detection**, **dependency audit**, and **IaC security** scans. Four of the
tools run for real offline (they are local CLIs) — only the GitHub wiring is
deferred.

## The pipeline (`.github/workflows/security.yml`)

| Job    | Tool                                        | Finds                                   |
| ------ | ------------------------------------------- | --------------------------------------- |
| `sast` | **Bandit** (Python)                         | hardcoded creds, weak hashes, `shell=True` injection |
| `secrets` | **gitleaks** + offline regex scanner    | AWS keys, GitHub tokens, JWTs, private keys |
| `deps` | **pip-audit** + policy audit                | packages with known CVEs                 |
| `iac`  | **Checkov** (Terraform)                     | open 0.0.0.0/0 rules, unencrypted buckets |

`iac` emits SARIF for GitHub code scanning integration.

## Offline execution (everything runs locally)

```bash
python3.12 -m venv .venv
.venv/bin/pip install bandit checkov packaging
.venv/bin/python scripts/run_all.py            # optional: pass a dir path
```

Expected results on the (intentionally vulnerable) demo:

```
label              state
bandit             FAIL      2 High (MD5, shell=True) + 4 Low
secret scan        FAIL      AWS key + hardcoded password + GH token
dependency audit   FAIL      flask CVE-2018-1000656, requests CVE-2018-18074
checkov            pass*     13 passed / 10 failed (SSH open, S3 unencrypted)
```
`*` checkov runs with `--soft-fail` so the overall gate reflects your policy.

Each scanner exits non-zero on findings, the same gate used in CI.

## Scan targets (deliberately vulnerable, demo only)

- `app/demo_app.py` — hardcoded `AWS_SECRET_ACCESS_KEY`, `DATABASE_PASSWORD`,
  `GITHUB_TOKEN`; `hashlib.md5`; `subprocess.run(..., shell=True)`
- `app/requirements.txt` — pinned `Flask==0.12.2`, `requests==2.19.1` (both
  have published CVEs)
- `iac/main.tf` — `0.0.0.0/0` SSH ingress, unencrypted S3 bucket

Read the fix directions in the file comments — every finding is intentionally
fixable (`sha256`, `subprocess` arg-list, `server_side_encryption_configuration`,
`ingress` from a real CIDR).

## Cross-project punch line

`iac/main.tf` mirrors the patterns that made it into **Project 2's production
Terraform** (least-privilege chained SGs, no `0.0.0.0/0`); `app/` mirrors the
style of **Projects 3/4**. Run `run_all.py` in this repo and the pipeline
catches exactly the class of bug those projects were written to avoid.
