---
name: gitleaks-check
description: Passive secret-leak check. Scans a git repository (the case subject's repo) for committed secrets using gitleaks, with values redacted. Use when triaging an exposed-secret or repository issue to confirm or refute that secrets are present in source/history.
---

# gitleaks-check — passive secret scan

Scans a repository for committed secrets. **Passive and read-only**: it clones (or
reads a local clone) and runs `gitleaks`. It never validates secrets against live
services (that is an active check requiring approval) and never prints raw secret
values.

## Steps
1. Determine the target repo from the case subject (a `repo` URL or local path).
2. Get a read-only copy if needed (shallow clone into a temp dir):
   ```bash
   git clone --depth 50 <repo-url> /tmp/spellbook-scan-<id>
   ```
   If the subject is already a local path, scan it in place.
3. Run gitleaks **with redaction so secret values never enter output**:
   ```bash
   gitleaks detect --source /tmp/spellbook-scan-<id> --redact --report-format json --no-banner
   ```
   Add `--log-opts` to bound history if the repo is large.
4. Report structured findings: for each hit, the rule id, file path, commit, and line —
   **never the secret value** (gitleaks `--redact` masks it).

## Reporting
Summarize: number of findings, which rules fired, whether they appear in current files
vs only history, and your read on whether this confirms the Wiz issue. If `gitleaks` is
not installed, say so and stop — do not improvise a substitute that prints secrets.

Do not run validation tools (`trufflehog --only-verified`, `curl` to the provider, etc.)
here — those are active checks and belong to a separate, approval-gated step.
