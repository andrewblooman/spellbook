# 🪄 Spellbook

![Spellbook banner](assets/image.png)

![Python](https://img.shields.io/badge/python-3.14%2B-3776AB?logo=python&logoColor=white)
![License](https://img.shields.io/github/license/andrewblooman/spellbook)
![Status](https://img.shields.io/badge/status-Milestone%200-6f42c1)

**Spellbook** triages cloud-security issues from [Wiz](https://www.wiz.io/) with an
evidence-backed, safety-gated AI agent. It opens a **case** for an issue, runs a
SOC-analyst agent (built on the [Claude Agent SDK](https://platform.claude.com/docs/en/agent-sdk/overview))
that drives validated **skills** through read-only checks, and renders a verifiable
evidence chain — while a deterministic safety layer blocks anything destructive or
out-of-scope before it can run.

> **Status: Milestone 0** — the runnable spine. `investigate` works end-to-end
> (interactive, steerable). The other verbs (`run`, `batch`, `show`, `export`,
> `replay`, `remediate`) are scaffolded and announce themselves as planned for later
> milestones. See [Roadmap](#roadmap).

---

## Why it's safe by construction

The model's instructions are *advisory*. Spellbook's guarantees are *enforced* by a
deterministic `PreToolUse` hook that classifies every tool call before it executes:

| Side effect | Examples | Interactive | Unattended |
|---|---|---|---|
| **passive** (read-only) | `gitleaks`, `git log`, `gh repo view`, Wiz read tools | ✅ allow | ✅ allow |
| **active-noninvasive** (reaches a live host) | `curl`, `trufflehog`, `nuclei` | ❓ ask you | ⛔ deny |
| **active-invasive** (state-changing) | `rm`, `terraform apply`, `aws s3 rm`, MCP `*_create/_update/_delete` | ⛔ deny | ⛔ deny |
| **out-of-scope host** (any network target not on the allowlist) | `curl https://evil.example` | ⛔ deny | ⛔ deny |

Every decision and every tool run is written to the case's `audit.log`. Untrusted input
(issue text, READMEs, commit messages) is treated as **data, never instructions**, and
secret values are redacted before they re-enter the model's context.

---

## Prerequisites

| Requirement | Why | Check |
|---|---|---|
| **Python ≥ 3.14** | the package runtime | `python3.14 --version` |
| **Claude Code CLI** | the Agent SDK drives it under the hood | `claude --version` |
| **Anthropic auth** | model access — `claude login` *or* `ANTHROPIC_API_KEY` | `claude login` |
| **Node.js + npx** | runs MCP servers (e.g. Wiz) | `node --version` |
| **gitleaks** | the passive secret-scan check | `gitleaks version` |
| **Wiz API creds** *(optional)* | live issue ingestion via the Wiz MCP server | see [Configuration](#configuration) |

The check binaries you need depend on which skills you run; Milestone 0 only needs
`gitleaks`. Install it from <https://github.com/gitleaks/gitleaks>.

---

## Install

```bash
git clone <this-repo> spellbook
cd spellbook

# editable install (recommended while developing)
pip install --user -e .

# verify
spellbook --help
```

This installs the `spellbook` console command. (Prefer a virtualenv:
`python3.14 -m venv .venv && source .venv/bin/activate && pip install -e .`.)

---

## Configuration

Spellbook reads everything sensitive from the environment — nothing is persisted into
case files.

```bash
# --- Anthropic (one of these) ---
claude login                       # interactive, recommended
# export ANTHROPIC_API_KEY=sk-...  # or an API key

# --- Wiz MCP (optional: enables live issue ingestion) ---
export WIZ_CLIENT_ID=...
export WIZ_CLIENT_SECRET=...
export WIZ_MCP_ISSUE_TOOL=get_issue   # override if the server's tool name differs
export WIZ_MCP_LIST_TOOL=list_issues  # tool used to pull the top-issues feed
# Or skip the exports: the launcher's "Authenticate to Wiz" action prompts for the
# client id/secret and validates them via an OAuth2 client-credentials exchange —
# kept in the session only, never written to disk. It auto-detects which Wiz IdP your
# tenant uses (Cognito auth.app.wiz.io / Auth0 auth.wiz.io). Force one if needed:
# export WIZ_TOKEN_URL=https://auth.wiz.io/oauth/token  WIZ_AUDIENCE=beyond-api

# --- Business-context sources (optional: read-only enrichment) ---
# Each is enabled only when its token is present. The agent reads them to establish
# ownership/intent behind an issue. Writes (create/update/comment) are gate-denied.
export GITHUB_PERSONAL_ACCESS_TOKEN=...   # repo ownership, README, recent commits
export NOTION_API_KEY=...                 # runbooks, accepted-risk docs
export LINEAR_API_KEY=...                 # is the issue already tracked / accepted?

# --- Scope allowlist (owned assets the agent may probe over the network) ---
# Comma-separated hosts / domains. Subdomains are matched automatically.
# The subject's own repo/host is always added to scope.
export SPELLBOOK_SCOPE="acme.com,github.com/acme"
```

Without Wiz creds you can still triage offline using `--subject-file` (below).

---

## Usage — step by step

### 1. (Offline) Describe the subject

If you don't have Wiz MCP creds wired up yet, hand Spellbook the issue subject as JSON.
A starter file ships as `sample_subject.json`:

```json
{
  "type": "exposed_secret",
  "resource": "github-repo",
  "repo": "https://github.com/acme/widget-api",
  "exposure": "AWS access key detected in commit history",
  "severity": "high"
}
```

### 2. Investigate

```bash
# numbered terminal menu
spellbook

# offline (subject from file)
spellbook investigate WIZ-12345 --subject-file sample_subject.json

# live (subject pulled from Wiz MCP — requires WIZ_* creds)
spellbook investigate WIZ-12345

# explicit launcher command
spellbook menu
```

This opens (or resumes) the case at `cases/WIZ-12345/`, then drops you into a
**steerable session**:

```
spellbook› <type a follow-up instruction to redirect the agent>
spellbook› /interrupt     # stop a runaway step
spellbook› /quit          # end the session
```

The agent invokes the `soc-analyst` skill, runs passive checks (e.g. `gitleaks-check`),
and summarizes a true-positive / false-positive / needs-investigation assessment. If it
wants to run an *active* check, it will pause and ask you to approve — and it can only
target hosts on your scope allowlist.

Running `spellbook` with no arguments in an interactive terminal now opens a
numbered terminal launcher. Direct subcommands still work unchanged.

### 2b. Settings & top issues

The launcher is a small workbench. On startup, if Wiz is configured and auto-fetch
is on, it pulls your **top issues** (via the agent + Wiz MCP), caches them, and lists
them so you can press a number to open a case with that issue already loaded as the
subject — you start triaging immediately, in context.

```
Spellbook
Top Wiz issues (high+, 5):
  1. WIZ-12345  CRITICAL  Exposed AWS key — github-repo acme/widget-api
  2. WIZ-12346  HIGH      Public S3 bucket — s3 acme-prod-logs
  ...
Actions:
  f. Investigate from subject file     c. Chat with the analyst AI
  w. Investigate by Wiz issue id       r. Refresh top issues
  e. Collect evidence manually         s. Settings
                                       a. Authenticate to Wiz   h. Help   q. Quit
```

- **A `spellbook` banner** greets you when the launcher opens.
- **`a` Authenticate to Wiz** — prompts for client id/secret and validates them with an
  OAuth2 client-credentials exchange (auto-detecting your tenant's Cognito/Auth0 endpoint).
  Session-only; nothing is written to disk.
- **`e` Collect evidence manually** — run a deterministic check (gitleaks, redacted)
  directly on a local repo and append the raw output to a case as evidence — no agent in
  the loop.
- **`c` Chat with the analyst AI** — a free-form, safety-gated chat (also `spellbook chat`)
  for reasoning and suggested lines of investigation, not pinned to a specific case.
- **`s` Settings** — how many issues to pull (1–10), the minimum severity
  (`CRITICAL`/`HIGH`/`MEDIUM`), and whether to auto-fetch on startup. Preferences persist
  to `~/.config/spellbook/settings.json`; the cached feed lives at
  `~/.cache/spellbook/top_issues.json` (issue metadata only — never credentials).
- **`r` Refresh** — re-pull the feed now. Otherwise a fresh cache (≤ 1h, same settings)
  is reused. `spellbook settings` edits the same preferences from the command line.

### 3. Inspect the case

Everything is written to a self-contained case directory:

```
cases/WIZ-12345/
├── case.json        # subject, evidence chain, (later) verdict
├── audit.log        # every gate decision + tool run, timestamped
└── evidence/        # raw tool output (secrets redacted)
    └── E001.txt
```

```bash
spellbook show WIZ-12345        # subject + evidence chain + verdict, rendered
cat cases/WIZ-12345/audit.log   # or read the raw audit trail
```

After a session you're offered to **record a verdict** (confirmed / refuted /
inconclusive + rationale); you can also set one directly:

```bash
spellbook verdict WIZ-12345 --status confirmed --rationale "E001, E003 confirm the leak"
```

Example audit trail:

```
2026-06-19T19:43:24Z   RAN        Bash   passive   'gitleaks detect --source /tmp/x --redact'
2026-06-19T19:43:24Z   GATE DENY  Bash   target not on owned-asset allowlist   'gh api https://evil.example.org'
```

---

## Can it run as a standalone binary?

**Not as a single self-contained executable** — and that's a property of the
architecture, not a missing feature:

- The Agent SDK shells out to the **Claude Code CLI** (a Node program), and
- MCP servers (Wiz, etc.) are launched via **`npx`**, and
- the **check tools** (`gitleaks`, …) are separate binaries the agent invokes.

A bundler like PyInstaller/`shiv`/`pex` can package the *Python* side into one file, but
it can't bundle Node, the `claude` CLI, or the check binaries — those must exist on the
host regardless. So the supported distribution models are:

| Model | How | Best for |
|---|---|---|
| **pip package** *(current)* | `pip install -e .` / `pip install spellbook` | developers, CI |
| **pipx / uv tool** | `pipx install .` — isolated venv, `spellbook` on PATH globally | end users on a workstation |
| **Container image** *(recommended for "standalone")* | a Docker image bundling Python + Node + `claude` CLI + check tools + Spellbook | the closest thing to a portable, reproducible single artifact |
| **Zipapp** | `shiv -c spellbook -o spellbook.pyz .` then `./spellbook.pyz` | one-file Python distribution *when* Node/CLI/tools are already present on the host |

If you want true "one artifact" portability, build a container — it's the only model
that captures all of Spellbook's runtime dependencies in one place.

---

## How it fits together

```
spellbook [menu]                       # cli.py callback → menu.py launcher (interactive TTY)
   └─ investigate WIZ-12345            # or invoked directly
        │
        ├─ case/store.py     open/resume cases/WIZ-12345/
        ├─ mcp/servers.py    Wiz MCP (issue ingestion)            ─┐
        ├─ agent/options.py  build ClaudeAgentOptions              │  Claude Agent SDK
        │     ├─ skills from .claude/skills/ (soc-analyst, …)      │  session
        │     ├─ PreToolUse  → safety/classify + safety/scope  ←───┤  (every tool call
        │     └─ PostToolUse → evidence + audit + redaction        │   passes the gate)
        └─ agent/session.py  interactive ClaudeSDKClient loop     ─┘
```

- **Skills** live in `.claude/skills/` and are loaded from the filesystem
  (`setting_sources=["user","project"]`). Add a check by dropping a new `SKILL.md` in —
  the safety gate governs whatever tools it tries to use.
- **The safety layer** (`spellbook/safety/`) is the real IP: `classify_bash`,
  `classify_mcp`, and the owned-asset `in_scope` allowlist.
- **The entrypoint** (`spellbook/cli.py`) opens the numbered launcher (`spellbook/menu.py`)
  when run with no subcommand in an interactive terminal; in a pipe/non-TTY it prints help.
  All subcommands remain directly invokable.

---

## Development

```bash
pip install --user -e .
python3.14 -m pytest tests/ -q        # safety gate, classifier, CLI routing + menu (no API needed)
```

The safety classifier, `PreToolUse` gate, CLI routing, and menu launcher are fully
unit-tested offline — you can verify the security boundary and the entrypoint behaviour
without spending any model calls.

---

## Roadmap

- **Milestone 0** *(done)* — runnable spine: `investigate`, safety gate, evidence + audit.
- **Milestone 1** — structured-output **Verdict**; more passive checks (source-correlation,
  dependency, passive-surface); `case show` / `export`.
- **Milestone 2** — active checks behind approval (secret validation, safe nuclei
  templates); hard scope enforcement.
- **Milestone 3** — `run --auto` / `batch` over a Wiz query; `remediate` to draft
  PRs/tickets after review.

---

## Security notes

- **Read-only by design.** Spellbook never performs state-changing actions; remediation
  drafting is a separate, explicit, human-invoked step (Milestone 3).
- **Credentials** come from the environment and are never written to case files.
- **Secrets** are redacted at the evidence boundary (`gitleaks --redact` at the source;
  regex redaction of MCP output) so they don't re-enter the model context.
- **Untrusted input** (issue/repo text) is data, not instructions — enforced by the hook
  layer, not just the prompt.
