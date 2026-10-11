# AGY Security Review (`agysecurityreview`)

An adversarial multi-agent security vulnerability review and automated patch generation plugin and skill for **Antigravity (AGY)**.

---

## Overview

Standard AI coding assistants frequently hallucinate non-exploitable security issues or miss nuanced business-logic flaws. **AGY Security Review** eliminates false positives by simulating a real-world adversarial red-team/blue-team review panel:

1. **Target Determination & Scope Sizing**: Inspects git state, pending diffs, target commits, or full component trees.
2. **Multi-Lens Vulnerability Hunting**: Deploys specialized security researchers across 4 focused vulnerability lenses.
3. **3-Lens Adversarial Verification Panel**: Challenges every candidate finding against an independent verification gate requiring proven reachability, real impact, and absence of defenses.
4. **Multi-Format Output Generation**: Renders clean Markdown reports, standard SARIF 2.1.0 logs (compatible with GitHub Code Scanning & IDEs), and JSONL streams.
5. **Targeted Patch Generation**: Synthesizes surgical, unified `.patch` fixes that eliminate vulnerabilities without regressing existing functionality.

---

## Architecture & Verification Pipeline

```text
       ┌────────────────────────┐
       │     Repository /       │
       │    Uncommitted Diff    │
       └───────────┬────────────┘
                   │
                   ▼
       ┌────────────────────────┐
       │   Scope & Git Scan     │
       │     (scan_git.py)      │
       └───────────┬────────────┘
                   │
                   ▼
┌───────────────────────────────────────────────────┐
│     4 Specialized Security Hunting Lenses         │
│  - Injection & Input (SQLi, Command, Path, SSRF)  │
│  - Auth & Access (Bypass, IDOR/BOLA, Race Conds)  │
│  - Memory & Unsafe (Buffer overflow, Unsafe FFI)  │
│  - Crypto & Secrets (Hardcoded keys, Weak PRNG)   │
└──────────────────┬────────────────────────────────┘
                   │
                   ▼
┌───────────────────────────────────────────────────┐
│     3-Lens Adversarial Verification Panel         │
│   1. REACHABILITY: Can untrusted input reach sink?│
│   2. IMPACT: Does execution harm CIA triad?       │
│   3. DEFENSES: Are ORM/framework defenses absent? │
│                                                   │
│   Quorum Rule: Default = FALSE_POSITIVE           │
│   Must earn ≥ 2 TRUE_POSITIVE votes to survive    │
└──────────────────┬────────────────────────────────┘
                   │
                   ▼
┌───────────────────────────────────────────────────┐
│              Output Artifacts                     │
│  - SECURITY-REVIEW-RESULTS.md (Executive summary) │
│  - SECURITY-REVIEW-RESULTS.sarif (SARIF 2.1.0)    │
│  - SECURITY-REVIEW-RESULTS.jsonl (CI/CD streams)  │
│  - patches/SEC-*.patch (Verified surgical diffs)  │
└───────────────────────────────────────────────────┘
```

---

## 4 Core Security Lenses

- **Lens A: `injection-and-input`**: SQL/NoSQL injection, command/code injection, path traversal, XSS, template injection (SSTI), unsafe deserialization, XML entity expansion (XXE), and LLM prompt injection.
- **Lens B: `auth-and-access`**: Authentication bypass, broken object-level authorization (IDOR/BOLA), CSRF, SSRF, open redirect, and time-of-check to time-of-use (TOCTOU) race conditions.
- **Lens C: `memory-and-unsafe`**: Buffer overflows, out-of-bounds array access, use-after-free, integer overflow/underflow, and unsafe FFI or `unsafe` blocks.
- **Lens D: `crypto-and-secrets`**: Hardcoded API keys, tokens, credentials, weak hashing (MD5/SHA1), ECB encryption, hardcoded salts/IVs, and predictable RNGs (`math/rand`).

---

## Adversarial Verification Gate (Quorum Rule)

Every candidate finding must withstand 3 adversarial refutation tests:

1. **REACHABILITY**: Can an untrusted external attacker genuinely feed data that reaches this sink in a real deployment?
2. **IMPACT**: If triggered, does this actually harm confidentiality, integrity, or availability?
3. **DEFENSES**: Is there an existing safeguard (ORM parameterization, type guards, framework escaping)?

> **Quorum Standard**: Findings default to `FALSE_POSITIVE` and are confirmed **ONLY** with at least 2 `TRUE_POSITIVE` votes citing exact `file:line` proof for source, sink, and lack of mitigation.

---

## Repository Structure

```text
.
├── plugin.json                 # AGY Plugin manifest
├── gemini-extension.json       # Extension metadata
├── LICENSE                     # MIT License
├── README.md                   # Documentation
└── skills/
    └── security-review/
        ├── SKILL.md            # Skill workflow & instructions
        ├── agents/             # Multi-agent role definitions
        │   ├── security-researcher.md
        │   ├── security-verifier.md
        │   ├── patch-generator.md
        │   └── patch-verifier.md
        └── scripts/            # Scan & report rendering utilities
            ├── scan_git.py     # Git status & diff range inspector
            ├── render_report.py# Markdown, SARIF 2.1.0 & JSONL renderer
            └── lib/            # CWE mappings, SARIF schemas & validators
                ├── cwe-categories.json
                ├── cwe.py
                ├── finding.py
                ├── sarif.py
                └── ...
```

---

## Installation

### Option 1: Install as an AGY Plugin (Recommended)

Clone directly into your global Antigravity plugins directory:

```bash
mkdir -p ~/.gemini/config/plugins
git clone https://github.com/theajmalrazaq/agysecurityreview.git ~/.gemini/config/plugins/agysecurityreview
```

Or install it for a specific project workspace:

```bash
mkdir -p .agents/plugins
git clone https://github.com/theajmalrazaq/agysecurityreview.git .agents/plugins/agysecurityreview
```

### Option 2: Install as a Standalone AGY Skill

Copy or clone the skill directly into your skills directory:

```bash
mkdir -p ~/.gemini/config/skills
git clone https://github.com/theajmalrazaq/agysecurityreview.git /tmp/agysecurityreview
cp -r /tmp/agysecurityreview/skills/security-review ~/.gemini/config/skills/security-review
rm -rf /tmp/agysecurityreview
```

---

## Usage

### In Antigravity / AGY Chat

#### 1. Scan Scopes

| Scope | Command / Syntax | Description |
| :--- | :--- | :--- |
| **Branch / Diff Scan** *(Default)* | `/security-review` | Rapid, high-signal audit of uncommitted modifications or branch diff against base. |
| **Full Codebase Scan** | `/security-review --codebase` | Comprehensive multi-agent review across all application components, API routes, and queries. |
| **Commit Scan** | `/security-review --commit <sha>` | Audits a specific commit against its parent (`<sha>~1..<sha>`). |

#### 2. Natural Language Commands

You can also trigger specific scopes using natural language:
- *"Scan the entire codebase for security vulnerabilities"* (`--codebase`)
- *"Run a full repository security audit"*
- *"Review my uncommitted changes before commit"*
- *"Audit commit abc1234 for vulnerabilities"*

### Standalone CLI Execution

Inspect git scope:
```bash
python3 skills/security-review/scripts/scan_git.py
```

Render SARIF, Markdown, and JSONL reports from a findings JSON:
```bash
python3 skills/security-review/scripts/render_report.py \
  --findings /path/to/findings.json \
  --output-dir SECURITY-REVIEW-$(date +%Y%m%d-%H%M%S) \
  --scan-root .
```

---

## Output Artifacts

When an audit runs, a timestamped directory `SECURITY-REVIEW-<YYYYMMDD-HHMMSS>/` is created containing:

- `SECURITY-REVIEW-RESULTS.md`: Human-readable executive summary with vulnerability descriptions, exploit paths, code snippets, and remediation.
- `SECURITY-REVIEW-RESULTS.sarif`: Standard SARIF 2.1.0 output compatible with GitHub Code Scanning, SonarQube, and VS Code SARIF viewers.
- `SECURITY-REVIEW-RESULTS.jsonl`: Line-delimited JSON for CI/CD gates and automated security pipelines.
- `SECURITY-REVIEW-METADATA.json`: Audit stamp recording commit SHA, branch, and verification status.
- `patches/SEC-*.patch`: Ready-to-apply unified diff patches for confirmed issues.

---

## License

MIT © [Ajmal Razaq](https://github.com/theajmalrazaq)
