#!/usr/bin/env python3
"""Render Security Review results into Markdown, SARIF 2.1.0, and JSONL formats."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

# Add lib directory to path
sys.path.insert(0, str(Path(__file__).resolve().parent / "lib"))
try:
    import cwe
except ImportError:
    cwe = None

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
SARIF_LEVEL_MAP = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
}


def build_sarif(findings: list[dict], scan_root: str, meta: dict) -> dict:
    rules = []
    rule_ids = set()
    results = []

    for f in findings:
        cwe_id = f.get("cwe_id") or f.get("cweId") or "CWE-699"
        if cwe_id not in rule_ids:
            rule_ids.add(cwe_id)
            desc = f.get("title", "Security Vulnerability")
            rules.append({
                "id": cwe_id,
                "name": cwe_id.replace("-", "_"),
                "shortDescription": {"text": desc},
                "fullDescription": {"text": f.get("description") or f.get("rationale") or desc},
                "helpUri": f"https://cwe.mitre.org/data/definitions/{cwe_id.replace('CWE-', '')}.html",
                "properties": {
                    "tags": ["security", "vulnerability"]
                }
            })

        severity = f.get("severity", "MEDIUM").upper()
        level = SARIF_LEVEL_MAP.get(severity, "warning")
        file_path = f.get("file", "unknown")
        line = int(f.get("line", 1))

        results.append({
            "ruleId": cwe_id,
            "level": level,
            "message": {
                "text": f"{f.get('title', 'Vulnerability')}: {f.get('description') or f.get('rationale') or ''}"
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": file_path,
                            "uriBaseId": "%SRCROOT%"
                        },
                        "region": {
                            "startLine": line,
                            "startColumn": 1,
                            "snippet": {
                                "text": f.get("snippet", "")
                            }
                        }
                    }
                }
            ],
            "properties": {
                "severity": severity,
                "confidence": f.get("confidence", "HIGH"),
                "exploitScenario": f.get("exploit_scenario") or f.get("exploitScenario", ""),
                "recommendation": f.get("recommendation", "")
            }
        })

    return {
        "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Antigravity Security Review",
                        "informationUri": "https://antigravity.google",
                        "version": "1.0.0",
                        "rules": rules
                    }
                },
                "results": results
            }
        ]
    }


def build_markdown_report(findings: list[dict], meta: dict) -> str:
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        sev = f.get("severity", "MEDIUM").upper()
        if sev in counts:
            counts[sev] += 1

    lines = [
        "# Security Vulnerability Review Report",
        "",
        f"**Generated:** {timestamp}  ",
        f"**Target:** `{meta.get('target', 'Codebase / Diff')}`  ",
        f"**Commit:** `{meta.get('commit_sha', 'HEAD')[:10] if meta.get('commit_sha') else 'N/A'}`  ",
        f"**Branch:** `{meta.get('branch', 'N/A')}`  ",
        f"**Verification Status:** Verified (Adversarial Panel Quorum)",
        "",
        "## Executive Summary",
        "",
        "| Severity | Count |",
        "| :--- | :---: |",
        f"| 🔴 **CRITICAL** | {counts['CRITICAL']} |",
        f"| 🟠 **HIGH** | {counts['HIGH']} |",
        f"| 🟡 **MEDIUM** | {counts['MEDIUM']} |",
        f"| 🔵 **LOW** | {counts['LOW']} |",
        f"| **Total Verified** | **{len(findings)}** |",
        "",
    ]

    if not findings:
        lines.extend([
            "### Result: Clean Scan",
            "",
            "No verifiable vulnerabilities were found in the reviewed scope after adversarial challenge.",
            "All candidate issues either lacked a viable attack path, were already mitigated by existing defenses, or fell below exploitability thresholds.",
            "",
            "> [!NOTE]",
            "> Security scans are non-deterministic and complement static analysis, fuzzing, and manual penetration testing.",
        ])
        return "\n".join(lines)

    lines.append("## Confirmed Findings")
    lines.append("")

    for idx, f in enumerate(findings, 1):
        fid = f.get("id", f"SEC-{idx:02d}")
        title = f.get("title", "Untitled Vulnerability")
        sev = f.get("severity", "MEDIUM").upper()
        conf = f.get("confidence", "HIGH").upper()
        cwe_id = f.get("cwe_id") or f.get("cweId") or "CWE-699"
        file_path = f.get("file", "unknown")
        line_num = f.get("line", 1)
        snippet = f.get("snippet", "").strip()
        desc = f.get("description") or f.get("rationale") or ""
        exploit = f.get("exploit_scenario") or f.get("exploitScenario") or ""
        precond = f.get("preconditions") or []
        rec = f.get("recommendation", "")

        sev_badge = {
            "CRITICAL": "🔴 CRITICAL",
            "HIGH": "🟠 HIGH",
            "MEDIUM": "🟡 MEDIUM",
            "LOW": "🔵 LOW",
        }.get(sev, sev)

        lines.extend([
            f"### [{fid}] {title}",
            "",
            f"- **Severity:** {sev_badge}",
            f"- **Confidence:** {conf}",
            f"- **Weakness:** [{cwe_id}](https://cwe.mitre.org/data/definitions/{cwe_id.replace('CWE-', '')}.html)",
            f"- **Location:** `{file_path}:{line_num}`",
            "",
            f"**Description:**",
            f"{desc}",
            "",
        ])

        if snippet:
            lines.extend([
                "**Vulnerable Sink Snippet:**",
                "```",
                f"{snippet}",
                "```",
                "",
            ])

        if exploit:
            lines.extend([
                "**Exploit Scenario & Attack Path:**",
                f"{exploit}",
                "",
            ])

        if precond:
            precond_str = "\n".join(f"- {p}" for p in precond) if isinstance(precond, list) else f"- {precond}"
            lines.extend([
                "**Preconditions:**",
                f"{precond_str}",
                "",
            ])

        if rec:
            lines.extend([
                "**Remediation Guidance:**",
                f"{rec}",
                "",
            ])

        lines.append("---")
        lines.append("")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Render security review reports")
    parser.add_argument("--findings", required=True, help="Path to findings JSON file")
    parser.add_argument("--meta", default="{}", help="JSON metadata string or path")
    parser.add_argument("--output-dir", required=True, help="Output directory")
    parser.add_argument("--scan-root", default=".", help="Scan root directory")
    args = parser.parse_args()

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    with open(args.findings, "r", encoding="utf-8") as f:
        findings = json.load(f)

    meta = {}
    if args.meta:
        if os.path.exists(args.meta):
            with open(args.meta, "r", encoding="utf-8") as f:
                meta = json.load(f)
        else:
            try:
                meta = json.loads(args.meta)
            except Exception:
                meta = {}

    # Sort findings by severity
    findings.sort(
        key=lambda x: (
            -SEVERITY_ORDER.get(x.get("severity", "MEDIUM").upper(), 0),
            x.get("file", ""),
            x.get("line", 0)
        )
    )

    # 1. Write Markdown Report
    md_content = build_markdown_report(findings, meta)
    md_path = output_dir / "SECURITY-REVIEW-RESULTS.md"
    md_path.write_text(md_content, encoding="utf-8")

    # 2. Write SARIF 2.1.0
    sarif_data = build_sarif(findings, args.scan_root, meta)
    sarif_path = output_dir / "SECURITY-REVIEW-RESULTS.sarif"
    with open(sarif_path, "w", encoding="utf-8") as f:
        json.dump(sarif_data, f, indent=2)

    # 3. Write JSONL
    jsonl_path = output_dir / "SECURITY-REVIEW-RESULTS.jsonl"
    with open(jsonl_path, "w", encoding="utf-8") as f:
        for item in findings:
            f.write(json.dumps(item) + "\n")

    # 4. Write Metadata Stamp
    meta_stamp = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "scan_root": str(Path(args.scan_root).resolve()),
        "findings_count": len(findings),
        "severities": {
            "critical": sum(1 for x in findings if x.get("severity", "").upper() == "CRITICAL"),
            "high": sum(1 for x in findings if x.get("severity", "").upper() == "HIGH"),
            "medium": sum(1 for x in findings if x.get("severity", "").upper() == "MEDIUM"),
            "low": sum(1 for x in findings if x.get("severity", "").upper() == "LOW"),
        },
        "meta": meta,
        "verification": {
            "status": "verified",
            "panel": "adversarial-quorum"
        }
    }
    stamp_path = output_dir / "SECURITY-REVIEW-METADATA.json"
    with open(stamp_path, "w", encoding="utf-8") as f:
        json.dump(meta_stamp, f, indent=2)

    # 5. Write local .gitignore so security artifacts don't accidentally get committed
    gitignore_path = output_dir / ".gitignore"
    if not gitignore_path.exists():
        gitignore_path.write_text("*\n", encoding="utf-8")

    print(f"Successfully rendered {len(findings)} findings into {output_dir}")
    print(f"  - Markdown: {md_path}")
    print(f"  - SARIF:    {sarif_path}")
    print(f"  - JSONL:    {jsonl_path}")
    print(f"  - Metadata: {stamp_path}")


if __name__ == "__main__":
    main()
