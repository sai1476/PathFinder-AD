"""
Report generation module for PathFinder AD.
Exports security assessment results to JSON, Markdown, and Standalone HTML formats.
"""

from __future__ import annotations
import json
from datetime import datetime, timezone
from typing import Any, Dict, List

from app.models import ADInventory
from app.analyzer import Finding, RiskPath


class ReportGenerator:
    def __init__(self, inventory: ADInventory, findings: List[Finding], risk_paths: List[RiskPath]):
        self.inventory = inventory
        self.findings = findings
        self.risk_paths = risk_paths

    def get_summary_metrics(self) -> Dict[str, Any]:
        """Compute severity metrics and counts."""
        severity_counts = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "INFORMATIONAL": 0,
        }
        for f in self.findings:
            sev = f.severity.upper()
            if sev in severity_counts:
                severity_counts[sev] += 1
            else:
                severity_counts[sev] = 1

        object_type_counts = {}
        for f in self.findings:
            object_type_counts[f.object_type] = object_type_counts.get(f.object_type, 0) + 1

        return {
            "total_findings": len(self.findings),
            "severity_counts": severity_counts,
            "object_type_counts": object_type_counts,
            "total_users": len(self.inventory.users),
            "total_groups": len(self.inventory.groups),
            "total_computers": len(self.inventory.computers),
            "total_acls": len(self.inventory.acls),
            "total_paths": len(self.risk_paths),
            "validation_issues_count": len(self.inventory.issues),
        }

    def to_json(self) -> str:
        """Export comprehensive results as a JSON string."""
        summary = self.get_summary_metrics()

        payload = {
            "assessment_meta": {
                "tool": "PathFinder AD — Active Directory Security Assessment",
                "version": "1.0.0",
                "domain": self.inventory.domain,
                "dataset_timestamp": self.inventory.generated_at,
                "exported_at": datetime.now(timezone.utc).isoformat(),
            },
            "summary": summary,
            "validation_issues": [
                {
                    "severity": issue.severity,
                    "field": issue.field_name,
                    "message": issue.message,
                }
                for issue in self.inventory.issues
            ],
            "findings": [
                {
                    "id": f.id,
                    "rule_id": f.rule_id,
                    "title": f.title,
                    "severity": f.severity,
                    "affected_object": f.affected_object,
                    "object_type": f.object_type,
                    "evidence": f.evidence,
                    "explanation": f.explanation,
                    "remediation": f.remediation,
                    "references": f.references,
                }
                for f in self.findings
            ],
            "structural_risk_paths": [
                {
                    "path_id": p.path_id,
                    "source": p.source_identity,
                    "target": p.target_privileged_identity,
                    "length": p.length,
                    "steps": p.steps,
                    "explanation": p.explanation,
                    "disclaimer": p.disclaimer,
                }
                for p in self.risk_paths
            ],
        }

        return json.dumps(payload, indent=2)

    def to_markdown(self) -> str:
        """Export findings as an executive Markdown report."""
        summary = self.get_summary_metrics()
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        lines = [
            f"# PathFinder AD — Security Assessment Report",
            f"",
            f"**Target Domain:** `{self.inventory.domain}`  ",
            f"**Report Generated:** `{now_str}`  ",
            f"**Dataset Timestamp:** `{self.inventory.generated_at}`  ",
            f"",
            f"---",
            f"",
            f"## Executive Summary",
            f"",
            f"| Metric | Count |",
            f"| :--- | :--- |",
            f"| **Total Findings** | **{summary['total_findings']}** |",
            f"| Critical Severity | {summary['severity_counts']['CRITICAL']} |",
            f"| High Severity | {summary['severity_counts']['HIGH']} |",
            f"| Medium Severity | {summary['severity_counts']['MEDIUM']} |",
            f"| Low Severity | {summary['severity_counts']['LOW']} |",
            f"| Structural Risk Paths | {summary['total_paths']} |",
            f"| AD Users Analyzed | {summary['total_users']} |",
            f"| AD Groups Analyzed | {summary['total_groups']} |",
            f"| AD Computers Analyzed | {summary['total_computers']} |",
            f"| Explicit ACLs Evaluated | {summary['total_acls']} |",
            f"",
        ]

        if self.inventory.issues:
            lines.extend([
                f"### Inventory Consistency & Validation Notes",
                f"",
                f"> **Notice:** The sample inventory contains {len(self.inventory.issues)} relationship or schema consistency warnings.",
                f"",
            ])
            for issue in self.inventory.issues:
                lines.append(f"- **[{issue.severity}]** `{issue.field_name}`: {issue.message}")
            lines.append("")

        lines.extend([
            f"## Detailed Findings",
            f"",
        ])

        if not self.findings:
            lines.append("No security misconfigurations or rule violations were identified in this inventory.\n")
        else:
            for f in self.findings:
                lines.extend([
                    f"### [{f.severity}] {f.title} ({f.rule_id})",
                    f"",
                    f"- **Finding ID:** `{f.id}`",
                    f"- **Severity:** **{f.severity}**",
                    f"- **Affected Object:** `{f.affected_object}` ({f.object_type})",
                    f"",
                    f"#### Technical Explanation",
                    f"{f.explanation}",
                    f"",
                    f"#### Verified Evidence",
                    f"```json",
                    json.dumps(f.evidence, indent=2),
                    f"```",
                    f"",
                    f"#### Recommended Remediation",
                    f"{f.remediation}",
                    f"",
                ])
                if f.references:
                    lines.append(f"**References:**")
                    for ref in f.references:
                        lines.append(f"- [{ref}]({ref})")
                    lines.append("")
                lines.append("---\n")

        lines.extend([
            f"## Structural Risk Paths (Graph Relationship Analysis)",
            f"",
            f"> **Disclaimer:** The paths below represent structural relationship chains (group memberships and explicit permissions) identified in the synthetic inventory. They are hypothetical privilege pathways rather than confirmed exploits.",
            f"",
        ])

        if not self.risk_paths:
            lines.append("No structural paths from standard users to Tier-0 entities were found.\n")
        else:
            for p in self.risk_paths:
                chain_str = " ➔ ".join([f"`{s['from']}` ({s['right']})" for s in p.steps] + [f"`{p.target_privileged_identity}`"])
                lines.extend([
                    f"### Path {p.path_id}: `{p.source_identity}` ➔ `{p.target_privileged_identity}` ({p.length} hops)",
                    f"",
                    f"**Progression Chain:**",
                    f"{chain_str}",
                    f"",
                    f"**Detail:** {p.explanation}",
                    f"",
                ])

        return "\n".join(lines)

    def to_html(self) -> str:
        """Export as a self-contained, beautifully formatted HTML report."""
        summary = self.get_summary_metrics()
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        # Color badges mapping
        badge_classes = {
            "CRITICAL": "badge-critical",
            "HIGH": "badge-high",
            "MEDIUM": "badge-medium",
            "LOW": "badge-low",
            "INFORMATIONAL": "badge-info",
        }

        findings_html = []
        for f in self.findings:
            badge_class = badge_classes.get(f.severity.upper(), "badge-info")
            evidence_json = json.dumps(f.evidence, indent=2)
            refs_html = "".join([f'<li><a href="{r}" target="_blank" rel="noopener">{r}</a></li>' for r in f.references])

            findings_html.append(f"""
            <div class="finding-card">
                <div class="finding-header">
                    <div>
                        <span class="badge {badge_class}">{f.severity}</span>
                        <span class="rule-id">{f.rule_id}</span>
                        <span class="finding-id">#{f.id}</span>
                        <h3 class="finding-title">{f.title}</h3>
                    </div>
                </div>
                <div class="finding-body">
                    <p><strong>Affected Object:</strong> <code>{f.affected_object}</code> ({f.object_type})</p>
                    <div class="section-block">
                        <h4>Security Explanation</h4>
                        <p>{f.explanation}</p>
                    </div>
                    <div class="section-block">
                        <h4>Observed Evidence</h4>
                        <pre><code>{evidence_json}</code></pre>
                    </div>
                    <div class="section-block remediation-block">
                        <h4>Remediation Guidance</h4>
                        <p>{f.remediation}</p>
                    </div>
                    {"<div class='section-block'><h4>References</h4><ul>" + refs_html + "</ul></div>" if f.references else ""}
                </div>
            </div>
            """)

        paths_html = []
        for p in self.risk_paths:
            steps_items = []
            for s in p.steps:
                steps_items.append(f"""
                <span class="step-node">{s['from']}</span>
                <span class="step-edge">--[{s['right']}]--></span>
                """)
            steps_items.append(f"""<span class="step-node target-node">{p.target_privileged_identity}</span>""")

            paths_html.append(f"""
            <div class="path-card">
                <h4>Path {p.path_id}: {p.source_identity} &rarr; {p.target_privileged_identity} ({p.length} hops)</h4>
                <div class="path-visual">
                    {''.join(steps_items)}
                </div>
                <p class="path-desc">{p.explanation}</p>
                <div class="disclaimer"><em>{p.disclaimer}</em></div>
            </div>
            """)

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PathFinder AD Security Assessment - {self.inventory.domain}</title>
    <style>
        :root {{
            --bg: #0f172a;
            --surface: #1e293b;
            --surface-hover: #334155;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --border: #334155;
            --critical: #ef4444;
            --high: #f97316;
            --medium: #eab308;
            --low: #3b82f6;
            --info: #64748b;
            --success: #10b981;
            --accent: #6366f1;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg);
            color: var(--text-main);
            line-height: 1.5;
            padding: 2rem;
        }}
        .container {{ max-width: 1100px; margin: 0 auto; }}
        header {{
            border-bottom: 1px solid var(--border);
            padding-bottom: 1.5rem;
            margin-bottom: 2rem;
        }}
        h1 {{ font-size: 2rem; color: #fff; margin-bottom: 0.5rem; }}
        .meta {{ color: var(--text-muted); font-size: 0.95rem; }}
        .metrics-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 1rem;
            margin-bottom: 2.5rem;
        }}
        .metric-card {{
            background: var(--surface);
            padding: 1.25rem;
            border-radius: 8px;
            border: 1px solid var(--border);
            text-align: center;
        }}
        .metric-val {{ font-size: 2rem; font-weight: bold; margin-top: 0.25rem; }}
        .badge {{
            display: inline-block;
            padding: 0.25rem 0.6rem;
            border-radius: 4px;
            font-weight: 700;
            font-size: 0.8rem;
            text-transform: uppercase;
        }}
        .badge-critical {{ background: rgba(239, 68, 68, 0.2); color: #fca5a5; border: 1px solid var(--critical); }}
        .badge-high {{ background: rgba(249, 115, 22, 0.2); color: #fdba74; border: 1px solid var(--high); }}
        .badge-medium {{ background: rgba(234, 179, 8, 0.2); color: #fde047; border: 1px solid var(--medium); }}
        .badge-low {{ background: rgba(59, 130, 246, 0.2); color: #93c5fd; border: 1px solid var(--low); }}
        .badge-info {{ background: rgba(100, 116, 139, 0.2); color: #cbd5e1; border: 1px solid var(--info); }}
        .rule-id, .finding-id {{ color: var(--text-muted); font-size: 0.85rem; margin-left: 0.5rem; font-family: monospace; }}
        .finding-card {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
        }}
        .finding-title {{ margin-top: 0.5rem; font-size: 1.25rem; }}
        .finding-body {{ margin-top: 1rem; }}
        .section-block {{ margin-top: 1rem; }}
        .section-block h4 {{ font-size: 0.95rem; text-transform: uppercase; color: var(--text-muted); margin-bottom: 0.25rem; }}
        pre {{
            background: #090d16;
            padding: 0.75rem;
            border-radius: 6px;
            border: 1px solid var(--border);
            overflow-x: auto;
            font-size: 0.85rem;
        }}
        code {{ font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; }}
        .remediation-block {{
            background: rgba(16, 185, 129, 0.1);
            border-left: 4px solid var(--success);
            padding: 0.75rem 1rem;
            border-radius: 0 6px 6px 0;
        }}
        .path-card {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 1.25rem;
            margin-bottom: 1rem;
        }}
        .path-visual {{
            display: flex;
            align-items: center;
            flex-wrap: wrap;
            gap: 0.5rem;
            margin: 1rem 0;
            background: #090d16;
            padding: 0.75rem;
            border-radius: 6px;
            font-family: monospace;
            font-size: 0.9rem;
        }}
        .step-node {{ background: #334155; padding: 0.2rem 0.5rem; border-radius: 4px; }}
        .step-node.target-node {{ background: #991b1b; color: #fff; font-weight: bold; }}
        .step-edge {{ color: #fdba74; }}
        .disclaimer {{
            background: rgba(100, 116, 139, 0.15);
            padding: 0.5rem 0.75rem;
            border-left: 3px solid var(--info);
            font-size: 0.85rem;
            margin-top: 0.5rem;
        }}
        a {{ color: #818cf8; text-decoration: none; }}
        a:hover {{ text-decoration: underline; }}
        @media print {{
            body {{ background: #fff; color: #000; }}
            .finding-card, .metric-card, .path-card {{ border: 1px solid #ccc; background: #fff; color: #000; }}
            pre {{ background: #f4f4f4; border: 1px solid #ddd; color: #000; }}
            .step-visual {{ background: #eee; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>PathFinder AD — Security Assessment Report</h1>
            <div class="meta">
                Domain: <strong>{self.inventory.domain}</strong> | 
                Generated: <strong>{now_str}</strong> | 
                Dataset Timestamp: <strong>{self.inventory.generated_at}</strong>
            </div>
        </header>

        <section>
            <h2 style="margin-bottom: 1rem;">Assessment Overview</h2>
            <div class="metrics-grid">
                <div class="metric-card">
                    <div>Total Findings</div>
                    <div class="metric-val" style="color: var(--text-main);">{summary['total_findings']}</div>
                </div>
                <div class="metric-card">
                    <div>Critical Severity</div>
                    <div class="metric-val" style="color: var(--critical);">{summary['severity_counts']['CRITICAL']}</div>
                </div>
                <div class="metric-card">
                    <div>High Severity</div>
                    <div class="metric-val" style="color: var(--high);">{summary['severity_counts']['HIGH']}</div>
                </div>
                <div class="metric-card">
                    <div>Medium Severity</div>
                    <div class="metric-val" style="color: var(--medium);">{summary['severity_counts']['MEDIUM']}</div>
                </div>
                <div class="metric-card">
                    <div>Risk Paths</div>
                    <div class="metric-val" style="color: var(--accent);">{summary['total_paths']}</div>
                </div>
            </div>
        </section>

        <section style="margin-bottom: 3rem;">
            <h2 style="margin-bottom: 1.5rem;">Detailed Findings ({len(self.findings)})</h2>
            {''.join(findings_html) if findings_html else '<p>No findings identified.</p>'}
        </section>

        <section style="margin-bottom: 3rem;">
            <h2 style="margin-bottom: 1.5rem;">Structural Risk Paths ({len(self.risk_paths)})</h2>
            {''.join(paths_html) if paths_html else '<p>No structural paths from standard accounts to privileged nodes found.</p>'}
        </section>
    </div>
</body>
</html>
"""
        return html
