"""
Tests for report generation (JSON, Markdown, HTML).
"""

import json
from datetime import datetime, timezone
from app.models import ADInventory, ADUser
from app.analyzer import ADAnalyzer, Finding, RiskPath
from app.reporter import ReportGenerator


def test_reporter_exports():
    inv = ADInventory(domain="REPORT.LOCAL", generated_at="2026-10-01T00:00:00Z")
    user = ADUser(
        sam_account_name="test_user",
        distinguished_name="CN=Test,DC=report,DC=local",
    )
    inv.users["test_user"] = user

    finding = Finding(
        id="PF-FND-001",
        rule_id="PF-AD-001",
        title="Test Stale Account",
        severity="MEDIUM",
        affected_object="test_user (CN=Test,DC=report,DC=local)",
        object_type="User",
        evidence={"days_inactive": 120},
        explanation="Test explanation",
        remediation="Test remediation",
        references=["https://example.com/ad-doc"],
    )

    risk_path = RiskPath(
        path_id="PATH-001",
        source_identity="test_user",
        target_privileged_identity="Domain Admins",
        length=2,
        steps=[
            {"from": "test_user", "to": "Helpdesk", "relationship": "MemberOf", "right": "MemberOf"},
            {"from": "Helpdesk", "to": "Domain Admins", "relationship": "AccessControl", "right": "GenericAll"},
        ],
        explanation="Test path explanation",
        disclaimer="Test disclaimer",
    )

    rep = ReportGenerator(inv, [finding], [risk_path])

    # 1. JSON Export Test
    json_out = rep.to_json()
    parsed = json.loads(json_out)
    assert parsed["assessment_meta"]["domain"] == "REPORT.LOCAL"
    assert len(parsed["findings"]) == 1
    assert parsed["findings"][0]["id"] == "PF-FND-001"
    assert len(parsed["structural_risk_paths"]) == 1

    # 2. Markdown Export Test
    md_out = rep.to_markdown()
    assert "# PathFinder AD — Security Assessment Report" in md_out
    assert "`REPORT.LOCAL`" in md_out
    assert "### [MEDIUM] Test Stale Account (PF-AD-001)" in md_out
    assert "https://example.com/ad-doc" in md_out

    # 3. HTML Export Test
    html_out = rep.to_html()
    assert "<!DOCTYPE html>" in html_out
    assert "REPORT.LOCAL" in html_out
    assert "badge-medium" in html_out
    assert "Test Stale Account" in html_out
