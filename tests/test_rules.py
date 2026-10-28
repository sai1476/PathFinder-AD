"""
Unit tests for Active Directory security detection rules.
"""

from datetime import datetime, timezone
import pytest

from app.models import ADInventory, ADUser, ADGroup, ADComputer, ADAce, parse_inventory_dict
from app.analyzer import ADAnalyzer


@pytest.fixture
def base_inventory():
    return ADInventory(domain="TEST.LOCAL", generated_at="2026-10-01T00:00:00Z")


def test_rule_stale_accounts(base_inventory):
    # User inactive for > 100 days
    user1 = ADUser(
        sam_account_name="stale_user",
        distinguished_name="CN=Stale,DC=test,DC=local",
        enabled=True,
        last_logon_timestamp="2026-05-01T00:00:00Z",
    )
    # User disabled, inactive for > 200 days (should NOT trigger finding)
    user2 = ADUser(
        sam_account_name="disabled_user",
        distinguished_name="CN=Disabled,DC=test,DC=local",
        enabled=False,
        last_logon_timestamp="2025-01-01T00:00:00Z",
    )
    # User with no timestamp (should NOT trigger false positive or crash)
    user3 = ADUser(
        sam_account_name="no_ts_user",
        distinguished_name="CN=NoTS,DC=test,DC=local",
        enabled=True,
        last_logon_timestamp=None,
    )
    # Active user (logged on 2 days ago)
    user4 = ADUser(
        sam_account_name="active_user",
        distinguished_name="CN=Active,DC=test,DC=local",
        enabled=True,
        last_logon_timestamp="2026-09-29T00:00:00Z",
    )

    for u in [user1, user2, user3, user4]:
        base_inventory.users[u.sam_account_name] = u
        base_inventory.register_object(u)

    ref_date = datetime(2026, 10, 1, tzinfo=timezone.utc)
    analyzer = ADAnalyzer(base_inventory, reference_date=ref_date)
    analyzer.check_stale_accounts(inactivity_days_threshold=90)

    stale_findings = [f for f in analyzer.findings if f.rule_id == "PF-AD-001"]
    assert len(stale_findings) == 1
    assert "stale_user" in stale_findings[0].affected_object
    assert stale_findings[0].severity == "MEDIUM"


def test_rule_privileged_spn(base_inventory):
    # Privileged account with SPN
    admin_svc = ADUser(
        sam_account_name="admin_svc",
        distinguished_name="CN=AdminSvc,DC=test,DC=local",
        enabled=True,
        admin_count=1,
        spn=["MSSQLSvc/db01.test.local:1433"],
    )
    # Non-privileged account with SPN (Kerberoastable, but standard service account, not PF-AD-002)
    std_svc = ADUser(
        sam_account_name="web_svc",
        distinguished_name="CN=WebSvc,DC=test,DC=local",
        enabled=True,
        admin_count=0,
        spn=["HTTP/web01.test.local"],
    )

    base_inventory.users["admin_svc"] = admin_svc
    base_inventory.users["web_svc"] = std_svc
    base_inventory.register_object(admin_svc)
    base_inventory.register_object(std_svc)

    analyzer = ADAnalyzer(base_inventory)
    analyzer.check_privileged_spns()

    findings = [f for f in analyzer.findings if f.rule_id == "PF-AD-002"]
    assert len(findings) == 1
    assert "admin_svc" in findings[0].affected_object
    assert findings[0].severity == "CRITICAL"


def test_rule_asrep_roastable(base_inventory):
    user = ADUser(
        sam_account_name="asrep_target",
        distinguished_name="CN=AsrepTarget,DC=test,DC=local",
        enabled=True,
        user_account_control=["NORMAL_ACCOUNT", "DONT_REQ_PREAUTH"],
    )
    base_inventory.users["asrep_target"] = user
    base_inventory.register_object(user)

    analyzer = ADAnalyzer(base_inventory)
    analyzer.check_asrep_roastable()

    findings = [f for f in analyzer.findings if f.rule_id == "PF-AD-003"]
    assert len(findings) == 1
    assert "asrep_target" in findings[0].affected_object
    assert findings[0].severity == "HIGH"


def test_rule_insecure_password_flags(base_inventory):
    u1 = ADUser(
        sam_account_name="nopass_user",
        distinguished_name="CN=NoPass,DC=test,DC=local",
        user_account_control=["PASSWD_NOTREQD"],
    )
    u2 = ADUser(
        sam_account_name="cleartext_user",
        distinguished_name="CN=Cleartext,DC=test,DC=local",
        user_account_control=["ENCRYPTED_TEXT_PWD_ALLOWED"],
    )
    base_inventory.users["nopass_user"] = u1
    base_inventory.users["cleartext_user"] = u2
    base_inventory.register_object(u1)
    base_inventory.register_object(u2)

    analyzer = ADAnalyzer(base_inventory)
    analyzer.check_insecure_password_flags()

    rule_ids = {f.rule_id for f in analyzer.findings}
    assert "PF-AD-004A" in rule_ids
    assert "PF-AD-004B" in rule_ids


def test_rule_unconstrained_delegation(base_inventory):
    # Non-DC with unconstrained delegation
    app_server = ADComputer(
        sam_account_name="APP01$",
        distinguished_name="CN=APP01,DC=test,DC=local",
        is_domain_controller=False,
        delegation_type="Unconstrained",
        user_account_control=["TRUSTED_FOR_DELEGATION"],
    )
    # DC with unconstrained delegation (normal domain controller behavior)
    dc01 = ADComputer(
        sam_account_name="DC01$",
        distinguished_name="CN=DC01,DC=test,DC=local",
        is_domain_controller=True,
        delegation_type="Unconstrained",
        user_account_control=["TRUSTED_FOR_DELEGATION", "SERVER_TRUST_ACCOUNT"],
    )

    base_inventory.computers["app01$"] = app_server
    base_inventory.computers["dc01$"] = dc01
    base_inventory.register_object(app_server)
    base_inventory.register_object(dc01)

    analyzer = ADAnalyzer(base_inventory)
    analyzer.check_unconstrained_delegation()

    findings = [f for f in analyzer.findings if f.rule_id == "PF-AD-005"]
    assert len(findings) == 1
    assert "APP01$" in findings[0].affected_object
    assert findings[0].severity == "CRITICAL"


def test_rule_excessive_acls(base_inventory):
    da_group = ADGroup(
        sam_account_name="Domain Admins",
        distinguished_name="CN=Domain Admins,CN=Users,DC=test,DC=local",
        is_privileged=True,
    )
    helpdesk = ADGroup(
        sam_account_name="Helpdesk",
        distinguished_name="CN=Helpdesk,OU=Groups,DC=test,DC=local",
        is_privileged=False,
    )
    ace = ADAce(
        principal_name="CN=Helpdesk,OU=Groups,DC=test,DC=local",
        target_name="CN=Domain Admins,CN=Users,DC=test,DC=local",
        right="WriteDacl",
    )

    base_inventory.groups["domain admins"] = da_group
    base_inventory.groups["helpdesk"] = helpdesk
    base_inventory.register_object(da_group)
    base_inventory.register_object(helpdesk)
    base_inventory.acls.append(ace)

    analyzer = ADAnalyzer(base_inventory)
    analyzer.check_excessive_acls()

    findings = [f for f in analyzer.findings if f.rule_id == "PF-AD-006"]
    assert len(findings) == 1
    assert findings[0].severity == "CRITICAL"


def test_rule_nested_group_in_tier0(base_inventory):
    da_group = ADGroup(
        sam_account_name="Domain Admins",
        distinguished_name="CN=Domain Admins,CN=Users,DC=test,DC=local",
        is_privileged=True,
        members=["CN=Junior Admins,OU=Groups,DC=test,DC=local"],
    )
    jr_group = ADGroup(
        sam_account_name="Junior Admins",
        distinguished_name="CN=Junior Admins,OU=Groups,DC=test,DC=local",
        is_privileged=False,
    )

    base_inventory.groups["domain admins"] = da_group
    base_inventory.groups["junior admins"] = jr_group
    base_inventory.register_object(da_group)
    base_inventory.register_object(jr_group)

    analyzer = ADAnalyzer(base_inventory)
    analyzer.check_privileged_group_nesting()

    findings = [f for f in analyzer.findings if f.rule_id == "PF-AD-007"]
    assert len(findings) == 1
    assert "Junior Admins" in findings[0].title


def test_benign_baseline_produces_zero_findings():
    import json
    from pathlib import Path

    sample_path = Path(__file__).resolve().parent.parent / "data" / "benign_baseline.json"
    with open(sample_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    inv, issues = parse_inventory_dict(data)
    assert inv is not None
    assert len(issues) == 0

    ref_date = datetime(2026, 10, 1, tzinfo=timezone.utc)
    analyzer = ADAnalyzer(inv, reference_date=ref_date)
    findings = analyzer.run_all_checks()

    # The hardened benign baseline must not trigger misconfiguration findings
    assert len(findings) == 0
    assert len(analyzer.risk_paths) == 0
