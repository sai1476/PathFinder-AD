"""
Tests for schema validation, data models, and relationship consistency checks.
"""

import pytest
from app.models import parse_inventory_dict, ADInventory, ADUser, ADGroup, ADComputer, ADAce


def test_valid_schema_parsing():
    raw_data = {
        "domain": "LAB.LOCAL",
        "generated_at": "2026-10-01T00:00:00Z",
        "users": [
            {
                "sam_account_name": "alice",
                "distinguished_name": "CN=Alice,OU=Users,DC=lab,DC=local",
                "enabled": True,
                "admin_count": 0,
            }
        ],
        "groups": [
            {
                "sam_account_name": "Domain Admins",
                "distinguished_name": "CN=Domain Admins,CN=Users,DC=lab,DC=local",
                "is_privileged": True,
                "members": ["CN=Alice,OU=Users,DC=lab,DC=local"],
            }
        ],
        "computers": [],
        "acls": [],
    }

    inv, issues = parse_inventory_dict(raw_data)
    assert inv is not None
    assert inv.domain == "LAB.LOCAL"
    assert "alice" in inv.users
    assert "domain admins" in inv.groups
    # No warnings because Alice exists
    assert len(issues) == 0


def test_malformed_input_root_not_dict():
    inv, issues = parse_inventory_dict(["not a dict"])
    assert inv is None
    assert any(i.severity == "ERROR" and "root" in i.field_name for i in issues)


def test_missing_domain():
    inv, issues = parse_inventory_dict({"users": []})
    assert inv is not None
    assert inv.domain == "CORP.LOCAL"  # default fallback


def test_invalid_domain_type():
    inv, issues = parse_inventory_dict({"domain": ""})
    assert inv is None
    assert any(i.severity == "ERROR" and i.field_name == "domain" for i in issues)


def test_missing_or_inconsistent_relationships():
    raw_data = {
        "domain": "TEST.LOCAL",
        "users": [
            {
                "sam_account_name": "bob",
                "distinguished_name": "CN=Bob,DC=test,DC=local",
                "member_of": ["CN=GhostGroup,DC=test,DC=local"],
            }
        ],
        "groups": [
            {
                "sam_account_name": "OrphanGroup",
                "distinguished_name": "CN=OrphanGroup,DC=test,DC=local",
                "members": ["CN=NonExistentUser,DC=test,DC=local"],
            }
        ],
        "acls": [
            {
                "principal_name": "CN=FakeUser,DC=test,DC=local",
                "target_name": "CN=OrphanGroup,DC=test,DC=local",
                "right": "GenericAll",
            }
        ],
    }

    inv, issues = parse_inventory_dict(raw_data)
    assert inv is not None
    # Warnings should be reported for ghost group, non-existent member, and fake principal
    warnings = [i for i in issues if i.severity == "WARNING"]
    assert len(warnings) >= 3
    messages = " ".join([w.message for w in warnings])
    assert "GhostGroup" in messages
    assert "NonExistentUser" in messages
    assert "FakeUser" in messages
