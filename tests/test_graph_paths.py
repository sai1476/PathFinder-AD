"""
Tests for graph construction and structural risk path discovery.
"""

from app.models import ADInventory, ADUser, ADGroup, ADAce
from app.analyzer import ADAnalyzer


def test_graph_path_discovery():
    inv = ADInventory(domain="CHAIN.LOCAL")

    # Bob (Contractor) -> MemberOf -> Contractors Group
    # Contractors Group -> GenericAll -> Helpdesk Group
    # Helpdesk Group -> WriteDacl -> Domain Admins Group
    bob = ADUser(
        sam_account_name="bob",
        distinguished_name="CN=Bob,DC=chain,DC=local",
        member_of=["CN=Contractors,DC=chain,DC=local"],
    )
    contractors = ADGroup(
        sam_account_name="Contractors",
        distinguished_name="CN=Contractors,DC=chain,DC=local",
        is_privileged=False,
    )
    helpdesk = ADGroup(
        sam_account_name="Helpdesk",
        distinguished_name="CN=Helpdesk,DC=chain,DC=local",
        is_privileged=False,
    )
    domain_admins = ADGroup(
        sam_account_name="Domain Admins",
        distinguished_name="CN=Domain Admins,DC=chain,DC=local",
        is_privileged=True,
    )

    inv.users["bob"] = bob
    inv.groups["contractors"] = contractors
    inv.groups["helpdesk"] = helpdesk
    inv.groups["domain admins"] = domain_admins

    inv.register_object(bob)
    inv.register_object(contractors)
    inv.register_object(helpdesk)
    inv.register_object(domain_admins)

    inv.acls.append(
        ADAce(
            principal_name="CN=Contractors,DC=chain,DC=local",
            target_name="CN=Helpdesk,DC=chain,DC=local",
            right="GenericAll",
        )
    )
    inv.acls.append(
        ADAce(
            principal_name="CN=Helpdesk,DC=chain,DC=local",
            target_name="CN=Domain Admins,DC=chain,DC=local",
            right="WriteDacl",
        )
    )

    analyzer = ADAnalyzer(inv)
    paths = analyzer.analyze_risk_paths()

    assert len(paths) >= 1
    p = paths[0]
    assert p.source_identity == "bob"
    assert p.target_privileged_identity == "Domain Admins"
    assert len(p.steps) == 3
    # Verify non-exploit disclaimer is populated
    assert "hypothetical" in p.disclaimer.lower() or "structural" in p.disclaimer.lower()
