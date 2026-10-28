"""
Security Analysis Engine for PathFinder AD.
Implements evidence-backed detection rules, graph-based privilege relationship analysis,
and structured findings with remediations.
"""

from __future__ import annotations
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

import networkx as nx

from app.models import ADInventory, ADUser, ADGroup, ADComputer, ADAce, normalize_identifier


CRITICAL_PERMISSIONS: Set[str] = {
    "GENERICALL",
    "WRITEDACL",
    "WRITEOWNER",
    "ALLPREFIDENTIAL",
    "ALL",
}

ELEVATED_PERMISSIONS: Set[str] = {
    "GENERICWRITE",
    "RESETPASSWORD",
    "WRITEPROPERTY",
    "EXTENDEDRIGHT",
}


@dataclass
class Finding:
    id: str
    rule_id: str
    title: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL
    affected_object: str
    object_type: str  # User, Group, Computer, ACL, Relationship
    evidence: Dict[str, Any]
    explanation: str
    remediation: str
    references: List[str] = field(default_factory=list)


@dataclass
class RiskPath:
    path_id: str
    source_identity: str
    target_privileged_identity: str
    length: int
    steps: List[Dict[str, str]]
    explanation: str
    disclaimer: str


class ADAnalyzer:
    def __init__(self, inventory: ADInventory, reference_date: Optional[datetime] = None):
        self.inventory: ADInventory = inventory
        self.reference_date: datetime = reference_date or datetime.now(timezone.utc)
        self.findings: List[Finding] = []
        self.risk_paths: List[RiskPath] = []
        self._finding_counter: int = 1

    def _next_finding_id(self) -> str:
        fid = f"PF-FND-{self._finding_counter:03d}"
        self._finding_counter += 1
        return fid

    def run_all_checks(self) -> List[Finding]:
        """Execute all implemented detection rules."""
        self.findings.clear()
        self._finding_counter = 1

        self.check_stale_accounts()
        self.check_privileged_spns()
        self.check_asrep_roastable()
        self.check_insecure_password_flags()
        self.check_unconstrained_delegation()
        self.check_excessive_acls()
        self.check_privileged_group_nesting()
        self.analyze_risk_paths()

        return self.findings

    def check_stale_accounts(self, inactivity_days_threshold: int = 90) -> None:
        """
        Rule PF-AD-001: Stale or Inactive Enabled Accounts.
        Limits: Only evaluates accounts where enabled=True and last_logon_timestamp is provided.
        """
        for user in self.inventory.users.values():
            if not user.enabled:
                continue

            parsed_logon = user.parsed_last_logon
            if not parsed_logon:
                # Do not guess or fabricate if timestamp is absent
                continue

            days_inactive = (self.reference_date - parsed_logon).days
            if days_inactive >= inactivity_days_threshold:
                is_priv = user.is_privileged_flag or any(
                    self.inventory.is_privileged_group(g) for g in user.member_of
                )
                severity = "HIGH" if is_priv else "MEDIUM"

                self.findings.append(
                    Finding(
                        id=self._next_finding_id(),
                        rule_id="PF-AD-001",
                        title=f"Stale Enabled Account: {user.sam_account_name} ({days_inactive} days inactive)",
                        severity=severity,
                        affected_object=f"{user.sam_account_name} ({user.distinguished_name})",
                        object_type="User",
                        evidence={
                            "sam_account_name": user.sam_account_name,
                            "distinguished_name": user.distinguished_name,
                            "enabled": user.enabled,
                            "last_logon_timestamp": user.last_logon_timestamp,
                            "days_inactive": days_inactive,
                            "inactivity_threshold": inactivity_days_threshold,
                            "is_privileged": is_priv,
                        },
                        explanation=(
                            f"Account '{user.sam_account_name}' is enabled but has had no authenticated logon "
                            f"for {days_inactive} days (exceeding policy threshold of {inactivity_days_threshold} days). "
                            "Dormant enabled accounts expand attack surface, violate least-privilege lifecycles, and are "
                            "frequent targets for covert persistence."
                        ),
                        remediation=(
                            f"Disable or decommission account '{user.sam_account_name}' if no longer required. "
                            "Enforce an automated account deprovisioning workflow for accounts inactive beyond 90 days."
                        ),
                        references=[
                            "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/monitoring-active-directory-for-signs-of-compromise"
                        ],
                    )
                )

    def check_privileged_spns(self) -> None:
        """
        Rule PF-AD-002: Privileged Account with ServicePrincipalName (Kerberoasting Risk).
        Limits: Evaluates enabled accounts with admin_count > 0 or in privileged groups holding an SPN.
        """
        for user in self.inventory.users.values():
            if not user.enabled or not user.spn:
                continue

            is_priv = user.is_privileged_flag or any(
                self.inventory.is_privileged_group(g) for g in user.member_of
            )
            if is_priv:
                self.findings.append(
                    Finding(
                        id=self._next_finding_id(),
                        rule_id="PF-AD-002",
                        title=f"Kerberoastable Privileged Account: {user.sam_account_name}",
                        severity="CRITICAL",
                        affected_object=f"{user.sam_account_name} ({user.distinguished_name})",
                        object_type="User",
                        evidence={
                            "sam_account_name": user.sam_account_name,
                            "distinguished_name": user.distinguished_name,
                            "admin_count": user.admin_count,
                            "spn_list": user.spn,
                            "member_of": user.member_of,
                        },
                        explanation=(
                            f"The privileged account '{user.sam_account_name}' has one or more ServicePrincipalNames (SPNs) registered: "
                            f"{', '.join(user.spn)}. Any valid domain authenticated user can request a Kerberos TGS ticket "
                            "for this service and attempt offline password cracking (Kerberoasting) against administrative credentials."
                        ),
                        remediation=(
                            "Decouple interactive administrative accounts from service registrations. "
                            "Migrate the service to a Group Managed Service Account (gMSA) with automated 128-character password rotation."
                        ),
                        references=[
                            "https://adsecurity.org/?p=3458",
                            "https://learn.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/group-managed-service-accounts-overview",
                        ],
                    )
                )

    def check_asrep_roastable(self) -> None:
        """
        Rule PF-AD-003: Pre-Authentication Disabled (AS-REP Roasting Risk).
        Limits: Evaluates enabled user accounts with DONT_REQ_PREAUTH flag set.
        """
        for user in self.inventory.users.values():
            if not user.enabled or not user.is_asrep_roastable:
                continue

            is_priv = user.is_privileged_flag or any(
                self.inventory.is_privileged_group(g) for g in user.member_of
            )
            severity = "CRITICAL" if is_priv else "HIGH"

            self.findings.append(
                Finding(
                    id=self._next_finding_id(),
                    rule_id="PF-AD-003",
                    title=f"AS-REP Roastable Account: {user.sam_account_name}",
                    severity=severity,
                    affected_object=f"{user.sam_account_name} ({user.distinguished_name})",
                    object_type="User",
                    evidence={
                        "sam_account_name": user.sam_account_name,
                        "distinguished_name": user.distinguished_name,
                        "user_account_control": user.user_account_control,
                        "is_privileged": is_priv,
                    },
                    explanation=(
                        f"Account '{user.sam_account_name}' has Kerberos pre-authentication disabled ('DONT_REQ_PREAUTH'). "
                        "An unauthenticated attacker can request an AS-REP ticket encrypted with the user's password hash and "
                        "conduct offline hash cracking."
                    ),
                    remediation=(
                        f"Enable Kerberos pre-authentication for '{user.sam_account_name}' by unchecking 'Do not require Kerberos preauthentication' "
                        "in Active Directory Users and Computers (ADUC), and enforce a strong password."
                    ),
                    references=[
                        "https://attack.mitre.org/techniques/T1558/004/",
                    ],
                )
            )

    def check_insecure_password_flags(self) -> None:
        """
        Rule PF-AD-004: Insecure Password Configuration Flags (PASSWD_NOTREQD / Reversible Encryption).
        Limits: Evaluates UAC flags explicitly set on accounts.
        """
        for user in self.inventory.users.values():
            if not user.enabled:
                continue

            if user.has_password_not_required:
                self.findings.append(
                    Finding(
                        id=self._next_finding_id(),
                        rule_id="PF-AD-004A",
                        title=f"Password Not Required Flag Enabled: {user.sam_account_name}",
                        severity="HIGH",
                        affected_object=f"{user.sam_account_name} ({user.distinguished_name})",
                        object_type="User",
                        evidence={
                            "sam_account_name": user.sam_account_name,
                            "user_account_control": user.user_account_control,
                        },
                        explanation=(
                            f"Account '{user.sam_account_name}' has the 'PASSWD_NOTREQD' flag set in userAccountControl. "
                            "This permits blank or null passwords to be configured, bypassing standard domain password complexity policies."
                        ),
                        remediation=(
                            f"Remove 'PASSWD_NOTREQD' from '{user.sam_account_name}' userAccountControl attribute and require immediate password reset."
                        ),
                        references=["https://attack.mitre.org/techniques/T1201/"],
                    )
                )

            if user.has_reversible_encryption:
                self.findings.append(
                    Finding(
                        id=self._next_finding_id(),
                        rule_id="PF-AD-004B",
                        title=f"Reversible Encryption Stored Password: {user.sam_account_name}",
                        severity="CRITICAL",
                        affected_object=f"{user.sam_account_name} ({user.distinguished_name})",
                        object_type="User",
                        evidence={
                            "sam_account_name": user.sam_account_name,
                            "user_account_control": user.user_account_control,
                        },
                        explanation=(
                            f"Account '{user.sam_account_name}' stores password using reversible encryption ('ENCRYPTED_TEXT_PWD_ALLOWED'). "
                            "This is equivalent to cleartext password storage in the Active Directory database."
                        ),
                        remediation=(
                            f"Disable 'Store password using reversible encryption' on '{user.sam_account_name}' and force a password change immediately."
                        ),
                        references=["https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption"],
                    )
                )

    def check_unconstrained_delegation(self) -> None:
        """
        Rule PF-AD-005: Unconstrained Kerberos Delegation on Non-Domain Controller.
        Limits: Evaluates enabled computer objects with TRUSTED_FOR_DELEGATION that are not domain controllers.
        """
        for comp in self.inventory.computers.values():
            if not comp.enabled:
                continue

            if comp.is_unconstrained_delegation and not comp.is_domain_controller:
                self.findings.append(
                    Finding(
                        id=self._next_finding_id(),
                        rule_id="PF-AD-005",
                        title=f"Unconstrained Delegation on Member Server: {comp.sam_account_name}",
                        severity="CRITICAL",
                        affected_object=f"{comp.sam_account_name} ({comp.distinguished_name})",
                        object_type="Computer",
                        evidence={
                            "sam_account_name": comp.sam_account_name,
                            "operating_system": comp.operating_system,
                            "is_domain_controller": comp.is_domain_controller,
                            "delegation_type": comp.delegation_type,
                            "user_account_control": comp.user_account_control,
                        },
                        explanation=(
                            f"Computer '{comp.sam_account_name}' is configured with Unconstrained Kerberos Delegation but is not a Domain Controller. "
                            "If a high-privilege account authenticates to any service on this host, the user's Ticket Granting Ticket (TGT) "
                            "is cached in memory, permitting an attacker on this machine to extract the TGT and impersonate the administrator domain-wide."
                        ),
                        remediation=(
                            "Reconfigure the computer to use Constrained Delegation (S4U2Proxy) or Resource-Based Constrained Delegation (RBCD). "
                            "Ensure privileged accounts are placed in the 'Protected Users' group or marked 'Account is sensitive and cannot be delegated'."
                        ),
                        references=[
                            "https://attack.mitre.org/techniques/T1558/001/",
                            "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/jj553400(v=ws.11)",
                        ],
                    )
                )

    def check_excessive_acls(self) -> None:
        """
        Rule PF-AD-006: Dangerous / Excessive ACLs on Sensitive Objects.
        Limits: Evaluates explicit ACEs targeting Tier-0 groups or privileged objects.
        """
        for ace in self.inventory.acls:
            target_obj = self.inventory.find_object(ace.target_name)
            target_is_priv = False

            if isinstance(target_obj, ADGroup) and target_obj.is_privileged:
                target_is_priv = True
            elif isinstance(target_obj, ADUser) and (target_obj.is_privileged_flag or any(self.inventory.is_privileged_group(g) for g in target_obj.member_of)):
                target_is_priv = True
            elif self.inventory.is_privileged_group(ace.target_name):
                target_is_priv = True

            if not target_is_priv:
                continue

            # If target is privileged, check who has rights over it
            principal_obj = self.inventory.find_object(ace.principal_name)
            principal_is_priv = False
            if isinstance(principal_obj, ADGroup) and principal_obj.is_privileged:
                principal_is_priv = True
            elif isinstance(principal_obj, ADUser) and principal_obj.is_privileged_flag:
                principal_is_priv = True

            # If the principal is already a recognized domain admin/privileged group, skip self-ownership
            if principal_is_priv:
                continue

            right_norm = ace.right.strip().upper()
            is_critical = right_norm in CRITICAL_PERMISSIONS
            is_elevated = right_norm in ELEVATED_PERMISSIONS

            if is_critical or is_elevated:
                severity = "CRITICAL" if is_critical else "HIGH"
                self.findings.append(
                    Finding(
                        id=self._next_finding_id(),
                        rule_id="PF-AD-006",
                        title=f"Excessive Permission: '{ace.right}' granted to '{ace.principal_name}' over '{ace.target_name}'",
                        severity=severity,
                        affected_object=f"{ace.target_name}",
                        object_type="ACL",
                        evidence={
                            "principal": ace.principal_name,
                            "target": ace.target_name,
                            "right": ace.right,
                            "is_inherited": ace.is_inherited,
                        },
                        explanation=(
                            f"Non-privileged entity '{ace.principal_name}' possesses explicit '{ace.right}' permission "
                            f"over privileged target '{ace.target_name}'. An identity with {ace.right} can directly modify group "
                            "membership, reset administrative passwords, or rewrite the Access Control List (DACL), leading to full domain compromise."
                        ),
                        remediation=(
                            f"Review and remove the explicit ACE granting '{ace.right}' to '{ace.principal_name}' on '{ace.target_name}'. "
                            "Ensure AdminSDHolder and SDProp protections are functioning properly."
                        ),
                        references=[
                            "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory",
                        ],
                    )
                )

    def check_privileged_group_nesting(self) -> None:
        """
        Rule PF-AD-007: Weakly Controlled Group Nesting to Tier-0.
        Limits: Evaluates group memberships where non-standard or external groups are nested into privileged groups.
        """
        for grp in self.inventory.groups.values():
            if not grp.is_privileged:
                continue

            for member_ref in grp.members:
                member_obj = self.inventory.find_object(member_ref)
                if isinstance(member_obj, ADGroup) and not member_obj.is_privileged:
                    self.findings.append(
                        Finding(
                            id=self._next_finding_id(),
                            rule_id="PF-AD-007",
                            title=f"Nested Non-Privileged Group in Tier-0: {member_obj.sam_account_name} -> {grp.sam_account_name}",
                            severity="HIGH",
                            affected_object=f"{grp.sam_account_name}",
                            object_type="Group",
                            evidence={
                                "parent_group": grp.sam_account_name,
                                "nested_member_group": member_obj.sam_account_name,
                                "nested_distinguished_name": member_obj.distinguished_name,
                            },
                            explanation=(
                                f"Non-privileged group '{member_obj.sam_account_name}' is nested directly into privileged group '{grp.sam_account_name}'. "
                                "Any user added to the nested group indirectly inherits administrative privileges, bypassing direct Tier-0 membership audits."
                            ),
                            remediation=(
                                f"Remove group '{member_obj.sam_account_name}' from '{grp.sam_account_name}'. "
                                "Maintain strict separation between Tier-0 administrative groups and operational or delegated groups."
                            ),
                            references=[
                                "https://learn.microsoft.com/en-us/security/privileged-access-workstations/privileged-access-access-model",
                            ],
                        )
                    )

    def build_relationship_graph(self) -> nx.DiGraph:
        """Build directed graph of AD objects, memberships, and explicit permissions."""
        G = nx.DiGraph()

        # Add all nodes
        for u in self.inventory.users.values():
            G.add_node(u.sam_account_name, label=u.sam_account_name, type="User", dn=u.distinguished_name, is_privileged=u.is_privileged_flag)
        for g in self.inventory.groups.values():
            G.add_node(g.sam_account_name, label=g.sam_account_name, type="Group", dn=g.distinguished_name, is_privileged=g.is_privileged)
        for c in self.inventory.computers.values():
            G.add_node(c.sam_account_name, label=c.sam_account_name, type="Computer", dn=c.distinguished_name, is_privileged=c.is_domain_controller)

        # Add edges from user/computer/group member_of
        all_objects = list(self.inventory.users.values()) + list(self.inventory.computers.values()) + list(self.inventory.groups.values())
        for obj in all_objects:
            source_sam = obj.sam_account_name
            for group_ref in obj.member_of:
                target_obj = self.inventory.find_object(group_ref)
                if target_obj:
                    G.add_edge(source_sam, target_obj.sam_account_name, relation="MemberOf", right="MemberOf")

        # Add edges from group members
        for grp in self.inventory.groups.values():
            target_sam = grp.sam_account_name
            for member_ref in grp.members:
                src_obj = self.inventory.find_object(member_ref)
                if src_obj:
                    G.add_edge(src_obj.sam_account_name, target_sam, relation="MemberOf", right="MemberOf")

        # Add edges from ACLs
        for ace in self.inventory.acls:
            src_obj = self.inventory.find_object(ace.principal_name)
            tgt_obj = self.inventory.find_object(ace.target_name)
            src_name = src_obj.sam_account_name if src_obj else ace.principal_name
            tgt_name = tgt_obj.sam_account_name if tgt_obj else ace.target_name

            if not G.has_node(src_name):
                G.add_node(src_name, label=src_name, type="Principal", dn="", is_privileged=False)
            if not G.has_node(tgt_name):
                G.add_node(tgt_name, label=tgt_name, type="Target", dn="", is_privileged=False)

            G.add_edge(src_name, tgt_name, relation="AccessControl", right=ace.right)

        return G

    def analyze_risk_paths(self) -> List[RiskPath]:
        """
        Identifies structural paths from non-privileged identities to Tier-0 / privileged targets.
        Clearly notes that these are hypothetical permission chains.
        """
        self.risk_paths.clear()
        G = self.build_relationship_graph()

        # Identify Tier-0 / privileged target nodes
        privileged_nodes = [
            n for n, data in G.nodes(data=True)
            if data.get("is_privileged") or self.inventory.is_privileged_group(n)
        ]

        # Identify non-privileged starting nodes (standard users)
        standard_user_nodes = [
            n for n, data in G.nodes(data=True)
            if data.get("type") == "User" and not data.get("is_privileged") and not self.inventory.is_privileged_group(n)
        ]

        found_path_keys = set()
        path_idx = 1

        for src in standard_user_nodes:
            for tgt in privileged_nodes:
                if src == tgt:
                    continue
                if nx.has_path(G, src, tgt):
                    try:
                        shortest_path = nx.shortest_path(G, src, tgt)
                        if len(shortest_path) >= 2:
                            path_key = "->".join(shortest_path)
                            if path_key in found_path_keys:
                                continue
                            found_path_keys.add(path_key)

                            steps: List[Dict[str, str]] = []
                            for i in range(len(shortest_path) - 1):
                                u = shortest_path[i]
                                v = shortest_path[i + 1]
                                edge_data = G.get_edge_data(u, v) or {}
                                steps.append({
                                    "from": u,
                                    "to": v,
                                    "relationship": edge_data.get("relation", "LinkedTo"),
                                    "right": edge_data.get("right", "MemberOf"),
                                })

                            rp = RiskPath(
                                path_id=f"PATH-{path_idx:03d}",
                                source_identity=src,
                                target_privileged_identity=tgt,
                                length=len(steps),
                                steps=steps,
                                explanation=(
                                    f"Structural permission path discovered from non-privileged identity '{src}' "
                                    f"to privileged entity '{tgt}' over {len(steps)} hops."
                                ),
                                disclaimer=(
                                    "Note: This is a structural analysis based on synthetic inventory relationships. "
                                    "It illustrates potential privilege progression based on group memberships and permissions; "
                                    "it does not confirm an active or exploitable vulnerability."
                                ),
                            )
                            self.risk_paths.append(rp)
                            path_idx += 1
                    except nx.NetworkXNoPath:
                        continue

        return self.risk_paths
