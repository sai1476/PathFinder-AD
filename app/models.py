"""
Data models and schema validation for Active Directory synthetic inventories.
Handles parsing, normalization, reference consistency checks, and schema validation.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple, Set


PRIVILEGED_GROUP_NAMES: Set[str] = {
    "DOMAIN ADMINS",
    "ENTERPRISE ADMINS",
    "SCHEMA ADMINS",
    "ADMINISTRATORS",
    "ACCOUNT OPERATORS",
    "BACKUP OPERATORS",
    "SERVER OPERATORS",
    "PRINT OPERATORS",
    "GROUP POLICY CREATOR OWNERS",
    "CRYPTOGRAPHIC OPERATORS",
}


def normalize_identifier(identifier: str) -> str:
    """Normalize object names or DNs for case-insensitive lookup."""
    return identifier.strip().lower() if identifier else ""


def parse_iso_datetime(value: Optional[str]) -> Optional[datetime]:
    """Safely parse an ISO-8601 datetime string."""
    if not value or not isinstance(value, str):
        return None
    try:
        # Handle 'Z' suffix for python < 3.11 compatibility if needed
        clean_val = value.replace("Z", "+00:00")
        dt = datetime.fromisoformat(clean_val)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except (ValueError, TypeError):
        return None


@dataclass
class ADUser:
    sam_account_name: str
    distinguished_name: str
    display_name: str = ""
    enabled: bool = True
    admin_count: int = 0
    spn: List[str] = field(default_factory=list)
    user_account_control: List[str] = field(default_factory=list)
    last_logon_timestamp: Optional[str] = None
    password_last_set: Optional[str] = None
    password_never_expires: bool = False
    member_of: List[str] = field(default_factory=list)
    description: str = ""
    department: str = ""

    @property
    def parsed_last_logon(self) -> Optional[datetime]:
        return parse_iso_datetime(self.last_logon_timestamp)

    @property
    def parsed_password_last_set(self) -> Optional[datetime]:
        return parse_iso_datetime(self.password_last_set)

    @property
    def is_privileged_flag(self) -> bool:
        return self.admin_count > 0

    @property
    def is_asrep_roastable(self) -> bool:
        uac_upper = [flag.upper() for flag in self.user_account_control]
        return "DONT_REQ_PREAUTH" in uac_upper or "DONT_REQUIRE_PREAUTH" in uac_upper

    @property
    def has_password_not_required(self) -> bool:
        uac_upper = [flag.upper() for flag in self.user_account_control]
        return "PASSWD_NOTREQD" in uac_upper or "PASSWORD_NOTREQD" in uac_upper

    @property
    def has_reversible_encryption(self) -> bool:
        uac_upper = [flag.upper() for flag in self.user_account_control]
        return "ENCRYPTED_TEXT_PWD_ALLOWED" in uac_upper


@dataclass
class ADGroup:
    sam_account_name: str
    distinguished_name: str
    is_privileged: bool = False
    members: List[str] = field(default_factory=list)
    member_of: List[str] = field(default_factory=list)
    description: str = ""

    def __post_init__(self):
        sam_upper = self.sam_account_name.strip().upper()
        if sam_upper in PRIVILEGED_GROUP_NAMES:
            self.is_privileged = True


@dataclass
class ADComputer:
    sam_account_name: str
    distinguished_name: str
    operating_system: str = "Unknown"
    enabled: bool = True
    is_domain_controller: bool = False
    delegation_type: str = "None"
    user_account_control: List[str] = field(default_factory=list)
    member_of: List[str] = field(default_factory=list)

    @property
    def is_unconstrained_delegation(self) -> bool:
        uac_upper = [flag.upper() for flag in self.user_account_control]
        return (
            self.delegation_type.lower() == "unconstrained"
            or "TRUSTED_FOR_DELEGATION" in uac_upper
        )


@dataclass
class ADAce:
    principal_name: str
    target_name: str
    right: str
    is_inherited: bool = False


@dataclass
class ValidationIssue:
    severity: str  # "ERROR" or "WARNING"
    field_name: str
    message: str


class ADInventory:
    def __init__(self, domain: str = "CONTOSO.LOCAL", generated_at: Optional[str] = None):
        self.domain: str = domain
        self.generated_at: str = generated_at or datetime.now(timezone.utc).isoformat()
        self.users: Dict[str, ADUser] = {}
        self.groups: Dict[str, ADGroup] = {}
        self.computers: Dict[str, ADComputer] = {}
        self.acls: List[ADAce] = []
        self.issues: List[ValidationIssue] = []

        # Lookup caches for DN and SAM
        self._dn_map: Dict[str, Any] = {}
        self._sam_map: Dict[str, Any] = {}

    def register_object(self, obj: Any) -> None:
        """Register object in internal lookup maps."""
        if hasattr(obj, "distinguished_name") and obj.distinguished_name:
            self._dn_map[normalize_identifier(obj.distinguished_name)] = obj
        if hasattr(obj, "sam_account_name") and obj.sam_account_name:
            self._sam_map[normalize_identifier(obj.sam_account_name)] = obj

    def find_object(self, identifier: str) -> Optional[Any]:
        """Lookup an AD object by either DN or SAM account name."""
        norm = normalize_identifier(identifier)
        if norm in self._dn_map:
            return self._dn_map[norm]
        if norm in self._sam_map:
            return self._sam_map[norm]
        return None

    def is_privileged_group(self, name_or_dn: str) -> bool:
        """Determine if a group name, DN, or object represents a Tier-0/privileged group."""
        norm = normalize_identifier(name_or_dn)
        obj = self.find_object(name_or_dn)
        if isinstance(obj, ADGroup) and obj.is_privileged:
            return True
        for priv in PRIVILEGED_GROUP_NAMES:
            if priv.lower() in norm:
                return True
        return False

    def validate_relationships(self) -> None:
        """Validate consistency of references across group memberships and ACLs."""
        # Check Group -> Members
        for grp_id, group in self.groups.items():
            for member_ref in group.members:
                if not self.find_object(member_ref):
                    self.issues.append(
                        ValidationIssue(
                            severity="WARNING",
                            field_name=f"groups[{group.sam_account_name}].members",
                            message=f"Group '{group.sam_account_name}' references non-existent member '{member_ref}'.",
                        )
                    )

        # Check Object -> MemberOf
        all_objects = list(self.users.values()) + list(self.groups.values()) + list(self.computers.values())
        for obj in all_objects:
            for group_ref in obj.member_of:
                target_grp = self.find_object(group_ref)
                if not target_grp:
                    self.issues.append(
                        ValidationIssue(
                            severity="WARNING",
                            field_name=f"{type(obj).__name__}[{obj.sam_account_name}].member_of",
                            message=f"Object '{obj.sam_account_name}' references non-existent group '{group_ref}'.",
                        )
                    )
                elif not isinstance(target_grp, ADGroup):
                    self.issues.append(
                        ValidationIssue(
                            severity="WARNING",
                            field_name=f"{type(obj).__name__}[{obj.sam_account_name}].member_of",
                            message=f"Object '{obj.sam_account_name}' lists '{group_ref}' in member_of, but target is not a group.",
                        )
                    )

        # Check ACL references
        for idx, ace in enumerate(self.acls):
            if not self.find_object(ace.principal_name):
                self.issues.append(
                    ValidationIssue(
                        severity="WARNING",
                        field_name=f"acls[{idx}].principal_name",
                        message=f"ACL grants permission '{ace.right}' to unresolvable principal '{ace.principal_name}'.",
                    )
                )
            if not self.find_object(ace.target_name):
                self.issues.append(
                    ValidationIssue(
                        severity="WARNING",
                        field_name=f"acls[{idx}].target_name",
                        message=f"ACL targets unresolvable object '{ace.target_name}'.",
                    )
                )


def parse_inventory_dict(data: Dict[str, Any]) -> Tuple[Optional[ADInventory], List[ValidationIssue]]:
    """
    Parse a Python dictionary into an ADInventory instance with schema validation.
    Returns (inventory, issues). If schema is fundamentally invalid, inventory will be None.
    """
    issues: List[ValidationIssue] = []

    if not isinstance(data, dict):
        issues.append(ValidationIssue(severity="ERROR", field_name="root", message="Input payload must be a JSON object."))
        return None, issues

    domain = data.get("domain", "CORP.LOCAL")
    if not isinstance(domain, str) or not domain.strip():
        issues.append(ValidationIssue(severity="ERROR", field_name="domain", message="Field 'domain' must be a non-empty string."))
        return None, issues

    inventory = ADInventory(domain=domain, generated_at=data.get("generated_at"))

    # Parse Users
    users_raw = data.get("users", [])
    if not isinstance(users_raw, list):
        issues.append(ValidationIssue(severity="ERROR", field_name="users", message="'users' must be an array."))
        return None, issues

    for idx, u in enumerate(users_raw):
        if not isinstance(u, dict):
            issues.append(ValidationIssue(severity="ERROR", field_name=f"users[{idx}]", message="User entry must be an object."))
            continue
        sam = u.get("sam_account_name")
        dn = u.get("distinguished_name")
        if not sam or not dn:
            issues.append(ValidationIssue(severity="ERROR", field_name=f"users[{idx}]", message="User entry must contain 'sam_account_name' and 'distinguished_name'."))
            continue

        user_obj = ADUser(
            sam_account_name=str(sam),
            distinguished_name=str(dn),
            display_name=str(u.get("display_name", "")),
            enabled=bool(u.get("enabled", True)),
            admin_count=int(u.get("admin_count", 0)),
            spn=list(u.get("spn", [])),
            user_account_control=list(u.get("user_account_control", [])),
            last_logon_timestamp=u.get("last_logon_timestamp"),
            password_last_set=u.get("password_last_set"),
            password_never_expires=bool(u.get("password_never_expires", False)),
            member_of=list(u.get("member_of", [])),
            description=str(u.get("description", "")),
            department=str(u.get("department", "")),
        )
        norm_key = normalize_identifier(sam)
        inventory.users[norm_key] = user_obj
        inventory.register_object(user_obj)

    # Parse Groups
    groups_raw = data.get("groups", [])
    if not isinstance(groups_raw, list):
        issues.append(ValidationIssue(severity="ERROR", field_name="groups", message="'groups' must be an array."))
        return None, issues

    for idx, g in enumerate(groups_raw):
        if not isinstance(g, dict):
            issues.append(ValidationIssue(severity="ERROR", field_name=f"groups[{idx}]", message="Group entry must be an object."))
            continue
        sam = g.get("sam_account_name")
        dn = g.get("distinguished_name")
        if not sam or not dn:
            issues.append(ValidationIssue(severity="ERROR", field_name=f"groups[{idx}]", message="Group entry must contain 'sam_account_name' and 'distinguished_name'."))
            continue

        grp_obj = ADGroup(
            sam_account_name=str(sam),
            distinguished_name=str(dn),
            is_privileged=bool(g.get("is_privileged", False)),
            members=list(g.get("members", [])),
            member_of=list(g.get("member_of", [])),
            description=str(g.get("description", "")),
        )
        norm_key = normalize_identifier(sam)
        inventory.groups[norm_key] = grp_obj
        inventory.register_object(grp_obj)

    # Parse Computers
    computers_raw = data.get("computers", [])
    if not isinstance(computers_raw, list):
        issues.append(ValidationIssue(severity="ERROR", field_name="computers", message="'computers' must be an array."))
        return None, issues

    for idx, c in enumerate(computers_raw):
        if not isinstance(c, dict):
            issues.append(ValidationIssue(severity="ERROR", field_name=f"computers[{idx}]", message="Computer entry must be an object."))
            continue
        sam = c.get("sam_account_name")
        dn = c.get("distinguished_name")
        if not sam or not dn:
            issues.append(ValidationIssue(severity="ERROR", field_name=f"computers[{idx}]", message="Computer entry must contain 'sam_account_name' and 'distinguished_name'."))
            continue

        comp_obj = ADComputer(
            sam_account_name=str(sam),
            distinguished_name=str(dn),
            operating_system=str(c.get("operating_system", "Windows Server")),
            enabled=bool(c.get("enabled", True)),
            is_domain_controller=bool(c.get("is_domain_controller", False)),
            delegation_type=str(c.get("delegation_type", "None")),
            user_account_control=list(c.get("user_account_control", [])),
            member_of=list(c.get("member_of", [])),
        )
        norm_key = normalize_identifier(sam)
        inventory.computers[norm_key] = comp_obj
        inventory.register_object(comp_obj)

    # Parse ACLs
    acls_raw = data.get("acls", [])
    if not isinstance(acls_raw, list):
        issues.append(ValidationIssue(severity="ERROR", field_name="acls", message="'acls' must be an array."))
        return None, issues

    for idx, a in enumerate(acls_raw):
        if not isinstance(a, dict):
            issues.append(ValidationIssue(severity="ERROR", field_name=f"acls[{idx}]", message="ACL entry must be an object."))
            continue
        principal = a.get("principal_name")
        target = a.get("target_name")
        right = a.get("right")
        if not principal or not target or not right:
            issues.append(ValidationIssue(severity="ERROR", field_name=f"acls[{idx}]", message="ACL entry requires 'principal_name', 'target_name', and 'right'."))
            continue

        ace_obj = ADAce(
            principal_name=str(principal),
            target_name=str(target),
            right=str(right),
            is_inherited=bool(a.get("is_inherited", False)),
        )
        inventory.acls.append(ace_obj)

    # Cross-reference consistency validation
    inventory.validate_relationships()
    issues.extend(inventory.issues)

    # If any ERROR issues occurred, return None inventory
    has_errors = any(issue.severity == "ERROR" for issue in issues)
    if has_errors:
        return None, issues

    return inventory, issues
