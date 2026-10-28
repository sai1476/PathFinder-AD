# PathFinder AD — Active Directory Security Assessment

**PathFinder AD** is an offline, defensive Active Directory security assessment tool engineered for security analysts and penetration testers. It ingests synthetic Active Directory inventories (JSON), executes explainable, evidence-backed detection rules, models identity relationships with graph theory (NetworkX), flags multi-hop privilege escalation paths, and exports comprehensive audit reports in JSON, Markdown, and Standalone HTML formats.

---

## Key Features

1. **Synthetic Inventory Ingestion & Validation**
   - Ingests offline JSON representations of Active Directory domains (users, groups, computers, ACLs, and flags).
   - Validates schema structure and cross-references (identifies dangling memberships, ghost objects, and orphaned ACEs).

2. **Explainable Detection Rules**
   - **PF-AD-001 (Stale Accounts):** Detects enabled user accounts with no authenticated logon exceeding 90 days.
   - **PF-AD-002 (Kerberoasting Exposure):** Identifies high-privilege accounts (e.g., Domain Admins, `adminCount > 0`) configured with Service Principal Names (SPNs).
   - **PF-AD-003 (AS-REP Roasting Exposure):** Detects accounts with Kerberos pre-authentication disabled (`DONT_REQ_PREAUTH`).
   - **PF-AD-004 (Insecure Credential Flags):** Identifies accounts where passwords are not required (`PASSWD_NOTREQD`) or stored using reversible encryption (`ENCRYPTED_TEXT_PWD_ALLOWED`).
   - **PF-AD-005 (Unconstrained Delegation):** Flags non-Domain Controller computers with `TRUSTED_FOR_DELEGATION` (LSASS credential harvest risk).
   - **PF-AD-006 (Excessive ACLs on Tier-0):** Uncovers dangerous rights (`GenericAll`, `WriteDacl`, `WriteOwner`, `ResetPassword`) granted to unprivileged identities over Tier-0 groups.
   - **PF-AD-007 (Weak Group Nesting):** Detects standard or unmanaged groups directly nested into privileged Tier-0 groups.

3. **Structural Risk Path Analysis (NetworkX)**
   - Models users, groups, and computers as nodes, and group memberships and ACLs as directed edges.
   - Traces shortest structural progression chains from unprivileged users to Tier-0 targets (e.g., `Domain Admins`).
   - *Educational & Scope Disclaimer:* Labels paths strictly as structural permission hypotheses, clarifying that real-world exploitability depends on network reachability, MFA, and host controls.

4. **Multi-Format Security Reporting**
   - **Standalone HTML Report:** Single-file, printable, styled offline report with executive metrics and remediation steps.
   - **Markdown Report:** Formatted for easy inclusion in GitHub repositories or documentation.
   - **JSON Export:** Full programmatic export of metrics, findings, and graph paths.

5. **Built-in Synthetic Scenarios**
   - `synthetic_enterprise.json`: Mid-sized corporate environment with intentional misconfigurations and multi-hop attack paths.
   - `benign_baseline.json`: Hardened Active Directory environment demonstrating clean scans (zero false positives).

---

## Project Structure

```
PathFinder AD/
├── app/
│   ├── __init__.py          # Flask application factory
│   ├── models.py            # Data models & schema validator (ADUser, ADGroup, ADComputer, ADAce)
│   ├── analyzer.py          # Detection rule engine & NetworkX relationship graph analyzer
│   ├── reporter.py          # Multi-format report exporter (HTML, Markdown, JSON)
│   ├── routes.py            # Web routes (Dashboard, Findings, Detail, Paths, Inventory, Upload)
│   ├── static/
│   │   ├── css/style.css    # Clean cybersecurity dark/light UI
│   │   └── js/main.js       # Search filters & UI interactions
│   └── templates/
│       ├── base.html        # Shared navigation layout
│       ├── dashboard.html   # Executive summary & metrics
│       ├── findings.html    # Filterable & searchable findings table
│       ├── finding_detail.html # Technical explanation, evidence, & remediation
│       ├── paths.html       # Attack path graph breakdown
│       ├── inventory.html   # Active Directory object browser
│       └── upload.html      # Dataset switcher & JSON upload
├── data/
│   ├── synthetic_enterprise.json # Misconfigured enterprise dataset
│   └── benign_baseline.json      # Hardened benchmark dataset
├── tests/
│   ├── test_schema.py       # Input validation & relationship consistency tests
│   ├── test_rules.py        # Individual unit tests for each security rule
│   ├── test_graph_paths.py  # Path traversal and chain discovery tests
│   ├── test_reporter.py     # HTML, Markdown, and JSON export tests
│   └── test_webapp.py       # Flask endpoints and workflow tests
├── requirements.txt
├── pytest.ini
├── .gitignore
├── run.py                   # Application launch script
└── README.md                # Documentation & demo walkthrough
```

---

## Installation & Setup

### Prerequisites
- Python 3.9+ (Python 3.11 recommended)
- `pip`

### 1. Clone or Navigate to Directory
```powershell
cd "c:\Users\SAITEJA\Documents\PathFinder AD"
```

### 2. Install Dependencies
```powershell
pip install -r requirements.txt
```

---

## Running the Application

To launch the web interface:
```powershell
python run.py
```
Open your browser and navigate to:
```
http://127.0.0.1:5000
```

By default, PathFinder AD automatically loads the `synthetic_enterprise.json` scenario on first launch.

---

## Running Automated Tests

Run the full pytest suite with verbose output:
```powershell
python -m pytest -v
```

All 24 automated unit and integration tests validate:
- Schema parsing, validation errors, and relationship warnings
- Individual rule detection logic and threshold behaviors
- Zero false positives on the benign hardened baseline
- Graph traversal and shortest-path discovery
- Multi-format report generation
- Flask web routes, filters, file uploads, and API endpoints

---

## Synthetic Data Schema

PathFinder AD accepts clean JSON files structured as follows:

```json
{
  "domain": "CORP.LOCAL",
  "generated_at": "2026-10-01T00:00:00Z",
  "users": [
    {
      "sam_account_name": "sql_svc",
      "display_name": "SQL Database Service Account",
      "distinguished_name": "CN=SQL Service,OU=ServiceAccounts,DC=corp,DC=local",
      "enabled": true,
      "admin_count": 1,
      "spn": ["MSSQLSvc/sql01.corp.local:1433"],
      "user_account_control": ["NORMAL_ACCOUNT"],
      "last_logon_timestamp": "2026-09-25T08:00:00Z",
      "password_last_set": "2024-05-10T14:30:00Z",
      "password_never_expires": true,
      "member_of": ["CN=Domain Admins,CN=Users,DC=corp,DC=local"]
    }
  ],
  "groups": [
    {
      "sam_account_name": "Domain Admins",
      "distinguished_name": "CN=Domain Admins,CN=Users,DC=corp,DC=local",
      "is_privileged": true,
      "members": ["CN=SQL Service,OU=ServiceAccounts,DC=corp,DC=local"],
      "member_of": []
    }
  ],
  "computers": [
    {
      "sam_account_name": "SRV-APP01$",
      "distinguished_name": "CN=SRV-APP01,OU=Servers,DC=corp,DC=local",
      "operating_system": "Windows Server 2019 Standard",
      "enabled": true,
      "is_domain_controller": false,
      "delegation_type": "Unconstrained",
      "user_account_control": ["WORKSTATION_TRUST_ACCOUNT", "TRUSTED_FOR_DELEGATION"],
      "member_of": []
    }
  ],
  "acls": [
    {
      "principal_name": "CN=Contractors,OU=Groups,DC=corp,DC=local",
      "target_name": "CN=Domain Admins,CN=Users,DC=corp,DC=local",
      "right": "WriteDacl",
      "is_inherited": false
    }
  ]
}
```

---

## Demo Walkthrough

1. **Dashboard Overview (`/`)**:
   - View severity distribution (Critical, High, Medium risks).
   - Review high-level breakdown of parsed objects and triggered detection rules.
2. **Explore Findings (`/findings`)**:
   - Filter findings by severity (e.g., `CRITICAL`) or rule identifier (e.g., `PF-AD-002`).
   - Use the instant search box to locate specific accounts or computers.
3. **Inspect Finding Detail (`/findings/PF-FND-001`)**:
   - Examine technical risk impact, parsed synthetic evidence, and actionable remediation instructions.
4. **Inspect Structural Attack Paths (`/paths`)**:
   - Observe how `contractor_bob` can reach `Domain Admins` through group membership and explicit `WriteDacl` permissions.
5. **Switch Scenarios (`/upload`)**:
   - Click **"Load Hardened Baseline"** to see how the engine evaluates a hardened domain, yielding **0 findings** and demonstrating rule precision.
6. **Export Audit Reports (`/export/html`, `/export/markdown`, `/export/json`)**:
   - Download executive-ready reports for offline review.

---

## Recommended Screenshots for Portfolio

When featuring this project in your portfolio or documentation, capture:
1. **Executive Dashboard:** Showing metric cards, rule breakdown, and top findings.
2. **Filterable Findings View:** Demonstrating severity filtering (`CRITICAL` and `HIGH`).
3. **Finding Detail Page:** Displaying technical explanation, raw JSON evidence, and remediation guidance.
4. **Structural Attack Path Visualizer:** Showing the multi-hop chain from `contractor_bob` to `Domain Admins`.
5. **Clean Baseline Demonstration:** Showing zero findings when loading `benign_baseline.json`.

---

## Safety, Scope & Engineering Limitations

- **Defensive & Static Only:** PathFinder AD does not connect to live Active Directory domain controllers or perform network enumeration.
- **No Exploitation or Credential Dumping:** No lateral movement, pass-the-hash, or password extraction tools are implemented.
- **Explainable Thresholds:** Timestamps must be explicitly present to trigger inactivity alerts; no assumptions or fictitious risk scores are generated.
- **Graph Path Semantics:** Discovered paths represent structural object linkages in the dataset, not confirmed live exploitability.
