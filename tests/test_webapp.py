"""
Integration tests for the Flask web application and routes.
"""

import io
import json
import pytest
from app import create_app


@pytest.fixture
def client():
    app = create_app({"TESTING": True, "SECRET_KEY": "test-key"})
    with app.test_client() as client:
        yield client


def test_dashboard_route(client):
    res = client.get("/")
    assert res.status_code == 200
    html = res.data.decode("utf-8")
    assert "Active Directory Security Assessment" in html
    assert "CORP.LOCAL" in html


def test_findings_route_and_filter(client):
    res = client.get("/findings")
    assert res.status_code == 200
    html = res.data.decode("utf-8")
    assert "Security Assessment Findings" in html

    # Filter by CRITICAL
    res_crit = client.get("/findings?severity=CRITICAL")
    assert res_crit.status_code == 200
    html_crit = res_crit.data.decode("utf-8")
    assert "CRITICAL" in html_crit


def test_finding_detail_route(client):
    # Check default finding 1
    res = client.get("/findings/PF-FND-001")
    assert res.status_code == 200
    html = res.data.decode("utf-8")
    assert "Finding ID: PF-FND-001" in html
    assert "Remediation Guidance" in html

    # Non-existent finding should redirect with message
    res_missing = client.get("/findings/NONEXISTENT", follow_redirects=True)
    assert res_missing.status_code == 200
    assert "Finding ID &#39;NONEXISTENT&#39; not found." in res_missing.data.decode("utf-8") or "Finding ID 'NONEXISTENT' not found." in res_missing.data.decode("utf-8")


def test_paths_route(client):
    res = client.get("/paths")
    assert res.status_code == 200
    html = res.data.decode("utf-8")
    assert "Structural Attack Paths" in html
    assert "Methodology &amp; Scope Disclaimer" in html or "Methodology & Scope Disclaimer" in html


def test_inventory_route(client):
    res = client.get("/inventory?tab=users")
    assert res.status_code == 200
    html = res.data.decode("utf-8")
    assert "adm_sarah" in html


def test_export_routes(client):
    # JSON
    res_json = client.get("/export/json")
    assert res_json.status_code == 200
    data = json.loads(res_json.data)
    assert "assessment_meta" in data

    # Markdown
    res_md = client.get("/export/markdown")
    assert res_md.status_code == 200
    assert b"# PathFinder AD" in res_md.data

    # HTML
    res_html = client.get("/export/html")
    assert res_html.status_code == 200
    assert b"<!DOCTYPE html>" in res_html.data


def test_api_summary(client):
    res = client.get("/api/summary")
    assert res.status_code == 200
    data = res.get_json()
    assert "total_findings" in data
    assert "severity_counts" in data
    assert data["total_findings"] > 0


def test_upload_dataset(client):
    custom_dataset = {
        "domain": "UPLOADED.LOCAL",
        "generated_at": "2026-10-01T00:00:00Z",
        "users": [
            {
                "sam_account_name": "uploaded_user",
                "distinguished_name": "CN=Uploaded User,DC=uploaded,DC=local",
                "enabled": True,
            }
        ],
        "groups": [],
        "computers": [],
        "acls": [],
    }

    data = {
        "action": "upload_file",
        "dataset_file": (io.BytesIO(json.dumps(custom_dataset).encode("utf-8")), "custom.json"),
    }
    res = client.post("/upload", data=data, content_type="multipart/form-data", follow_redirects=True)
    assert res.status_code == 200
    html = res.data.decode("utf-8")
    assert "UPLOADED.LOCAL" in html


def test_switch_to_benign_sample(client):
    res = client.post("/upload", data={"action": "load_sample_benign"}, follow_redirects=True)
    assert res.status_code == 200
    html = res.data.decode("utf-8")
    assert "SECURE.CORP.LOCAL" in html
