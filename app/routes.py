"""
Flask web routes for PathFinder AD.
Provides dashboard metrics, findings explorer, detail views, path inspection,
inventory browsing, dataset uploads, and multi-format report exports.
"""

from __future__ import annotations
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from flask import (
    Blueprint,
    Response,
    current_app,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    url_for,
)

from app.models import parse_inventory_dict, ADInventory
from app.analyzer import ADAnalyzer, Finding, RiskPath
from app.reporter import ReportGenerator

bp = Blueprint("main", __name__)

# State container for active session
class AssessmentState:
    def __init__(self):
        self.inventory: Optional[ADInventory] = None
        self.findings: list[Finding] = []
        self.risk_paths: list[RiskPath] = []
        self.source_name: str = "synthetic_enterprise.json"
        self.analyzed_at: Optional[datetime] = None

    def load_dataset(self, data: dict, source_name: str = "Uploaded Dataset"):
        inv, issues = parse_inventory_dict(data)
        if not inv:
            return False, issues
        
        # Reference date from dataset timestamp or fallback to now
        ref_dt = None
        if inv.generated_at:
            try:
                ref_dt = datetime.fromisoformat(inv.generated_at.replace("Z", "+00:00"))
            except Exception:
                ref_dt = datetime.now(timezone.utc)
        else:
            ref_dt = datetime.now(timezone.utc)

        analyzer = ADAnalyzer(inv, reference_date=ref_dt)
        findings = analyzer.run_all_checks()
        paths = analyzer.risk_paths

        self.inventory = inv
        self.findings = findings
        self.risk_paths = paths
        self.source_name = source_name
        self.analyzed_at = datetime.now(timezone.utc)
        return True, issues

state = AssessmentState()


def load_default_dataset_if_empty():
    """Ensure default enterprise sample is loaded on first visit."""
    if state.inventory is None:
        base_dir = Path(__file__).resolve().parent.parent
        default_sample = base_dir / "data" / "synthetic_enterprise.json"
        if default_sample.exists():
            with open(default_sample, "r", encoding="utf-8") as f:
                data = json.load(f)
            state.load_dataset(data, source_name="synthetic_enterprise.json (Default Sample)")


@bp.before_request
def ensure_dataset():
    load_default_dataset_if_empty()


@bp.route("/")
def dashboard():
    """Main security assessment dashboard."""
    if not state.inventory:
        return redirect(url_for("main.upload"))

    rep = ReportGenerator(state.inventory, state.findings, state.risk_paths)
    summary = rep.get_summary_metrics()

    # Rule distribution
    rule_counts = {}
    for f in state.findings:
        rule_counts[f.rule_id] = rule_counts.get(f.rule_id, 0) + 1

    return render_template(
        "dashboard.html",
        state=state,
        summary=summary,
        rule_counts=rule_counts,
        top_findings=state.findings[:6],
        active_tab="dashboard",
    )


@bp.route("/findings")
def findings():
    """Searchable & filterable findings explorer."""
    sev_filter = request.args.get("severity", "").strip().upper()
    rule_filter = request.args.get("rule_id", "").strip().upper()
    q = request.args.get("q", "").strip().lower()

    filtered = state.findings
    if sev_filter:
        filtered = [f for f in filtered if f.severity.upper() == sev_filter]
    if rule_filter:
        filtered = [f for f in filtered if f.rule_id.upper() == rule_filter]
    if q:
        filtered = [
            f for f in filtered
            if q in f.title.lower() or q in f.affected_object.lower() or q in f.rule_id.lower() or q in f.explanation.lower()
        ]

    # Available rule identifiers for dropdown
    all_rules = sorted(list({f.rule_id for f in state.findings}))

    return render_template(
        "findings.html",
        findings=filtered,
        total_count=len(state.findings),
        all_rules=all_rules,
        current_sev=sev_filter,
        current_rule=rule_filter,
        search_query=q,
        active_tab="findings",
    )


@bp.route("/findings/<finding_id>")
def finding_detail(finding_id: str):
    """Detailed view for a specific finding."""
    target = next((f for f in state.findings if f.id.upper() == finding_id.upper()), None)
    if not target:
        flash(f"Finding ID '{finding_id}' not found.", "warning")
        return redirect(url_for("main.findings"))

    return render_template(
        "finding_detail.html",
        finding=target,
        active_tab="findings",
    )


@bp.route("/paths")
def paths():
    """Structural attack path and relationship analysis view."""
    return render_template(
        "paths.html",
        risk_paths=state.risk_paths,
        active_tab="paths",
    )


@bp.route("/inventory")
def inventory():
    """Active Directory objects and parsed inventory browser."""
    tab = request.args.get("tab", "users")
    return render_template(
        "inventory.html",
        inventory=state.inventory,
        active_subtab=tab,
        active_tab="inventory",
    )


@bp.route("/upload", methods=["GET", "POST"])
def upload():
    """Upload custom JSON dataset or pick synthetic samples."""
    base_dir = Path(__file__).resolve().parent.parent
    sample_enterprise = base_dir / "data" / "synthetic_enterprise.json"
    sample_benign = base_dir / "data" / "benign_baseline.json"

    if request.method == "POST":
        action = request.form.get("action", "")

        if action == "load_sample_enterprise":
            if sample_enterprise.exists():
                with open(sample_enterprise, "r", encoding="utf-8") as f:
                    data = json.load(f)
                success, issues = state.load_dataset(data, "Synthetic Enterprise (Misconfigured)")
                if success:
                    flash("Loaded 'Synthetic Enterprise' scenario with misconfigurations.", "success")
                    return redirect(url_for("main.dashboard"))
                else:
                    flash("Failed to load sample dataset.", "danger")

        elif action == "load_sample_benign":
            if sample_benign.exists():
                with open(sample_benign, "r", encoding="utf-8") as f:
                    data = json.load(f)
                success, issues = state.load_dataset(data, "Benign Baseline (Hardened)")
                if success:
                    flash("Loaded 'Benign Baseline' scenario (Hardened Active Directory).", "success")
                    return redirect(url_for("main.dashboard"))
                else:
                    flash("Failed to load benign baseline dataset.", "danger")

        elif action == "upload_file":
            file = request.files.get("dataset_file")
            if not file or file.filename == "":
                flash("Please select a JSON file to upload.", "danger")
                return redirect(url_for("main.upload"))

            try:
                content = file.read().decode("utf-8")
                data = json.loads(content)
            except Exception as e:
                flash(f"Invalid JSON format: {str(e)}", "danger")
                return redirect(url_for("main.upload"))

            success, issues = state.load_dataset(data, f"Uploaded: {file.filename}")
            if not success:
                err_msgs = [f"[{i.severity}] {i.field_name}: {i.message}" for i in issues if i.severity == "ERROR"]
                flash(f"Schema validation failed: {'; '.join(err_msgs)}", "danger")
                return redirect(url_for("main.upload"))

            warn_count = sum(1 for i in issues if i.severity == "WARNING")
            if warn_count > 0:
                flash(f"Dataset loaded with {warn_count} consistency warning(s). Check inventory issues tab.", "warning")
            else:
                flash(f"Successfully loaded and analyzed '{file.filename}'.", "success")

            return redirect(url_for("main.dashboard"))

    return render_template(
        "upload.html",
        active_tab="upload",
        current_source=state.source_name,
    )


@bp.route("/export/json")
def export_json():
    """Export findings as JSON file."""
    if not state.inventory:
        return redirect(url_for("main.upload"))
    rep = ReportGenerator(state.inventory, state.findings, state.risk_paths)
    json_text = rep.to_json()
    return Response(
        json_text,
        mimetype="application/json",
        headers={"Content-Disposition": f"attachment; filename=pathfinder_ad_{state.inventory.domain}.json"},
    )


@bp.route("/export/markdown")
def export_markdown():
    """Export findings as Markdown report."""
    if not state.inventory:
        return redirect(url_for("main.upload"))
    rep = ReportGenerator(state.inventory, state.findings, state.risk_paths)
    md_text = rep.to_markdown()
    return Response(
        md_text,
        mimetype="text/markdown",
        headers={"Content-Disposition": f"attachment; filename=pathfinder_ad_{state.inventory.domain}.md"},
    )


@bp.route("/export/html")
def export_html():
    """Export findings as standalone HTML report."""
    if not state.inventory:
        return redirect(url_for("main.upload"))
    rep = ReportGenerator(state.inventory, state.findings, state.risk_paths)
    html_text = rep.to_html()
    return Response(
        html_text,
        mimetype="text/html",
        headers={"Content-Disposition": f"attachment; filename=pathfinder_ad_{state.inventory.domain}.html"},
    )


@bp.route("/api/summary")
def api_summary():
    """API endpoint providing assessment metrics in JSON."""
    if not state.inventory:
        return jsonify({"error": "No dataset loaded"}), 400
    rep = ReportGenerator(state.inventory, state.findings, state.risk_paths)
    return jsonify(rep.get_summary_metrics())
