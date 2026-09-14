import os
import sys
import copy
import time
import logging
import threading
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional
from flask import Flask, render_template, request, jsonify

import retrohunt_batch as rb

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("retrohunt-ui")

app = Flask(__name__, template_folder="templates")

DEFAULT_PARENT_INSTANCE = os.getenv("PARENT_INSTANCE_ID", "12c99f43-6a09-4611-add1-7de0b3fcbfbd")
DEFAULT_PARENT_PROJECT = os.getenv("PARENT_PROJECT_ID", "huan-test-377123")
DEFAULT_REGION = os.getenv("SECOPS_REGION", "asia-southeast1")
CREDENTIALS_PATH = os.getenv("GOOGLE_APPLICATION_CREDENTIALS", None)

execution_lock = threading.RLock()
execution_state: Dict[str, Any] = {
    "status": "IDLE",  # IDLE, RUNNING, COMPLETED, FAILED
    "job_id": None,
    "started_at": None,
    "ended_at": None,
    "target_instances": [],
    "total_rules": 0,
    "total_jobs": 0,
    "completed_jobs": 0,
    "failed_jobs": 0,
    "total_detections": 0,
    "active_jobs": {},
    "results": [],
    "logs": [],
}


def add_log(msg: str, level: str = "INFO"):
    timestamp = datetime.now(timezone.utc).strftime("%H:%M:%S")
    entry = f"[{timestamp}] [{level}] {msg}"
    with execution_lock:
        execution_state["logs"].append(entry)
        if len(execution_state["logs"]) > 200:
            execution_state["logs"].pop(0)
    logger.info(msg)


@app.route("/")
def index():
    return render_template(
        "index.html",
        parent_instance=DEFAULT_PARENT_INSTANCE,
        parent_project=DEFAULT_PARENT_PROJECT,
        region=DEFAULT_REGION,
    )


@app.route("/api/status")
def get_status():
    with execution_lock:
        state_copy = copy.deepcopy(execution_state)
    return jsonify(state_copy)


@app.route("/api/tenants")
def get_tenants():
    parent_inst = request.args.get("parent_instance", DEFAULT_PARENT_INSTANCE)
    parent_proj = request.args.get("parent_project", DEFAULT_PARENT_PROJECT)
    region = request.args.get("region", DEFAULT_REGION)

    try:
        client = rb.create_secops_client(CREDENTIALS_PATH)
        tenants = rb.discover_tenants_from_partner_api(
            secops_client=client,
            parent_instance_id=parent_inst,
            parent_project=parent_proj,
            region=region,
        )
        return jsonify({
            "status": "success",
            "count": len(tenants),
            "tenants": [
                {
                    "customer_id": t.customer_id,
                    "project_id": t.project_id,
                    "display_name": t.display_name,
                    "region": t.region,
                    "customer_code": t.customer_code,
                }
                for t in tenants
            ]
        })
    except Exception as e:
        logger.error(f"Error discovering tenants: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/rules")
def get_instance_rules():
    instance_id = request.args.get("instance_id")
    project_id = request.args.get("project_id", DEFAULT_PARENT_PROJECT)
    region = request.args.get("region", DEFAULT_REGION)

    if not instance_id:
        return jsonify({"status": "error", "message": "instance_id is required"}), 400

    try:
        client = rb.create_secops_client(CREDENTIALS_PATH)
        chronicle = client.chronicle(customer_id=instance_id, project_id=project_id, region=region)
        res = chronicle.list_rules(page_size=200)
        rules = []
        for r in res.get("rules", []):
            dname = r.get("displayName")
            rname = r.get("name", "")
            rid = rname.split("/")[-1] if rname else None
            if dname and rid:
                rules.append({
                    "rule_id": rid,
                    "display_name": dname,
                    "create_time": r.get("createTime", ""),
                })
        return jsonify({"status": "success", "count": len(rules), "rules": rules})
    except Exception as e:
        logger.error(f"Error fetching rules for {instance_id}: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/start", methods=["POST"])
def start_retrohunt():
    global execution_state
    with execution_lock:
        if execution_state["status"] == "RUNNING":
            return jsonify({"status": "error", "message": "A retrohunt run is already in progress"}), 400

    data = request.get_json() or {}
    parent_inst = data.get("parent_instance", DEFAULT_PARENT_INSTANCE)
    parent_proj = data.get("parent_project", DEFAULT_PARENT_PROJECT)
    region = data.get("region", DEFAULT_REGION)
    tenant_ids = data.get("tenant_ids", [])
    max_rules = int(data.get("limit_rules", 3))
    hours = int(data.get("hours", 24))
    dry_run = bool(data.get("dry_run", False))
    safe_mode = bool(data.get("safe_mode", True))

    job_id = f"run_{int(time.time())}"

    with execution_lock:
        execution_state = {
            "status": "RUNNING",
            "job_id": job_id,
            "started_at": datetime.now(timezone.utc).isoformat(),
            "ended_at": None,
            "target_instances": [],
            "total_rules": max_rules,
            "total_jobs": 0,
            "completed_jobs": 0,
            "failed_jobs": 0,
            "total_detections": 0,
            "active_jobs": {},
            "results": [],
            "logs": [],
        }

    t = threading.Thread(
        target=_run_orchestration_background,
        args=(job_id, parent_inst, parent_proj, region, tenant_ids, max_rules, hours, dry_run, safe_mode),
        daemon=True,
    )
    t.start()

    return jsonify({"status": "started", "job_id": job_id})


def _run_orchestration_background(
    job_id: str,
    parent_inst: str,
    parent_proj: str,
    region: str,
    tenant_ids: List[str],
    max_rules: int,
    hours: int,
    dry_run: bool,
    safe_mode: bool,
):
    add_log(f"Initiating batch retrohunt run [{job_id}]...")
    add_log(f"Parent Instance: {parent_inst} | Region: {region} | Dry Run: {dry_run} | Safe Mode: {safe_mode}")

    try:
        client = rb.create_secops_client(CREDENTIALS_PATH)
        all_tenants = rb.discover_tenants_from_partner_api(
            secops_client=client,
            parent_instance_id=parent_inst,
            parent_project=parent_proj,
            region=region,
        )

        if tenant_ids:
            target_tenants = [t for t in all_tenants if t.customer_id in tenant_ids]
        else:
            target_tenants = all_tenants

        if not target_tenants:
            add_log("No matching tenant instances found.", "ERROR")
            with execution_lock:
                execution_state["status"] = "FAILED"
                execution_state["ended_at"] = datetime.now(timezone.utc).isoformat()
            return

        with execution_lock:
            execution_state["target_instances"] = [
                {"customer_id": t.customer_id, "display_name": t.display_name, "project_id": t.project_id}
                for t in target_tenants
            ]

        add_log(f"Discovered {len(target_tenants)} target instance(s).")

        # Chronicle requires retrohunt end_time to be within indexed data range (buffer by 1 hour)
        end_dt = datetime.now(timezone.utc) - timedelta(hours=1)
        start_dt = end_dt - timedelta(hours=hours)

        for target in target_tenants:
            add_log(f"Inspecting rules for tenant: {target.display_name} ({target.customer_id})...")
            chronicle = client.chronicle(customer_id=target.customer_id, project_id=target.project_id, region=region)
            
            res = chronicle.list_rules(page_size=100)
            rules_raw = res.get("rules", [])
            selected_rules = []
            for r in rules_raw:
                dname = r.get("displayName")
                rname = r.get("name", "")
                rid = rname.split("/")[-1] if rname else None
                if dname and rid:
                    selected_rules.append(rb.RuleItem(display_name=dname, rule_id=rid, category="instance_rule"))
                if len(selected_rules) >= max_rules:
                    break

            if not selected_rules:
                add_log(f"No rules found for tenant {target.display_name}, skipping.", "WARNING")
                continue

            with execution_lock:
                execution_state["total_jobs"] += len(selected_rules)

            add_log(f"[{target.display_name}] Executing retrohunt with {len(selected_rules)} rules (max 3 concurrent)...")

            inst_orch = None
            if not dry_run:
                inst_orch = rb.SecOpsInstanceOrchestrator(
                    instance=target,
                    secops_client=client,
                    max_concurrent=3,
                    poll_interval=5,
                    job_timeout=600,
                    safe_mode=safe_mode,
                    cleanup_created_rules=False,
                )

            for rule_item in selected_rules:
                job_key = f"{target.customer_id}::{rule_item.display_name}"
                with execution_lock:
                    execution_state["active_jobs"][job_key] = {
                        "instance_name": target.display_name,
                        "instance_id": target.customer_id,
                        "rule_name": rule_item.display_name,
                        "rule_id": rule_item.rule_id,
                        "status": "RUNNING",
                        "started_at": datetime.now(timezone.utc).isoformat(),
                    }

                add_log(f"[{target.display_name}] Starting retrohunt for '{rule_item.display_name}' ({rule_item.rule_id})...")

                if dry_run:
                    time.sleep(1.2)
                    result = rb.RetrohuntResult(
                        rule_name=rule_item.display_name,
                        rule_id=rule_item.rule_id or "DRY_RUN",
                        instance_id=target.customer_id,
                        instance_name=target.display_name,
                        file_path=None,
                        category="dry_run",
                        status="DONE",
                        start_time=rb.format_rfc3339(start_dt),
                        end_time=rb.format_rfc3339(end_dt),
                        duration_seconds=1.2,
                        detection_count=0,
                    )
                else:
                    result = inst_orch.execute_retrohunt(
                        rule_item=rule_item,
                        rule_id=rule_item.rule_id,
                        start_time=start_dt,
                        end_time=end_dt,
                    )

                with execution_lock:
                    execution_state["active_jobs"].pop(job_key, None)
                    execution_state["results"].append({
                        "instance_name": result.instance_name,
                        "instance_id": result.instance_id,
                        "rule_name": result.rule_name,
                        "rule_id": result.rule_id,
                        "status": result.status,
                        "duration_seconds": round(result.duration_seconds, 2),
                        "detection_count": result.detection_count,
                        "error_message": result.error_message,
                        "sample_detections": result.sample_detections,
                    })
                    if result.status == "DONE":
                        execution_state["completed_jobs"] += 1
                        execution_state["total_detections"] += result.detection_count
                    else:
                        execution_state["failed_jobs"] += 1

                if result.status == "DONE":
                    add_log(
                        f"[{target.display_name}] Rule '{result.rule_name}' finished: "
                        f"DONE ({result.duration_seconds:.1f}s, {result.detection_count} detections)."
                    )
                else:
                    add_log(f"[{target.display_name}] Rule '{result.rule_name}' failed: {result.error_message}", "ERROR")

        with execution_lock:
            execution_state["status"] = "COMPLETED"
            execution_state["ended_at"] = datetime.now(timezone.utc).isoformat()
        add_log(f"Retrohunt orchestration run [{job_id}] finished successfully.")

    except Exception as e:
        logger.exception("Orchestration failed")
        add_log(f"Fatal error during retrohunt run: {e}", "ERROR")
        with execution_lock:
            execution_state["status"] = "FAILED"
            execution_state["ended_at"] = datetime.now(timezone.utc).isoformat()


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port)
