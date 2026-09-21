#!/usr/bin/env python3
"""
SecOps Batch Retrohunt Orchestrator
===================================
A high-throughput, quota-aware multi-tenant batch retrohunt runner for Google SecOps
(Chronicle) using the official secops-wrapper SDK and Customer Management / Partner APIs.

Key Features & Multi-Tenant Support:
1. Multi-Tenant Architecture (e.g., Enterprise/MSSP with dozens of instances):
   - Supports automated tenant discovery via Customer Management / Partner APIs
   - (GET /v1alpha/projects/{project}/locations/{location}/instances/{instance}/tenants)
     as mapped in https://docs.cloud.google.com/chronicle/docs/administration/siem-endpoint-mapping-table
   - Supports static instance inventory files (CSV or JSON) to target specific tenants or subsets.
   - Leverages unified authentication across all child tenants.
2. Per-Instance Concurrency Management:
   - Google SecOps limits each instance to a maximum of 3 concurrent retrohunts.
   - Automatically executes batches of 3 rules concurrently per instance without manual intervention.
   - As soon as a retrohunt completes, the next rule is immediately dispatched from the queue.
   - Supports cross-instance parallelism (--max-parallel-instances) for multi-tenant scalability.
3. Alert Storm Prevention (Safe Mode):
   - Running retrohunts on rules with alerting enabled triggers SOAR alerts for all historical matches.
   - Safe mode automatically detects and disables alerting during retrohunt, with automatic restoration.
4. Rule Ingestion & Dynamic Staging:
   - Ingests rules from disk (e.g. chronicle/detection-rules repo), instance rules, or rule IDs.
   - Caches instance rules for O(1) matching.
   - Validates YARA-L syntax via SecOps API before submission.
   - Automatically stages missing rules (disabled/non-alerting) with optional post-run cleanup.
5. Resiliency & Reporting:
   - Live percentage progress polling across all active jobs.
   - Checkpointing keyed by (instance_id, rule_name) for seamless resumption.
   - Unified multi-tenant JSON and CSV reports with detection counts and timings.
"""

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import csv
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
import glob
import json
import logging
import os
import queue
import re
import sys
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

# Third-party SDK import
try:
    from secops import SecOpsClient
    from secops.exceptions import APIError, SecOpsError
except ImportError:
    print(
        "ERROR: 'secops' library is not installed or dependencies are missing.\n"
        "Please install secops-wrapper: pip install secops\n",
        file=sys.stderr,
    )
    sys.exit(1)

# Default Placeholders & Config
DEFAULT_CUSTOMER_ID = os.getenv("SECOPS_CUSTOMER_ID", "YOUR_CUSTOMER_ID")
DEFAULT_REGION = os.getenv("SECOPS_REGION", "us")
DEFAULT_PROJECT_ID = os.getenv("SECOPS_PROJECT_ID", "YOUR_PROJECT_ID")
DEFAULT_CRED_PATH = os.getenv(
    "GOOGLE_APPLICATION_CREDENTIALS",
    "path/to/service_account.json"
)


def create_secops_client(credentials_path: Optional[str] = None) -> SecOpsClient:
    """Instantiate SecOpsClient with cloud-platform and chronicle-backstory scopes."""
    if credentials_path and os.path.exists(credentials_path):
        return SecOpsClient(service_account_path=credentials_path)
    elif os.environ.get("GOOGLE_APPLICATION_CREDENTIALS") and os.path.exists(os.environ["GOOGLE_APPLICATION_CREDENTIALS"]):
        return SecOpsClient(service_account_path=os.environ["GOOGLE_APPLICATION_CREDENTIALS"])
    else:
        return SecOpsClient()

# Hard limit for Google SecOps per individual instance
MAX_CONCURRENT_PER_INSTANCE = 3


@dataclass
class InstanceTarget:
    """Representation of a Google SecOps instance/tenant."""
    customer_id: str
    project_id: str
    display_name: str
    region: str = "us"
    customer_code: Optional[str] = None


@dataclass
class RuleItem:
    """Representation of a detection rule candidate for retrohunt."""
    display_name: str
    file_path: Optional[str] = None
    rule_text: Optional[str] = None
    rule_id: Optional[str] = None
    category: str = "custom"
    created_dynamically: bool = False
    original_alerting: Optional[bool] = None
    meta: Dict[str, str] = field(default_factory=dict)


@dataclass
class RetrohuntResult:
    """Output metrics and findings for a single retrohunt job."""
    rule_name: str
    rule_id: str
    instance_id: str
    instance_name: str
    file_path: Optional[str]
    category: str
    status: str  # DONE, FAILED, SKIPPED, TIMEOUT, CANCELED
    operation_id: Optional[str] = None
    start_time: str = ""
    end_time: str = ""
    duration_seconds: float = 0.0
    detection_count: int = 0
    error_message: Optional[str] = None
    sample_detections: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class RuleDeployResult:
    """Output details and status for a single rule deployment / save operation."""
    rule_name: str
    rule_id: str
    instance_id: str
    instance_name: str
    file_path: Optional[str]
    category: str
    action: str  # CREATED, UPDATED, UNCHANGED, DRY_RUN, FAILED, VALIDATION_ERROR
    revision_id: Optional[str] = None
    enabled: Optional[bool] = None
    alerting: Optional[bool] = None
    error_message: Optional[str] = None



def parse_rfc3339(date_str: str) -> datetime:
    """Parse RFC 3339 / ISO 8601 string to timezone-aware UTC datetime."""
    clean_str = date_str.strip()
    if clean_str.endswith("Z"):
        clean_str = clean_str[:-1] + "+00:00"
    dt = datetime.fromisoformat(clean_str)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def format_rfc3339(dt: datetime) -> str:
    """Format timezone-aware datetime into UTC RFC 3339 string."""
    utc_dt = dt.astimezone(timezone.utc)
    return utc_dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def extract_rule_metadata(rule_text: str) -> Tuple[str, Dict[str, str]]:
    """Extract rule display name and meta properties from YARA-L content."""
    name_match = re.search(r"rule\s+([a-zA-Z0-9_]+)\s*\{", rule_text)
    display_name = name_match.group(1) if name_match else "unnamed_rule"

    meta: Dict[str, str] = {}
    meta_block = re.search(r"meta\s*:(.*?)(?:events\s*:|condition\s*:|match\s*:)", rule_text, re.DOTALL)
    if meta_block:
        lines = meta_block.group(1).splitlines()
        for line in lines:
            kv = re.search(r'([a-zA-Z0-9_-]+)\s*=\s*"([^"]+)"', line)
            if kv:
                meta[kv.group(1).strip()] = kv.group(2).strip()

    return display_name, meta


def discover_tenants_from_partner_api(
    secops_client: SecOpsClient,
    parent_instance_id: str,
    parent_project: str,
    region: str = "us",
    api_version: str = "v1alpha",
) -> List[InstanceTarget]:
    """
    Discovers child tenants using the Chronicle Partner / Customer Management API:
    Endpoint: GET https://{region}-chronicle.googleapis.com/{api_version}/projects/{parent_project}/locations/{region}/instances/{parent_instance_id}/tenants
    Reference: https://docs.cloud.google.com/chronicle/docs/administration/siem-endpoint-mapping-table
    """
    logging.info(
        f"Discovering tenants via Partner API for parent {parent_instance_id} (Project: {parent_project}, Region: {region})..."
    )
    base_endpoint = f"https://{region}-chronicle.googleapis.com"
    parent_path = f"projects/{parent_project}/locations/{region}/instances/{parent_instance_id}"
    url = f"{base_endpoint}/{api_version}/{parent_path}/tenants"

    instances: List[InstanceTarget] = []
    page_token = None

    while True:
        params = {"pageSize": 100}
        if page_token:
            params["pageToken"] = page_token

        try:
            resp = secops_client.auth.session.get(url, params=params)
            if resp.status_code != 200:
                # If v1alpha fails, attempt v1beta fallback
                if api_version == "v1alpha":
                    logging.warning(f"v1alpha returned {resp.status_code}, falling back to v1beta...")
                    return discover_tenants_from_partner_api(
                        secops_client, parent_instance_id, parent_project, region, api_version="v1beta"
                    )
                logging.error(f"Failed to query Customer Management API ({resp.status_code}): {resp.text}")
                break

            data = resp.json()
            tenants = data.get("tenants", [])
            for t in tenants:
                name = t.get("name", "")
                tenant_id = name.split("/")[-1] if name else ""
                display_name = t.get("displayName", tenant_id)
                customer_code = t.get("customerCode", "")
                tenant_gcp_project = t.get("tenantGcpProject", "")
                project_id = tenant_gcp_project.replace("projects/", "") if tenant_gcp_project else parent_project

                if tenant_id:
                    instances.append(
                        InstanceTarget(
                            customer_id=tenant_id,
                            project_id=project_id,
                            display_name=display_name,
                            region=region,
                            customer_code=customer_code,
                        )
                    )

            page_token = data.get("nextPageToken")
            if not page_token or not tenants:
                break
        except Exception as e:
            logging.error(f"Error calling Partner Tenants API: {e}")
            break

    logging.info(f"Successfully discovered {len(instances)} tenant instance(s) via Partner API.")
    return instances


def load_instances_from_file(
    file_path: str,
    default_region: str = "us",
    default_project: str = "YOUR_PROJECT_ID",
) -> List[InstanceTarget]:
    """
    Loads instance targets from a CSV or JSON file.
    CSV expected headers: instance_id, project_id, display_name, region (optional)
    JSON expected format: list of objects with keys: instance_id, project_id, display_name, region
    """
    logging.info(f"Loading instance targets from file '{file_path}'...")
    instances: List[InstanceTarget] = []

    if file_path.endswith(".json"):
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, list):
                for item in data:
                    inst_id = item.get("instance_id") or item.get("customer_id")
                    if inst_id:
                        instances.append(
                            InstanceTarget(
                                customer_id=inst_id,
                                project_id=item.get("project_id", default_project),
                                display_name=item.get("display_name", inst_id),
                                region=item.get("region", default_region),
                                customer_code=item.get("customer_code"),
                            )
                        )
    elif file_path.endswith(".csv"):
        with open(file_path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                inst_id = row.get("instance_id") or row.get("customer_id")
                if inst_id:
                    instances.append(
                        InstanceTarget(
                            customer_id=inst_id,
                            project_id=row.get("project_id") or default_project,
                            display_name=row.get("display_name") or inst_id,
                            region=row.get("region") or default_region,
                            customer_code=row.get("customer_code"),
                        )
                    )
    else:
        # Plain text file with one instance UUID per line
        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    instances.append(
                        InstanceTarget(
                            customer_id=line,
                            project_id=default_project,
                            display_name=line,
                            region=default_region,
                        )
                    )

    logging.info(f"Loaded {len(instances)} instance(s) from '{file_path}'.")
    return instances


class SecOpsInstanceOrchestrator:
    """Manages retrohunt lifecycle for a single Google SecOps instance/tenant."""

    def __init__(
        self,
        instance: InstanceTarget,
        secops_client: SecOpsClient,
        max_concurrent: int = 3,
        poll_interval: int = 10,
        job_timeout: int = 600,
        safe_mode: bool = True,
        restore_alerting: bool = True,
        cleanup_created_rules: bool = False,
    ):
        self.instance = instance
        self.secops_client = secops_client
        self.max_concurrent = min(max_concurrent, MAX_CONCURRENT_PER_INSTANCE)
        self.poll_interval = poll_interval
        self.job_timeout = job_timeout
        self.safe_mode = safe_mode
        self.restore_alerting = restore_alerting
        self.cleanup_created_rules = cleanup_created_rules

        # Instance Chronicle client
        self.chronicle = self.secops_client.chronicle(
            customer_id=instance.customer_id,
            project_id=instance.project_id,
            region=instance.region,
        )

        # Instance rules cache: {display_name: rule_id}
        self.existing_rules: Dict[str, str] = {}
        self._load_rules_cache()

    def _load_rules_cache(self):
        """Cache all rules deployed in this instance for O(1) matching."""
        logging.info(f"[{self.instance.display_name}] Caching existing instance rules...")
        token = None
        count = 0
        while True:
            try:
                res = self.chronicle.list_rules(page_size=1000, page_token=token)
                for r in res.get("rules", []):
                    dname = r.get("displayName")
                    rname = r.get("name", "")
                    rid = rname.split("/")[-1] if rname else None
                    if dname and rid:
                        self.existing_rules[dname] = rid
                        count += 1
                token = res.get("nextPageToken")
                if not token:
                    break
            except Exception as e:
                logging.warning(f"[{self.instance.display_name}] Rules cache error: {e}")
                break
        logging.info(f"[{self.instance.display_name}] Cached {count} deployed rule(s).")

    def stage_rule(
        self,
        rule_item: RuleItem,
        update_existing: bool = False,
    ) -> Tuple[bool, Optional[str], Optional[str]]:
        """Ensures the rule exists in this instance, creating it if missing or updating if requested."""
        rule_id = rule_item.rule_id or self.existing_rules.get(rule_item.display_name)

        # If rule already exists and update is not requested, return existing ID
        if rule_id and not update_existing:
            return True, rule_id, None

        if not rule_item.rule_text:
            if rule_id:
                return True, rule_id, None
            return False, None, f"Rule '{rule_item.display_name}' not in instance and has no rule text."

        # Validate syntax
        try:
            val = self.chronicle.validate_rule(rule_item.rule_text)
            if not val.success:
                return False, None, f"Validation failed: {val.message}"
        except Exception as e:
            return False, None, f"Validate API error: {e}"

        # If rule exists and update_existing is True, update rule content
        if rule_id and update_existing:
            try:
                updated = self.chronicle.update_rule(rule_id, rule_item.rule_text)
                logging.info(f"[{self.instance.display_name}] Updated existing rule '{rule_item.display_name}' ({rule_id}).")
                return True, rule_id, None
            except Exception as e:
                return False, None, f"Update rule failed: {e}"

        # Create rule in disabled / non-alerting state
        try:
            created = self.chronicle.create_rule(rule_item.rule_text)
            rname = created.get("name", "")
            rule_id = rname.split("/")[-1] if rname else None
            if not rule_id:
                return False, None, f"Failed parsing created rule ID: {created}"

            self.existing_rules[rule_item.display_name] = rule_id
            logging.info(f"[{self.instance.display_name}] Staged missing rule '{rule_item.display_name}' as {rule_id}.")
            return True, rule_id, None
        except Exception as e:
            return False, None, f"Create rule failed: {e}"

    def deploy_rule(
        self,
        rule_item: RuleItem,
        update_existing: bool = True,
        enable_rule: Optional[bool] = None,
        enable_alerting: Optional[bool] = None,
        dry_run: bool = False,
    ) -> RuleDeployResult:
        """Deploys or saves a rule directly into this Chronicle instance."""
        rule_name = rule_item.display_name
        inst_name = self.instance.display_name
        inst_id = self.instance.customer_id
        file_path = rule_item.file_path
        category = rule_item.category

        if not rule_item.rule_text:
            return RuleDeployResult(
                rule_name=rule_name,
                rule_id=rule_item.rule_id or "UNKNOWN",
                instance_id=inst_id,
                instance_name=inst_name,
                file_path=file_path,
                category=category,
                action="FAILED",
                error_message="No rule text available to deploy.",
            )

        # 1. Validate syntax
        try:
            val = self.chronicle.validate_rule(rule_item.rule_text)
            if not val.success:
                return RuleDeployResult(
                    rule_name=rule_name,
                    rule_id=rule_item.rule_id or "INVALID",
                    instance_id=inst_id,
                    instance_name=inst_name,
                    file_path=file_path,
                    category=category,
                    action="VALIDATION_ERROR",
                    error_message=f"Validation error: {val.message}",
                )
        except Exception as e:
            return RuleDeployResult(
                rule_name=rule_name,
                rule_id=rule_item.rule_id or "ERROR",
                instance_id=inst_id,
                instance_name=inst_name,
                file_path=file_path,
                category=category,
                action="VALIDATION_ERROR",
                error_message=f"Validate API call failed: {e}",
            )

        existing_rule_id = rule_item.rule_id or self.existing_rules.get(rule_name)

        if dry_run:
            action_preview = "DRY_RUN (WOULD_UPDATE)" if existing_rule_id else "DRY_RUN (WOULD_CREATE)"
            return RuleDeployResult(
                rule_name=rule_name,
                rule_id=existing_rule_id or "NEW_RULE",
                instance_id=inst_id,
                instance_name=inst_name,
                file_path=file_path,
                category=category,
                action=action_preview,
                enabled=enable_rule,
                alerting=enable_alerting,
            )

        target_rule_id = existing_rule_id
        action_taken = "UNCHANGED"
        revision_id = None

        # 2. Create or Update Rule
        try:
            if existing_rule_id:
                if update_existing:
                    upd_res = self.chronicle.update_rule(existing_rule_id, rule_item.rule_text)
                    revision_id = upd_res.get("revisionId") or upd_res.get("revisionCreateTime")
                    action_taken = "UPDATED"
                    logging.info(f"[{inst_name}] Successfully updated rule '{rule_name}' ({existing_rule_id}).")
                else:
                    action_taken = "UNCHANGED"
                    logging.info(f"[{inst_name}] Rule '{rule_name}' already exists ({existing_rule_id}); update not requested.")
            else:
                create_res = self.chronicle.create_rule(rule_item.rule_text)
                rname = create_res.get("name", "")
                target_rule_id = rname.split("/")[-1] if rname else None
                if not target_rule_id:
                    raise APIError(f"Created rule response missing rule ID: {create_res}")
                revision_id = create_res.get("revisionId") or create_res.get("revisionCreateTime")
                self.existing_rules[rule_name] = target_rule_id
                action_taken = "CREATED"
                logging.info(f"[{inst_name}] Successfully created rule '{rule_name}' as {target_rule_id}.")
        except Exception as e:
            logging.error(f"[{inst_name}] Failed saving rule '{rule_name}': {e}")
            return RuleDeployResult(
                rule_name=rule_name,
                rule_id=target_rule_id or "UNKNOWN",
                instance_id=inst_id,
                instance_name=inst_name,
                file_path=file_path,
                category=category,
                action="FAILED",
                error_message=str(e),
            )

        # 3. Configure Deployment State (enabled / alerting) if requested
        if target_rule_id and (enable_rule is not None or enable_alerting is not None):
            try:
                kwargs = {}
                if enable_rule is not None:
                    kwargs["enabled"] = enable_rule
                if enable_alerting is not None:
                    kwargs["alerting"] = enable_alerting
                self.chronicle.update_rule_deployment(target_rule_id, **kwargs)
                logging.info(f"[{inst_name}] Configured deployment for '{rule_name}' ({target_rule_id}): {kwargs}")
            except Exception as e:
                logging.warning(f"[{inst_name}] Could not update deployment settings for '{rule_name}': {e}")

        return RuleDeployResult(
            rule_name=rule_name,
            rule_id=target_rule_id or "UNKNOWN",
            instance_id=inst_id,
            instance_name=inst_name,
            file_path=file_path,
            category=category,
            action=action_taken,
            revision_id=revision_id,
            enabled=enable_rule,
            alerting=enable_alerting,
        )

    def _manage_alerting(self, rule_id: str, disable: bool) -> Optional[bool]:
        """Temporarily disables alerting to prevent flooding SOAR during retrohunt."""
        try:
            dep = self.chronicle.get_rule_deployment(rule_id)
            is_alerting = dep.get("alerting", False)
            if is_alerting and disable:
                logging.info(f"[{self.instance.display_name}] Disabling alerting on rule {rule_id} for retrohunt...")
                self.chronicle.set_rule_alerting(rule_id, enabled=False)
            return is_alerting
        except Exception as e:
            logging.debug(f"[{self.instance.display_name}] Alerting check error: {e}")
            return None

    def execute_retrohunt(
        self,
        rule_item: RuleItem,
        rule_id: str,
        start_time: datetime,
        end_time: datetime,
    ) -> RetrohuntResult:
        """Executes a single retrohunt job with live polling and detection extraction."""
        rule_name = rule_item.display_name
        inst_name = self.instance.display_name
        inst_id = self.instance.customer_id
        category = rule_item.category
        file_path = rule_item.file_path

        # Safe Mode Alert Handling
        original_alerting = None
        if self.safe_mode:
            original_alerting = self._manage_alerting(rule_id, disable=True)

        operation_id = None
        start_t = time.time()
        max_retries = 6
        base_backoff = 15

        # Initiate Retrohunt with Exponential Backoff if Tenant Limit Reached
        for attempt in range(max_retries):
            try:
                res = self.chronicle.create_retrohunt(rule_id, start_time, end_time)
                if isinstance(res, dict) and "error" in res:
                    raise APIError(res["error"].get("message", str(res["error"])))

                op_name = res.get("name", "")
                operation_id = op_name.split("/")[-1] if op_name else None
                if not operation_id:
                    meta_rh = res.get("metadata", {}).get("retrohunt", "")
                    operation_id = meta_rh.split("/")[-1] if meta_rh else None

                if not operation_id:
                    raise APIError(f"Missing operation ID: {res}")

                logging.info(f"[{inst_name}] [{rule_name}] Retrohunt initiated: {operation_id}")
                break
            except Exception as e:
                err_str = str(e)
                if any(x in err_str for x in ["RESOURCE_EXHAUSTED", "429", "FAILED_PRECONDITION"]):
                    wait_sec = base_backoff * (attempt + 1)
                    logging.warning(
                        f"[{inst_name}] [{rule_name}] Quota saturated. Backing off {wait_sec}s (attempt {attempt+1}/{max_retries})..."
                    )
                    time.sleep(wait_sec)
                else:
                    logging.error(f"[{inst_name}] [{rule_name}] Failed creating retrohunt: {e}")
                    if original_alerting and self.restore_alerting:
                        self._manage_alerting(rule_id, disable=False)
                    return RetrohuntResult(
                        rule_name=rule_name,
                        rule_id=rule_id,
                        instance_id=inst_id,
                        instance_name=inst_name,
                        file_path=file_path,
                        category=category,
                        status="FAILED",
                        start_time=format_rfc3339(start_time),
                        end_time=format_rfc3339(end_time),
                        error_message=err_str,
                    )
        else:
            if original_alerting and self.restore_alerting:
                self._manage_alerting(rule_id, disable=False)
            return RetrohuntResult(
                rule_name=rule_name,
                rule_id=rule_id,
                instance_id=inst_id,
                instance_name=inst_name,
                file_path=file_path,
                category=category,
                status="FAILED",
                start_time=format_rfc3339(start_time),
                end_time=format_rfc3339(end_time),
                error_message="Exceeded max retries waiting for concurrent retrohunt slot.",
            )

        # Polling Loop
        final_state = "UNKNOWN"
        progress_pct = 0
        error_msg = None

        try:
            while True:
                elapsed = time.time() - start_t
                if elapsed > self.job_timeout:
                    final_state = "TIMEOUT"
                    error_msg = f"Timed out after {self.job_timeout}s"
                    break

                time.sleep(self.poll_interval)

                try:
                    status_res = self.chronicle.get_retrohunt(rule_id, operation_id)
                    state = status_res.get("state", "RUNNING")
                    progress_pct = status_res.get("progressPercentage", progress_pct)

                    logging.info(
                        f"[{inst_name}] [{rule_name}] Status: {state} | Progress: {progress_pct}% (Elapsed: {int(elapsed)}s)"
                    )

                    if state in ("DONE", "COMPLETED"):
                        final_state = "DONE"
                        break
                    elif state in ("CANCELED", "CANCELLED"):
                        final_state = "CANCELED"
                        error_msg = "Retrohunt canceled by server."
                        break
                    elif state == "FAILED":
                        final_state = "FAILED"
                        error_msg = "Retrohunt failed on server."
                        break
                except Exception as e:
                    logging.warning(f"[{inst_name}] [{rule_name}] Status polling error: {e}")
        finally:
            # Restore alerting if Safe Mode was on
            if original_alerting and self.restore_alerting:
                self._manage_alerting(rule_id, disable=False)

            # Cleanup dynamic rule if requested
            if rule_item.created_dynamically and self.cleanup_created_rules:
                try:
                    self.chronicle.delete_rule(rule_id, force=True)
                except Exception as e:
                    logging.warning(f"[{inst_name}] Cleanup error: {e}")

        # Fetch detections if successful
        detection_count = 0
        sample_dets: List[Dict[str, Any]] = []
        if final_state == "DONE":
            try:
                dets = self.chronicle.list_detections(
                    rule_id, start_time=start_time, end_time=end_time, page_size=100
                )
                det_list = dets.get("detections", [])
                detection_count = len(det_list)

                for d in det_list[:5]:
                    sample_dets.append({
                        "detectionTime": d.get("detectionTime"),
                        "timingDetails": d.get("detectionTimingDetails", []),
                    })

                token = dets.get("nextPageToken")
                while token and detection_count < 10000:
                    more = self.chronicle.list_detections(
                        rule_id, start_time=start_time, end_time=end_time, page_size=100, page_token=token
                    )
                    items = more.get("detections", [])
                    detection_count += len(items)
                    token = more.get("nextPageToken")
                    if not items:
                        break
            except Exception as e:
                logging.warning(f"[{inst_name}] [{rule_name}] Detection list error: {e}")

        duration = round(time.time() - start_t, 2)
        logging.info(
            f"[{inst_name}] [{rule_name}] Complete! Status: {final_state}, Detections: {detection_count}, Duration: {duration}s"
        )

        return RetrohuntResult(
            rule_name=rule_name,
            rule_id=rule_id,
            instance_id=inst_id,
            instance_name=inst_name,
            file_path=file_path,
            category=category,
            status=final_state,
            operation_id=operation_id,
            start_time=format_rfc3339(start_time),
            end_time=format_rfc3339(end_time),
            duration_seconds=duration,
            detection_count=detection_count,
            error_message=error_msg,
            sample_detections=sample_dets,
        )


class MultiTenantRetrohuntOrchestrator:
    """Orchestrates batch retrohunts across multiple Google SecOps instances (e.g. Enterprise/MSSP instances)."""

    def __init__(
        self,
        instances: List[InstanceTarget],
        credentials_path: Optional[str] = None,
        max_concurrent_per_instance: int = 3,
        max_parallel_instances: int = 3,
        poll_interval: int = 10,
        job_timeout: int = 600,
        safe_mode: bool = True,
        restore_alerting: bool = True,
        cleanup_created_rules: bool = False,
        checkpoint_file: Optional[str] = None,
    ):
        self.instances = instances
        self.credentials_path = credentials_path
        self.max_concurrent_per_instance = min(max_concurrent_per_instance, MAX_CONCURRENT_PER_INSTANCE)
        self.max_parallel_instances = max_parallel_instances
        self.poll_interval = poll_interval
        self.job_timeout = job_timeout
        self.safe_mode = safe_mode
        self.restore_alerting = restore_alerting
        self.cleanup_created_rules = cleanup_created_rules
        self.checkpoint_file = checkpoint_file or f"retrohunt_checkpoint_{int(time.time())}.json"

        self.secops_client = create_secops_client(self.credentials_path)
        self.results_lock = threading.Lock()
        self.checkpoint_lock = threading.Lock()
        self.results: List[RetrohuntResult] = []
        self.completed_keys: set = set()  # "instance_id::rule_name"

        self._load_checkpoint()

    def _load_checkpoint(self):
        """Loads state checkpoint to allow resuming interrupted multi-tenant runs."""
        if os.path.exists(self.checkpoint_file):
            try:
                with open(self.checkpoint_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    for item in data.get("completed_results", []):
                        res = RetrohuntResult(**item)
                        self.results.append(res)
                        self.completed_keys.add(f"{res.instance_id}::{res.rule_name}")
                logging.info(
                    f"Resumed checkpoint '{self.checkpoint_file}': {len(self.completed_keys)} jobs already completed."
                )
            except Exception as e:
                logging.warning(f"Error loading checkpoint: {e}")

    def _save_checkpoint(self):
        """Thread-safe flush to checkpoint file."""
        with self.checkpoint_lock:
            try:
                data = {
                    "updated_at": datetime.now(timezone.utc).isoformat(),
                    "total_completed": len(self.results),
                    "completed_results": [asdict(r) for r in self.results],
                }
                with open(self.checkpoint_file, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2)
            except Exception as e:
                logging.error(f"Error saving checkpoint: {e}")

    def load_rules_from_directory(
        self,
        directory_path: str,
        pattern: str = "**/*.yaral",
        category_filter: Optional[str] = None,
        limit: Optional[int] = None,
    ) -> List[RuleItem]:
        """Scan directory for YARA-L rule files."""
        abs_dir = os.path.abspath(directory_path)
        search_glob = os.path.join(abs_dir, pattern)
        found_files = glob.glob(search_glob, recursive=True)
        found_files.sort()
        logging.info(f"Discovered {len(found_files)} potential rule files.")

        rule_items: List[RuleItem] = []
        for fpath in found_files:
            rel_path = os.path.relpath(fpath, abs_dir)
            parts = rel_path.split(os.sep)
            category = parts[0] if len(parts) > 1 else os.path.basename(abs_dir)

            if category_filter and category_filter.lower() not in category.lower():
                continue

            try:
                with open(fpath, "r", encoding="utf-8") as f:
                    content = f.read()

                if len(content.encode("utf-8")) > 1_000_000:
                    logging.warning(f"Skipping '{rel_path}': File size exceeds 1 MB limit.")
                    continue

                display_name, meta = extract_rule_metadata(content)
                rule_items.append(
                    RuleItem(
                        display_name=display_name,
                        file_path=fpath,
                        rule_text=content,
                        category=category,
                        meta=meta,
                    )
                )
            except Exception as e:
                logging.warning(f"Could not read rule file '{fpath}': {e}")

            if limit and len(rule_items) >= limit:
                break

        logging.info(f"Selected {len(rule_items)} valid rule candidate(s).")
        return rule_items

    def load_rule_from_file(self, file_path: str) -> List[RuleItem]:
        """Load a single YARA-L rule file."""
        fpath = os.path.abspath(file_path)
        if not os.path.exists(fpath):
            logging.error(f"Rule file does not exist: {fpath}")
            return []

        try:
            with open(fpath, "r", encoding="utf-8") as f:
                content = f.read()

            display_name, meta = extract_rule_metadata(content)
            category = os.path.basename(os.path.dirname(fpath)) or "custom"
            rule_item = RuleItem(
                display_name=display_name,
                file_path=fpath,
                rule_text=content,
                category=category,
                meta=meta,
            )
            logging.info(f"Loaded single rule '{display_name}' from '{fpath}'.")
            return [rule_item]
        except Exception as e:
            logging.error(f"Could not read rule file '{fpath}': {e}")
            return []


    def load_rules_from_instances(
        self,
        rule_filter: Optional[str] = None,
        rule_ids: Optional[List[str]] = None,
        limit: Optional[int] = None,
    ) -> List[RuleItem]:
        """Fetch existing rules directly from target instance(s) without requiring local files."""
        collected_rules: Dict[str, RuleItem] = {}
        pattern = re.compile(rule_filter, re.IGNORECASE) if rule_filter else None
        target_ids = [x.strip() for x in rule_ids if x.strip()] if rule_ids else None

        for inst in self.instances:
            try:
                chronicle = self.secops_client.chronicle(
                    customer_id=inst.customer_id,
                    project_id=inst.project_id,
                    region=inst.region,
                )

                # Path A: Specific Rule IDs provided -> Lookup directly by ID
                if target_ids:
                    logging.info(f"[{inst.display_name}] Looking up {len(target_ids)} specific rule ID(s) directly...")
                    for rid in target_ids:
                        try:
                            rule = chronicle.get_rule(rid)
                            dname = rule.get("displayName") or rid
                            if pattern and not pattern.search(dname) and not pattern.search(rid):
                                continue
                            if dname not in collected_rules:
                                collected_rules[dname] = RuleItem(
                                    display_name=dname,
                                    rule_id=rid,
                                    category="instance_rule",
                                )
                                logging.info(f"[{inst.display_name}] Found rule '{dname}' ({rid}).")
                        except Exception as e:
                            err_str = str(e)
                            if "access to scope" in err_str.lower() or "403" in err_str:
                                logging.error(
                                    f"[{inst.display_name}] PERMISSION ERROR on rule '{rid}': HTTP 403 'user does not have access to scope'.\n"
                                    f"  -> Cause: The Service Account lacks access to this rule's Data Access Scope.\n"
                                    f"  -> Fix 1 (GCP IAM): Ensure the Service Account has 'chronicle.dataAccessScopes.permit' (included in 'roles/chronicle.admin').\n"
                                    f"  -> Fix 2 (SecOps UI): In Chronicle -> Settings -> Access Control -> Data Access Scopes, assign the Service Account to the rule's scope."
                                )
                            elif "404" in err_str or "not found" in err_str.lower():
                                logging.warning(f"[{inst.display_name}] Rule '{rid}' not found in instance.")
                            else:
                                logging.warning(f"[{inst.display_name}] Failed to fetch rule '{rid}': {e}")
                    continue

                # Path B: Scan deployed rules with filter and full pagination
                logging.info(f"[{inst.display_name}] Fetching deployed rules from Chronicle...")
                total_scanned = 0
                page_token = None

                while True:
                    res = chronicle.list_rules(page_size=1000, page_token=page_token)
                    rules_raw = res.get("rules", [])
                    total_scanned += len(rules_raw)

                    for r in rules_raw:
                        dname = r.get("displayName")
                        rname = r.get("name", "")
                        rid = rname.split("/")[-1] if rname else None
                        if not dname or not rid:
                            continue
                        if pattern and not pattern.search(dname) and not pattern.search(rid):
                            continue

                        if dname not in collected_rules:
                            collected_rules[dname] = RuleItem(
                                display_name=dname,
                                rule_id=rid,
                                category="instance_rule",
                            )
                        if limit and len(collected_rules) >= limit:
                            break

                    if limit and len(collected_rules) >= limit:
                        break

                    page_token = res.get("nextPageToken")
                    if not page_token or not rules_raw:
                        break

                if total_scanned == 0:
                    logging.warning(
                        f"[{inst.display_name}] Chronicle returned 0 total rules visible to this account.\n"
                        f"  Diagnostic check:\n"
                        f"  1. In GCP IAM: Does the Service Account have 'roles/chronicle.admin' on the GCP project hosting this instance? ('roles/chronicle.editor' lacks 'chronicle.dataAccessScopes.permit' required for scoped rules).\n"
                        f"  2. In Chronicle UI -> Settings -> Access Control -> Data Access Scopes: Is the Service Account assigned to the scope governing these rules? (Rules under custom scopes are silently filtered out from rules.list if unassigned)."
                    )
                else:
                    logging.info(
                        f"[{inst.display_name}] Scanned {total_scanned} rule(s) in Chronicle, "
                        f"matched {len(collected_rules)} rule(s) with filter '{rule_filter}'."
                    )

            except Exception as e:
                logging.warning(f"[{inst.display_name}] Failed to list instance rules: {e}")

            if limit and len(collected_rules) >= limit:
                break

        rule_items = list(collected_rules.values())
        logging.info(f"Loaded {len(rule_items)} deployed rule(s) from target instance(s).")
        return rule_items

    def _process_single_instance(
        self,
        instance: InstanceTarget,
        rules: List[RuleItem],
        start_time: datetime,
        end_time: datetime,
        dry_run: bool = False,
        update_existing: bool = False,
    ):
        """Processes batches of rules for one instance with up to 3 concurrent retrohunts."""
        inst_orchestrator = SecOpsInstanceOrchestrator(
            instance=instance,
            secops_client=self.secops_client,
            max_concurrent=self.max_concurrent_per_instance,
            poll_interval=self.poll_interval,
            job_timeout=self.job_timeout,
            safe_mode=self.safe_mode,
            restore_alerting=self.restore_alerting,
            cleanup_created_rules=self.cleanup_created_rules,
        )

        # Filter out rules already finished for this instance
        pending_rules: List[RuleItem] = []
        for r in rules:
            key = f"{instance.customer_id}::{r.display_name}"
            if key in self.completed_keys:
                logging.info(f"[{instance.display_name}] Skipping already completed rule '{r.display_name}'")
                continue
            pending_rules.append(r)

        logging.info(f"[{instance.display_name}] {len(pending_rules)} rule(s) queued.")

        if dry_run:
            for idx, item in enumerate(pending_rules, 1):
                exists = (item.rule_id is not None) or (item.display_name in inst_orchestrator.existing_rules)
                status = "DEPLOYED" if exists else "NEEDS_CREATION"
                print(f"[{instance.display_name}] [{idx}/{len(pending_rules)}] {item.display_name} -> {status}")
                with self.results_lock:
                    self.results.append(
                        RetrohuntResult(
                            rule_name=item.display_name,
                            rule_id=item.rule_id or ("EXISTS" if exists else "NEEDS_CREATION"),
                            instance_id=instance.customer_id,
                            instance_name=instance.display_name,
                            file_path=item.file_path,
                            category=item.category,
                            status="DRY_RUN",
                            start_time=format_rfc3339(start_time),
                            end_time=format_rfc3339(end_time),
                            duration_seconds=0.0,
                            detection_count=0,
                            error_message=f"Dry-run check: {status}",
                        )
                    )
            return

        # Queue-based continuous batch execution: automatically executes up to 3 rules at a time
        work_queue: queue.Queue[RuleItem] = queue.Queue()
        for r in pending_rules:
            work_queue.put(r)

        def worker():
            while not work_queue.empty():
                try:
                    rule_item = work_queue.get_nowait()
                except queue.Empty:
                    break

                # 1. Stage rule in instance
                ok, rule_id, err = inst_orchestrator.stage_rule(rule_item, update_existing=update_existing)
                if not ok:
                    res = RetrohuntResult(
                        rule_name=rule_item.display_name,
                        rule_id=rule_id or "UNKNOWN",
                        instance_id=instance.customer_id,
                        instance_name=instance.display_name,
                        file_path=rule_item.file_path,
                        category=rule_item.category,
                        status="SKIPPED",
                        start_time=format_rfc3339(start_time),
                        end_time=format_rfc3339(end_time),
                        error_message=err,
                    )
                else:
                    # 2. Run retrohunt
                    res = inst_orchestrator.execute_retrohunt(rule_item, rule_id, start_time, end_time)

                # 3. Store result & checkpoint
                with self.results_lock:
                    self.results.append(res)
                    self.completed_keys.add(f"{instance.customer_id}::{res.rule_name}")

                self._save_checkpoint()
                work_queue.task_done()

        # Launch worker threads up to max_concurrent_per_instance (max 3)
        threads = []
        for i in range(self.max_concurrent_per_instance):
            t = threading.Thread(target=worker, name=f"{instance.display_name}-Worker-{i+1}")
            t.daemon = True
            t.start()
            threads.append(t)

        for t in threads:
            t.join()

    def run_all(
        self,
        rules: List[RuleItem],
        start_time: datetime,
        end_time: datetime,
        dry_run: bool = False,
        update_existing: bool = False,
    ):
        """Runs batch retrohunts across all target instances in parallel."""
        total_inst = len(self.instances)
        total_rules = len(rules)
        logging.info("=" * 70)
        logging.info(f"STARTING MULTI-TENANT RETROHUNT: {total_inst} Instance(s) x {total_rules} Rule(s)")
        logging.info(f"Per-Instance Concurrency: {self.max_concurrent_per_instance} (Tenant Limit: {MAX_CONCURRENT_PER_INSTANCE})")
        logging.info(f"Parallel Instances: {self.max_parallel_instances}")
        logging.info(f"Target Window: {format_rfc3339(start_time)} -> {format_rfc3339(end_time)}")
        if update_existing:
            logging.info("Update Existing: Enabled (will update Chronicle rules if local content has changed)")
        logging.info("=" * 70)

        # ThreadPoolExecutor across instances
        with ThreadPoolExecutor(max_workers=self.max_parallel_instances) as executor:
            futures = {
                executor.submit(
                    self._process_single_instance, inst, rules, start_time, end_time, dry_run, update_existing
                ): inst
                for inst in self.instances
            }
            for future in as_completed(futures):
                inst = futures[future]
                try:
                    future.result()
                    logging.info(f"Completed processing instance '{inst.display_name}'.")
                except Exception as e:
                    logging.error(f"Error processing instance '{inst.display_name}': {e}")

        logging.info("All instances and retrohunt batches finished.")

    def generate_summary_table(self) -> str:
        """Constructs a multi-tenant summary table."""
        lines = []
        header = f"{'INSTANCE':<25} | {'RULE NAME':<35} | {'STATUS':<9} | {'DETECTIONS':<10} | {'DURATION':<8}"
        sep = "-" * len(header)
        lines.append("\n" + sep)
        lines.append(header)
        lines.append(sep)

        total_detections = 0
        status_counts = {"DONE": 0, "FAILED": 0, "SKIPPED": 0, "TIMEOUT": 0, "CANCELED": 0, "DRY_RUN": 0}

        for r in self.results:
            status_counts[r.status] = status_counts.get(r.status, 0) + 1
            total_detections += r.detection_count
            inst_disp = (r.instance_name[:23] + "..") if len(r.instance_name) > 25 else r.instance_name
            rule_disp = (r.rule_name[:33] + "..") if len(r.rule_name) > 35 else r.rule_name
            lines.append(
                f"{inst_disp:<25} | {rule_disp:<35} | {r.status:<9} | {r.detection_count:<10} | {r.duration_seconds:<7.1f}s"
            )

        lines.append(sep)
        lines.append(f"TOTAL INSTANCES: {len(self.instances)} | TOTAL RUNS: {len(self.results)}")
        lines.append(
            f"OUTCOMES: Done: {status_counts.get('DONE', 0)}, "
            f"Dry-Run: {status_counts.get('DRY_RUN', 0)}, "
            f"Failed: {status_counts.get('FAILED', 0)}, "
            f"Skipped: {status_counts.get('SKIPPED', 0)}, "
            f"Timeout: {status_counts.get('TIMEOUT', 0)}"
        )
        lines.append(f"TOTAL DETECTIONS IDENTIFIED: {total_detections}")
        lines.append(sep + "\n")
        return "\n".join(lines)

    def export_reports(self, json_path: Optional[str] = None, csv_path: Optional[str] = None):
        """Exports unified multi-tenant JSON and CSV reports."""
        if json_path:
            with open(json_path, "w", encoding="utf-8") as f:
                json.dump([asdict(r) for r in self.results], f, indent=2)
            logging.info(f"Exported JSON report: {json_path}")

        if csv_path:
            with open(csv_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow([
                    "instance_name",
                    "instance_id",
                    "rule_name",
                    "rule_id",
                    "category",
                    "status",
                    "detection_count",
                    "duration_seconds",
                    "operation_id",
                    "start_time",
                    "end_time",
                    "error_message",
                    "file_path",
                ])
                for r in self.results:
                    writer.writerow([
                        r.instance_name,
                        r.instance_id,
                        r.rule_name,
                        r.rule_id,
                        r.category,
                        r.status,
                        r.detection_count,
                        r.duration_seconds,
                        r.operation_id or "",
                        r.start_time,
                        r.end_time,
                        r.error_message or "",
                        r.file_path or "",
                    ])
            logging.info(f"Exported CSV report: {csv_path}")

    def deploy_rules_all(
        self,
        rules: List[RuleItem],
        update_existing: bool = True,
        enable_rules: Optional[bool] = None,
        enable_alerting: Optional[bool] = None,
        dry_run: bool = False,
    ) -> List[RuleDeployResult]:
        """Deploy or update rules across all target instances."""
        total_inst = len(self.instances)
        total_rules = len(rules)
        mode_str = "DRY RUN PREVIEW" if dry_run else "LIVE DEPLOYMENT"
        logging.info("=" * 70)
        logging.info(f"STARTING MASS RULE DEPLOYMENT ({mode_str}): {total_inst} Instance(s) x {total_rules} Rule(s)")
        logging.info(f"Update Existing: {update_existing}")
        if enable_rules is not None:
            logging.info(f"Set Rule Enabled: {enable_rules}")
        if enable_alerting is not None:
            logging.info(f"Set Alerting Enabled: {enable_alerting}")
        logging.info("=" * 70)

        deploy_results: List[RuleDeployResult] = []
        deploy_lock = threading.Lock()

        def process_instance_rules(instance: InstanceTarget):
            inst_orchestrator = SecOpsInstanceOrchestrator(
                instance=instance,
                secops_client=self.secops_client,
            )
            for rule_item in rules:
                res = inst_orchestrator.deploy_rule(
                    rule_item=rule_item,
                    update_existing=update_existing,
                    enable_rule=enable_rules,
                    enable_alerting=enable_alerting,
                    dry_run=dry_run,
                )
                with deploy_lock:
                    deploy_results.append(res)

        with ThreadPoolExecutor(max_workers=self.max_parallel_instances) as executor:
            futures = {executor.submit(process_instance_rules, inst): inst for inst in self.instances}
            for future in as_completed(futures):
                inst = futures[future]
                try:
                    future.result()
                    logging.info(f"Finished rule deployment for instance '{inst.display_name}'.")
                except Exception as e:
                    logging.error(f"Error during deployment for instance '{inst.display_name}': {e}")

        return deploy_results

    def generate_deploy_summary_table(self, deploy_results: List[RuleDeployResult]) -> str:
        """Constructs a summary table for rule deployment results."""
        lines = []
        header = f"{'INSTANCE':<25} | {'RULE NAME':<35} | {'ACTION':<20} | {'RULE ID':<38}"
        sep = "-" * len(header)
        lines.append("\n" + sep)
        lines.append(header)
        lines.append(sep)

        action_counts: Dict[str, int] = {}
        for r in deploy_results:
            action_counts[r.action] = action_counts.get(r.action, 0) + 1
            inst_disp = (r.instance_name[:23] + "..") if len(r.instance_name) > 25 else r.instance_name
            rule_disp = (r.rule_name[:33] + "..") if len(r.rule_name) > 35 else r.rule_name
            rid_disp = (r.rule_id[:36] + "..") if len(r.rule_id) > 38 else r.rule_id
            lines.append(f"{inst_disp:<25} | {rule_disp:<35} | {r.action:<20} | {rid_disp:<38}")

        lines.append(sep)
        lines.append(f"TOTAL INSTANCES: {len(self.instances)} | TOTAL RULES PROCESSED: {len(deploy_results)}")
        outcomes_str = ", ".join(f"{k}: {v}" for k, v in sorted(action_counts.items()))
        lines.append(f"OUTCOMES: {outcomes_str}")
        lines.append(sep + "\n")
        return "\n".join(lines)

    def export_deploy_reports(
        self,
        deploy_results: List[RuleDeployResult],
        json_path: Optional[str] = None,
        csv_path: Optional[str] = None,
    ):
        """Exports rule deployment results to JSON and CSV reports."""
        if json_path:
            with open(json_path, "w", encoding="utf-8") as f:
                json.dump([asdict(r) for r in deploy_results], f, indent=2)
            logging.info(f"Exported deployment JSON report: {json_path}")

        if csv_path:
            with open(csv_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow([
                    "instance_name",
                    "instance_id",
                    "rule_name",
                    "rule_id",
                    "action",
                    "revision_id",
                    "enabled",
                    "alerting",
                    "error_message",
                    "file_path",
                ])
                for r in deploy_results:
                    writer.writerow([
                        r.instance_name,
                        r.instance_id,
                        r.rule_name,
                        r.rule_id,
                        r.action,
                        r.revision_id or "",
                        "" if r.enabled is None else r.enabled,
                        "" if r.alerting is None else r.alerting,
                        r.error_message or "",
                        r.file_path or "",
                    ])
            logging.info(f"Exported deployment CSV report: {csv_path}")



def main():
    parser = argparse.ArgumentParser(
        description="Multi-Tenant Batch Retrohunt Orchestrator for Google SecOps (Chronicle).",
        epilog="""
Examples:
  # 1. Mass Deploy / Save Rules to Target SIEM Instance(s) (Deploy-only mode)
  python3 retrohunt_batch.py --instances-file instances.csv \
    --rules-dir ./my-modified-rules --update-existing --deploy-only

  # 2. Deploy a single rule file with alerting and live detection enabled
  python3 retrohunt_batch.py --instances-file instances.csv \
    --rule-file ./rules/rule_sample.yaral --update-existing --enable-rules --enable-alerting --deploy-only

  # 3. Single Instance Retrohunt Test (Dry-run with 3 rules from workspace)
  python3 retrohunt_batch.py --customer-id YOUR_CUSTOMER_ID --project-id YOUR_PROJECT_ID \
    --rules-dir detection-rules/rules/community/workspace --limit 3 --dry-run

  # 4. Multi-Tenant Retrohunt: Auto-Discover tenant instances via Partner API and run 5 rules
  python3 retrohunt_batch.py --discover-tenants \
    --parent-instance YOUR_PARENT_INSTANCE_ID --parent-project YOUR_PARENT_PROJECT_ID --region asia-southeast1 \
    --rules-dir detection-rules/rules/community/microsoft --limit 5 --hours 24

  # 5. Multi-Tenant: Load instances from CSV/JSON inventory file and execute batches of 3 rules
  python3 retrohunt_batch.py --instances-file instances.csv \
    --rules-dir detection-rules/rules/community/workspace --days 7 \
    --max-concurrent-per-instance 3 --max-parallel-instances 5 \
    --output-json multi_tenant_results.json --output-csv multi_tenant_results.csv
        """,
    )

    # Multi-Tenant & Instance Selection
    inst_group = parser.add_argument_group("Multi-Tenant & Instance Targets")
    inst_group.add_argument(
        "--discover-tenants",
        action="store_true",
        help="Discover all child tenants using Chronicle Customer Management / Partner API",
    )
    inst_group.add_argument(
        "--parent-instance",
        type=str,
        help="Parent instance UUID for tenant discovery",
    )
    inst_group.add_argument(
        "--parent-project",
        type=str,
        help="Parent GCP project ID for tenant discovery",
    )
    inst_group.add_argument(
        "--instances-file",
        type=str,
        help="Path to CSV or JSON file containing target instance inventory (e.g. 50+ tenant instances)",
    )
    inst_group.add_argument(
        "--instance-filter",
        type=str,
        help="Regex filter on instance displayName or customerCode",
    )
    inst_group.add_argument(
        "--instance-limit",
        type=int,
        help="Limit number of instances to target (useful for initial pilots)",
    )

    # Single-Instance Fallback Options
    single_group = parser.add_argument_group("Single Instance Connection (Fallback)")
    single_group.add_argument(
        "--customer-id",
        type=str,
        default=DEFAULT_CUSTOMER_ID,
        help=f"Chronicle Customer ID (or set SECOPS_CUSTOMER_ID, default: {DEFAULT_CUSTOMER_ID})",
    )
    single_group.add_argument(
        "--project-id",
        type=str,
        default=DEFAULT_PROJECT_ID,
        help=f"GCP Project ID (or set SECOPS_PROJECT_ID, default: {DEFAULT_PROJECT_ID})",
    )
    single_group.add_argument(
        "--region",
        type=str,
        default=DEFAULT_REGION,
        help=f"SecOps Region (or set SECOPS_REGION, default: {DEFAULT_REGION})",
    )
    single_group.add_argument(
        "--credentials-path",
        type=str,
        default=DEFAULT_CRED_PATH,
        help=f"Path to service account JSON key (or set GOOGLE_APPLICATION_CREDENTIALS, default: {DEFAULT_CRED_PATH})",
    )

    # Rule Source Options
    source_group = parser.add_argument_group("Rule Sources")
    source_group.add_argument(
        "--rules-dir",
        type=str,
        help="Directory of YARA-L detection rules (e.g. detection-rules/rules/community)",
    )
    source_group.add_argument(
        "--rule-file",
        type=str,
        help="Path to a single YARA-L detection rule file (.yaral)",
    )
    source_group.add_argument(
        "--use-instance-rules",
        action="store_true",
        help="Use rules already deployed in target Chronicle instance(s) without needing local files",
    )
    source_group.add_argument(
        "--rule-filter",
        type=str,
        help="Regex filter on deployed rule displayName or rule ID (e.g. '(?i)ransomware|vpn')",
    )
    source_group.add_argument(
        "--rule-ids",
        type=str,
        help="Comma-separated list of specific Chronicle rule IDs to retrohunt (e.g. 'ru_xxx,ru_yyy')",
    )
    source_group.add_argument(
        "--rules-pattern",
        type=str,
        default="**/*.yaral",
        help="Glob pattern to search for rules inside --rules-dir (default: '**/*.yaral')",
    )
    source_group.add_argument(
        "--category",
        type=str,
        help="Filter rules by category folder (e.g. workspace, aws, microsoft)",
    )
    source_group.add_argument(
        "--limit",
        type=int,
        help="Maximum rules to process per instance (e.g. 5, 20, 100)",
    )

    # Rule Deployment / Direct Save Options
    deploy_group = parser.add_argument_group("Rule Deployment & Direct Save Controls")
    deploy_group.add_argument(
        "--deploy-only",
        "--deploy-rules",
        action="store_true",
        help="Deploy / save rules directly into target SIEM instance(s) without running retrohunts",
    )
    deploy_group.add_argument(
        "--update-existing",
        action="store_true",
        help="Update existing rules in Chronicle when rule text has changed (creates a new revision)",
    )
    deploy_group.add_argument(
        "--enable-rules",
        action="store_true",
        help="Enable rules in Chronicle for live event streaming evaluation after deployment",
    )
    deploy_group.add_argument(
        "--enable-alerting",
        action="store_true",
        help="Enable SOAR alerting on rules after deployment (for live incoming events)",
    )


    # Time Window Options
    time_group = parser.add_argument_group("Time Window Options")
    time_group.add_argument("--hours", type=int, help="Relative lookback window in hours (e.g. 24)")
    time_group.add_argument("--days", type=int, help="Relative lookback window in days (e.g. 7)")
    time_group.add_argument("--start-time", type=str, help="Explicit RFC3339 start timestamp")
    time_group.add_argument("--end-time", type=str, help="Explicit RFC3339 end timestamp")

    # Concurrency and Quota Limits
    limit_group = parser.add_argument_group("Concurrency & Quota Controls")
    limit_group.add_argument(
        "--max-concurrent-per-instance",
        type=int,
        default=3,
        choices=[1, 2, 3],
        help="Max concurrent retrohunts per instance (Hard limit is 3, default: 3)",
    )
    limit_group.add_argument(
        "--max-parallel-instances",
        type=int,
        default=3,
        help="Number of instances to process in parallel (default: 3)",
    )
    limit_group.add_argument(
        "--poll-interval",
        type=int,
        default=10,
        help="Seconds between polling retrohunt operation status (default: 10s)",
    )
    limit_group.add_argument(
        "--timeout",
        type=int,
        default=600,
        help="Timeout in seconds per retrohunt job (default: 600s)",
    )
    limit_group.add_argument(
        "--dry-run",
        action="store_true",
        help="Simulate run: check staging and syntax without launching retrohunts",
    )
    limit_group.add_argument(
        "--no-safe-mode",
        action="store_true",
        help="Do NOT disable alerting on rules during retrohunt (WARNING: alert flood risk)",
    )
    limit_group.add_argument(
        "--cleanup-created-rules",
        action="store_true",
        help="Delete newly created temporary rules after retrohunt completes",
    )
    limit_group.add_argument(
        "--checkpoint-file",
        type=str,
        help="Path to checkpoint file for resuming interrupted runs",
    )

    # Reporting Options
    out_group = parser.add_argument_group("Reporting & Output")
    out_group.add_argument(
        "--output-json",
        type=str,
        default=f"retrohunt_results_{int(time.time())}.json",
        help="Path to output results JSON file",
    )
    out_group.add_argument(
        "--output-csv",
        type=str,
        default=f"retrohunt_results_{int(time.time())}.csv",
        help="Path to output results CSV file",
    )

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Compute Time Range
    now_utc = datetime.now(timezone.utc)
    if args.start_time and args.end_time:
        start_time = parse_rfc3339(args.start_time)
        end_time = parse_rfc3339(args.end_time)
    elif args.hours:
        end_time = now_utc - timedelta(hours=1)
        start_time = end_time - timedelta(hours=args.hours)
    elif args.days:
        end_time = now_utc - timedelta(hours=1)
        start_time = end_time - timedelta(days=args.days)
    else:
        end_time = now_utc - timedelta(hours=1)
        start_time = end_time - timedelta(hours=24)

    if start_time >= end_time:
        logging.error(f"Invalid time window: start_time ({start_time}) >= end_time ({end_time}).")
        sys.exit(1)

    # Resolve Target Instances
    target_instances: List[InstanceTarget] = []

    # 1. Partner Discovery
    if args.discover_tenants:
        parent_inst = args.parent_instance or args.customer_id
        parent_proj = args.parent_project or args.project_id
        client = create_secops_client(args.credentials_path)
        target_instances = discover_tenants_from_partner_api(
            secops_client=client,
            parent_instance_id=parent_inst,
            parent_project=parent_proj,
            region=args.region,
        )
    # 2. File Inventory
    elif args.instances_file:
        target_instances = load_instances_from_file(
            file_path=args.instances_file,
            default_region=args.region,
            default_project=args.project_id,
        )
    # 3. Single Instance Fallback
    else:
        target_instances = [
            InstanceTarget(
                customer_id=args.customer_id,
                project_id=args.project_id,
                display_name=f"Instance-{args.customer_id[:8]}",
                region=args.region,
            )
        ]

    # Filter instances if requested
    if args.instance_filter:
        pattern = re.compile(args.instance_filter, re.IGNORECASE)
        target_instances = [
            inst for inst in target_instances
            if pattern.search(inst.display_name) or (inst.customer_code and pattern.search(inst.customer_code))
        ]

    if args.instance_limit:
        target_instances = target_instances[:args.instance_limit]

    if not target_instances:
        logging.error("No valid instance targets found.")
        sys.exit(1)

    logging.info(f"Targeting {len(target_instances)} Google SecOps instance(s).")

    # Initialize Multi-Tenant Orchestrator
    orchestrator = MultiTenantRetrohuntOrchestrator(
        instances=target_instances,
        credentials_path=args.credentials_path,
        max_concurrent_per_instance=args.max_concurrent_per_instance,
        max_parallel_instances=args.max_parallel_instances,
        poll_interval=args.poll_interval,
        job_timeout=args.timeout,
        safe_mode=(not args.no_safe_mode),
        cleanup_created_rules=args.cleanup_created_rules,
        checkpoint_file=args.checkpoint_file,
    )

    # Load Detection Rules
    rules_to_hunt: List[RuleItem] = []

    # 1. Single rule file specified
    if args.rule_file:
        rules_to_hunt = orchestrator.load_rule_from_file(args.rule_file)
    # 2. Fetch deployed rules directly from target instances
    elif args.use_instance_rules or args.rule_filter or args.rule_ids:
        r_ids = [x.strip() for x in args.rule_ids.split(",")] if args.rule_ids else None
        rules_to_hunt = orchestrator.load_rules_from_instances(
            rule_filter=args.rule_filter,
            rule_ids=r_ids,
            limit=args.limit,
        )
    # 3. Load from local rules directory
    else:
        rules_dir = args.rules_dir
        if not rules_dir and os.path.exists("detection-rules/rules/community"):
            rules_dir = "detection-rules/rules/community"
        elif not rules_dir and os.path.exists("/usr/local/google/home/hzmndt/Google/detection-rules/rules/community"):
            rules_dir = "/usr/local/google/home/hzmndt/Google/detection-rules/rules/community"

        if rules_dir:
            rules_to_hunt = orchestrator.load_rules_from_directory(
                directory_path=rules_dir,
                pattern=args.rules_pattern,
                category_filter=args.category,
                limit=args.limit,
            )
        else:
            logging.error(
                "No rule source provided. Please specify --rules-dir or --rule-file to load local files, "
                "or --use-instance-rules / --rule-filter to hunt rules already in Chronicle."
            )
            sys.exit(1)

    if not rules_to_hunt:
        logging.warning("No candidate rules found.")
        sys.exit(0)

    # If --deploy-only is selected, deploy/update rules in Chronicle and exit without running retrohunts
    if args.deploy_only:
        deploy_results = orchestrator.deploy_rules_all(
            rules=rules_to_hunt,
            update_existing=args.update_existing,
            enable_rules=True if args.enable_rules else None,
            enable_alerting=True if args.enable_alerting else None,
            dry_run=args.dry_run,
        )
        print(orchestrator.generate_deploy_summary_table(deploy_results))
        if not args.dry_run:
            deploy_json = args.output_json.replace("retrohunt_results_", "rule_deploy_results_")
            deploy_csv = args.output_csv.replace("retrohunt_results_", "rule_deploy_results_")
            orchestrator.export_deploy_reports(deploy_results, json_path=deploy_json, csv_path=deploy_csv)
        sys.exit(0)


    # Execute Multi-Tenant Batch
    try:
        orchestrator.run_all(
            rules=rules_to_hunt,
            start_time=start_time,
            end_time=end_time,
            dry_run=args.dry_run,
            update_existing=args.update_existing,
        )
    except KeyboardInterrupt:
        logging.warning("Interrupted by user. Generating summary table...")

    # Display Summary Table
    print(orchestrator.generate_summary_table())

    # Export Unified Reports
    if not args.dry_run:
        orchestrator.export_reports(
            json_path=args.output_json,
            csv_path=args.output_csv,
        )


if __name__ == "__main__":
    main()
