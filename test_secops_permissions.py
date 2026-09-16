#!/usr/bin/env python3
"""
Google SecOps (Chronicle) Service Account Permission & Scope Diagnostic Tool

Validates whether a Service Account has all necessary GCP IAM permissions and
Chronicle Data Access Scopes required to execute batch retrohunts, query rules,
and export detections.

Usage:
  # Test with an instances file (e.g. your instances.csv)
  python3 test_secops_permissions.py \
    --credentials-path path/to/service_account.json \
    --instances-file instances.csv \
    --rule-id ru_b0e4c1eb-7335-4902-b933-8cc1bee32cad

  # Test a single SecOps instance directly
  python3 test_secops_permissions.py \
    --credentials-path path/to/service_account.json \
    --customer-id 08189574-f559-4428-92dd-0314f7723c6f \
    --project-id apac-workshop-1 \
    --region asia-southeast1 \
    --rule-id ru_ca82e120-ad18-4694-b1eb-0d3cb1ed7b57
"""

import argparse
import csv
import json
import os
import re
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from secops import SecOpsClient


# Console Colors for terminal output
class Colors:
    HEADER = "\033[95m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    RESET = "\033[0m"
    BOLD = "\033[1m"


@dataclass
class TestResult:
    domain: str
    permission: str
    passed: bool
    status_label: str
    message: str
    is_critical: bool = True
    remedy_iam: Optional[str] = None
    remedy_secops_ui: Optional[str] = None


def load_sa_identity(credentials_path: Optional[str]) -> Dict[str, Any]:
    """Inspects service account file or environment for identity metadata."""
    cred_file = (
        credentials_path
        or os.getenv("GOOGLE_APPLICATION_CREDENTIALS")
    )
    if cred_file and os.path.exists(cred_file):
        try:
            with open(cred_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                return {
                    "source": f"Service Account Key ({os.path.basename(cred_file)})",
                    "client_email": data.get("client_email", "unknown"),
                    "project_id": data.get("project_id", "unknown"),
                    "type": data.get("type", "service_account"),
                }
        except Exception:
            pass
    return {
        "source": "Application Default Credentials (ADC) or Environment",
        "client_email": "ADC Principal",
        "project_id": os.getenv("GOOGLE_CLOUD_PROJECT", "unknown"),
        "type": "ADC",
    }


def load_targets(args: argparse.Namespace) -> List[Dict[str, str]]:
    """Loads target instances from args or instances file."""
    targets = []
    if args.instances_file and os.path.exists(args.instances_file):
        if args.instances_file.endswith(".json"):
            with open(args.instances_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, list):
                    for item in data:
                        targets.append({
                            "customer_id": item.get("instance_id") or item.get("customer_id", ""),
                            "project_id": item.get("project_id", args.project_id or ""),
                            "display_name": item.get("display_name", "Target Instance"),
                            "region": item.get("region", args.region or "us"),
                        })
        elif args.instances_file.endswith(".csv"):
            with open(args.instances_file, "r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    targets.append({
                        "customer_id": row.get("instance_id") or row.get("customer_id", ""),
                        "project_id": row.get("project_id", args.project_id or ""),
                        "display_name": row.get("display_name", "Target Instance"),
                        "region": row.get("region", args.region or "us"),
                    })
    if not targets and args.customer_id:
        targets.append({
            "customer_id": args.customer_id,
            "project_id": args.project_id or "UNKNOWN_PROJECT",
            "display_name": f"Instance-{args.customer_id[:8]}",
            "region": args.region or "us",
        })
    return targets


def run_permission_diagnostic(
    client: SecOpsClient,
    target: Dict[str, str],
    sa_identity: Dict[str, Any],
    probe_rule_id: Optional[str] = None,
    rule_filter: Optional[str] = None,
) -> List[TestResult]:
    """Runs functional probes against Chronicle APIs to verify each permission."""
    results: List[TestResult] = []
    cust_id = target["customer_id"]
    proj_id = target["project_id"]
    region = target["region"]
    sa_email = sa_identity.get("client_email", "YOUR_SERVICE_ACCOUNT_EMAIL")

    chronicle = client.chronicle(customer_id=cust_id, project_id=proj_id, region=region)
    session = client.auth.session
    base_v1alpha = f"https://{region}-chronicle.googleapis.com/v1alpha/projects/{proj_id}/locations/{region}/instances/{cust_id}"

    # -------------------------------------------------------------
    # 1. Instance Connectivity (chronicle.instances.get)
    # -------------------------------------------------------------
    try:
        r_inst = session.get(base_v1alpha)
        if r_inst.status_code == 200:
            results.append(TestResult(
                domain="Instance Health",
                permission="chronicle.instances.get",
                passed=True,
                status_label="PASS",
                message=f"Connected to instance {cust_id[:8]}... (Region: {region})",
            ))
        else:
            results.append(TestResult(
                domain="Instance Health",
                permission="chronicle.instances.get",
                passed=False,
                status_label="FAIL",
                message=f"HTTP {r_inst.status_code}: {r_inst.text[:120]}",
                remedy_iam=f"gcloud projects add-iam-policy-binding {proj_id} --member='serviceAccount:{sa_email}' --role='roles/chronicle.viewer'",
            ))
    except Exception as e:
        results.append(TestResult(
            domain="Instance Health",
            permission="chronicle.instances.get",
            passed=False,
            status_label="FAIL",
            message=f"Connection error: {e}",
        ))

    # -------------------------------------------------------------
    # 2. Data Access Scopes (chronicle.dataAccessScopes.*)
    # -------------------------------------------------------------
    scopes_found = []
    global_scope_granted = False
    try:
        r_scopes = session.get(f"{base_v1alpha}/dataAccessScopes")
        if r_scopes.status_code == 200:
            scope_data = r_scopes.json()
            scopes_found = scope_data.get("dataAccessScopes", [])
            global_scope_granted = scope_data.get("globalDataAccessScopeGranted", False)

            # Global Scope check
            if global_scope_granted:
                results.append(TestResult(
                    domain="Data Scopes",
                    permission="chronicle.globalDataAccessScopes.permit",
                    passed=True,
                    status_label="PASS",
                    message="Global/Default Scope access granted (Scope: None).",
                ))
            else:
                results.append(TestResult(
                    domain="Data Scopes",
                    permission="chronicle.globalDataAccessScopes.permit",
                    passed=False,
                    status_label="FAIL",
                    message="Global Data Access Scope NOT granted.",
                    remedy_iam=f"gcloud projects add-iam-policy-binding {proj_id} --member='serviceAccount:{sa_email}' --role='roles/chronicle.editor'",
                ))

            # Custom Data Access Scopes check
            results.append(TestResult(
                domain="Data Scopes",
                permission="chronicle.dataAccessScopes.permit",
                passed=True,
                status_label="PASS",
                message=f"Access verified for {len(scopes_found)} custom scope(s): {[s.get('displayName') for s in scopes_found]}",
            ))
        elif r_scopes.status_code == 403:
            results.append(TestResult(
                domain="Data Scopes",
                permission="chronicle.dataAccessScopes.permit",
                passed=False,
                status_label="FAIL",
                message="HTTP 403 Forbidden: Caller lacks permission to evaluate Data Access Scopes.",
                remedy_iam=f"gcloud projects add-iam-policy-binding {proj_id} --member='serviceAccount:{sa_email}' --role='roles/chronicle.admin'",
                remedy_secops_ui="In Chronicle UI -> Settings -> Access Control -> Data Access Scopes, ensure the Service Account is an assignee for the target scope.",
            ))
        else:
            results.append(TestResult(
                domain="Data Scopes",
                permission="chronicle.dataAccessScopes.list",
                passed=False,
                status_label="WARN",
                message=f"HTTP {r_scopes.status_code}: {r_scopes.text[:120]}",
            ))
    except Exception as e:
        results.append(TestResult(
            domain="Data Scopes",
            permission="chronicle.dataAccessScopes.permit",
            passed=False,
            status_label="FAIL",
            message=f"Scope check failed: {e}",
        ))

    # -------------------------------------------------------------
    # 3. Detection Rules Listing & Filtering (chronicle.rules.list)
    # -------------------------------------------------------------
    first_rule_id = None
    first_rule_name = None
    matched_rules: List[tuple] = []
    total_scanned = 0
    pattern = re.compile(rule_filter, re.IGNORECASE) if rule_filter else None

    try:
        page_token = None
        while True:
            r_rules = chronicle.list_rules(page_size=1000, page_token=page_token)
            rules_list = r_rules.get("rules", [])
            total_scanned += len(rules_list)

            for r in rules_list:
                dname = r.get("displayName")
                rname = r.get("name", "")
                rid = rname.split("/")[-1] if rname else None
                if not dname or not rid:
                    continue

                if pattern:
                    if pattern.search(dname) or pattern.search(rid):
                        matched_rules.append((dname, rid))
                else:
                    if len(matched_rules) < 5:
                        matched_rules.append((dname, rid))

            page_token = r_rules.get("nextPageToken")
            if not page_token or not rules_list:
                break
            # If no filter is specified, page 1 (up to 1000 rules) is sufficient for permission check
            if not pattern:
                break

        if total_scanned > 0:
            if pattern:
                if matched_rules:
                    first_rule_name, first_rule_id = matched_rules[0]
                    sample_str = ", ".join([f"'{m[0]}'" for m in matched_rules[:3]])
                    if len(matched_rules) > 3:
                        sample_str += f" and {len(matched_rules) - 3} more"
                    results.append(TestResult(
                        domain="Detection Rules",
                        permission="chronicle.rules.list",
                        passed=True,
                        status_label="PASS",
                        message=f"Scanned {total_scanned} rules; found {len(matched_rules)} rule(s) matching '{rule_filter}': {sample_str}.",
                    ))
                else:
                    results.append(TestResult(
                        domain="Detection Rules",
                        permission="chronicle.rules.list",
                        passed=False,
                        status_label="WARN",
                        message=f"Scanned {total_scanned} rules, but 0 matched filter '{rule_filter}'. If these rules exist, they belong to an unassigned Data Access Scope.",
                        remedy_iam=f"gcloud projects add-iam-policy-binding {proj_id} --member='serviceAccount:{sa_email}' --role='roles/chronicle.admin'",
                        remedy_secops_ui=f"Chronicle silently filters out scoped rules from rules.list if unassigned. Check Chronicle UI -> Settings -> Access Control -> Data Access Scopes to verify if rules matching '{rule_filter}' belong to a restricted scope.",
                    ))
            else:
                first_rule_name, first_rule_id = matched_rules[0]
                results.append(TestResult(
                    domain="Detection Rules",
                    permission="chronicle.rules.list",
                    passed=True,
                    status_label="PASS",
                    message=f"Successfully listed rules ({total_scanned} visible rule(s) in Chronicle).",
                ))
        else:
            results.append(TestResult(
                domain="Detection Rules",
                permission="chronicle.rules.list",
                passed=False,
                status_label="WARN",
                message="Chronicle returned 0 total rules. If rules exist, this account lacks scope assignment or 'chronicle.rules.list'.",
                remedy_iam=f"gcloud projects add-iam-policy-binding {proj_id} --member='serviceAccount:{sa_email}' --role='roles/chronicle.admin'",
                remedy_secops_ui="Chronicle silently filters out scoped rules from rules.list if the Service Account is not assigned to their Data Access Scope. Go to Chronicle Settings -> Access Control -> Data Access Scopes to assign.",
            ))
    except Exception as e:
        err_msg = str(e)
        results.append(TestResult(
            domain="Detection Rules",
            permission="chronicle.rules.list",
            passed=False,
            status_label="FAIL",
            message=f"Failed listing rules: {err_msg[:120]}",
            remedy_iam=f"gcloud projects add-iam-policy-binding {proj_id} --member='serviceAccount:{sa_email}' --role='roles/chronicle.editor'",
        ))

    # -------------------------------------------------------------
    # 4. YARA-L Syntax Verification (chronicle.rules.verifyRuleText)
    # -------------------------------------------------------------
    test_yaral = """rule permission_probe_check {
  meta:
    description = "Test YARA-L rule syntax verification"
  events:
    $e.metadata.event_type = "USER_LOGIN"
  condition:
    $e
}"""
    try:
        val_res = chronicle.validate_rule(test_yaral)
        if val_res.success:
            results.append(TestResult(
                domain="Rule Staging",
                permission="chronicle.rules.verifyRuleText",
                passed=True,
                status_label="PASS",
                message="Syntax validation (:verifyRuleText) succeeded.",
            ))
        else:
            results.append(TestResult(
                domain="Rule Staging",
                permission="chronicle.rules.verifyRuleText",
                passed=False,
                status_label="FAIL",
                message=f"Syntax validation failed: {val_res.message}",
            ))
    except Exception as e:
        results.append(TestResult(
            domain="Rule Staging",
            permission="chronicle.rules.verifyRuleText",
            passed=False,
            status_label="FAIL",
            message=f"verifyRuleText call failed: {e}",
            remedy_iam=f"gcloud projects add-iam-policy-binding {proj_id} --member='serviceAccount:{sa_email}' --role='roles/chronicle.editor'",
        ))

    # -------------------------------------------------------------
    # 5. Specific Target Rule & Data Access Scope Probe (chronicle.rules.get)
    # -------------------------------------------------------------
    target_rule_to_test = probe_rule_id or first_rule_id
    if target_rule_to_test:
        try:
            rule_obj = chronicle.get_rule(target_rule_to_test)
            r_dname = rule_obj.get("displayName", target_rule_to_test)
            results.append(TestResult(
                domain="Rule Access",
                permission="chronicle.rules.get",
                passed=True,
                status_label="PASS",
                message=f"Successfully retrieved rule '{r_dname}' ({target_rule_to_test}).",
            ))

            # -------------------------------------------------------------
            # 6. Rule Deployment State (chronicle.ruleDeployments.get)
            # -------------------------------------------------------------
            try:
                dep_obj = chronicle.get_rule_deployment(target_rule_to_test)
                is_alerting = dep_obj.get("alerting", False)
                results.append(TestResult(
                    domain="Safe Mode",
                    permission="chronicle.ruleDeployments.get",
                    passed=True,
                    status_label="PASS",
                    message=f"Deployment state readable (alerting={is_alerting}). Safe Mode can toggle alerting safely.",
                ))
            except Exception as e:
                results.append(TestResult(
                    domain="Safe Mode",
                    permission="chronicle.ruleDeployments.get",
                    passed=False,
                    status_label="WARN",
                    message=f"Failed reading rule deployment: {e}",
                    remedy_iam=f"gcloud projects add-iam-policy-binding {proj_id} --member='serviceAccount:{sa_email}' --role='roles/chronicle.editor'",
                ))

        except Exception as e:
            err_str = str(e)
            if "access to scope" in err_str.lower() or "403" in err_str:
                results.append(TestResult(
                    domain="Rule Access",
                    permission="chronicle.rules.get",
                    passed=False,
                    status_label="FAIL",
                    message=f"HTTP 403 on rule '{target_rule_to_test}': user does not have access to scope.",
                    remedy_iam=f"gcloud projects add-iam-policy-binding {proj_id} --member='serviceAccount:{sa_email}' --role='roles/chronicle.admin'",
                    remedy_secops_ui=f"Rule '{target_rule_to_test}' is protected by a Data Access Scope. Go to Chronicle Settings -> Access Control -> Data Access Scopes and add '{sa_email}' as an Assignee.",
                ))
            elif "404" in err_str or "not found" in err_str.lower():
                results.append(TestResult(
                    domain="Rule Access",
                    permission="chronicle.rules.get",
                    passed=False,
                    status_label="WARN",
                    message=f"Rule '{target_rule_to_test}' not found (HTTP 404).",
                ))
            else:
                results.append(TestResult(
                    domain="Rule Access",
                    permission="chronicle.rules.get",
                    passed=False,
                    status_label="FAIL",
                    message=f"Error reading rule '{target_rule_to_test}': {err_str[:120]}",
                ))
    else:
        results.append(TestResult(
            domain="Rule Access",
            permission="chronicle.rules.get",
            passed=False,
            status_label="SKIP",
            message="No rule ID provided and 0 rules discovered to probe.",
        ))

    # -------------------------------------------------------------
    # 7. Detections Search API (chronicle.legacies.legacySearchDetections)
    # -------------------------------------------------------------
    if target_rule_to_test:
        try:
            now_utc = datetime.now(timezone.utc)
            start_dt = now_utc - timedelta(hours=2)
            end_dt = now_utc - timedelta(hours=1)
            det_res = chronicle.list_detections(
                rule_id=target_rule_to_test,
                start_time=start_dt,
                end_time=end_dt,
                page_size=1,
            )
            results.append(TestResult(
                domain="Detections Search",
                permission="chronicle.legacies.legacySearchDetections",
                passed=True,
                status_label="PASS",
                message=f"Detection search endpoint verified (returned {len(det_res.get('detections', []))} match records).",
            ))
        except Exception as e:
            results.append(TestResult(
                domain="Detections Search",
                permission="chronicle.legacies.legacySearchDetections",
                passed=False,
                status_label="WARN",
                message=f"list_detections probe: {e}",
                remedy_iam=f"Ensure IAM role includes 'chronicle.legacies.legacySearchDetections'.",
            ))
    else:
        results.append(TestResult(
            domain="Detections Search",
            permission="chronicle.legacies.legacySearchDetections",
            passed=False,
            status_label="SKIP",
            message="Skipped detection probe (requires at least one valid rule ID).",
        ))

    # -------------------------------------------------------------
    # 8. Partner Multi-Tenant Discovery (chronicle.tenants.list) - Optional
    # -------------------------------------------------------------
    try:
        r_tenants = session.get(f"{base_v1alpha}/tenants?pageSize=5")
        if r_tenants.status_code == 200:
            t_data = r_tenants.json().get("tenants", [])
            results.append(TestResult(
                domain="Partner Discovery",
                permission="chronicle.tenants.list",
                passed=True,
                status_label="PASS",
                message=f"Customer Management Partner API verified (Found {len(t_data)} child tenant(s)).",
                is_critical=False,
            ))
        elif r_tenants.status_code in (403, 404):
            results.append(TestResult(
                domain="Partner Discovery",
                permission="chronicle.tenants.list",
                passed=True,
                status_label="INFO",
                message="Single-tenant instance or non-partner instance (Normal for standalone SIEMs).",
                is_critical=False,
            ))
    except Exception:
        pass

    return results


def print_diagnostic_report(
    target: Dict[str, str],
    sa_identity: Dict[str, Any],
    results: List[TestResult],
):
    """Formats and prints the diagnostic test report with actionable remedies."""
    print("\n" + "=" * 95)
    print(f"{Colors.BOLD}GOOGLE SECOPS PERMISSION & SCOPE DIAGNOSTIC REPORT{Colors.RESET}")
    print("=" * 95)
    print(f"  Target Instance : {Colors.CYAN}{target['display_name']}{Colors.RESET} ({target['customer_id']})")
    print(f"  GCP Project ID  : {target['project_id']} | Region: {target['region']}")
    print(f"  Auth Identity   : {Colors.CYAN}{sa_identity['client_email']}{Colors.RESET} [{sa_identity['source']}]")
    print("-" * 95)
    print(f"{'DOMAIN':<18} | {'IAM PERMISSION':<42} | {'STATUS':<7} | {'DETAILS'}")
    print("-" * 95)

    failures: List[TestResult] = []
    warnings: List[TestResult] = []

    for r in results:
        if r.status_label == "PASS":
            status_str = f"{Colors.GREEN}{r.status_label}{Colors.RESET}"
        elif r.status_label in ("FAIL", "ERROR"):
            status_str = f"{Colors.RED}{r.status_label}{Colors.RESET}"
            if r.is_critical:
                failures.append(r)
        elif r.status_label == "WARN":
            status_str = f"{Colors.YELLOW}{r.status_label}{Colors.RESET}"
            warnings.append(r)
        else:
            status_str = f"{Colors.BLUE}{r.status_label}{Colors.RESET}"

        print(f"{r.domain:<18} | {r.permission:<42} | {status_str:<16} | {r.message}")

    print("-" * 95)

    if not failures and not warnings:
        print(f"{Colors.GREEN}{Colors.BOLD}✔ ALL REQUIRED PERMISSIONS & DATA ACCESS SCOPES ARE VERIFIED AND READY.{Colors.RESET}")
        print("You can run batch retrohunts safely without permission errors.\n")
        return

    # Print Actionable Recommendations
    print(f"\n{Colors.BOLD}{Colors.YELLOW}ACTIONABLE RECOMMENDATIONS & FIXES:{Colors.RESET}")
    print("=" * 95)

    sa_email = sa_identity.get("client_email", "YOUR_SERVICE_ACCOUNT_EMAIL")
    proj_id = target["project_id"]

    seen_remedies = set()

    for item in failures + warnings:
        if item.permission in seen_remedies:
            continue
        seen_remedies.add(item.permission)

        print(f"\n{Colors.BOLD}► Issue with [{item.permission}] ({item.domain}):{Colors.RESET}")
        print(f"  Description: {item.message}")

        if item.remedy_iam:
            print(f"  {Colors.CYAN}[Fix Step 1 - GCP IAM]{Colors.RESET} Run this command in Google Cloud Shell or terminal:")
            print(f"    {Colors.BOLD}{item.remedy_iam}{Colors.RESET}")

        if item.remedy_secops_ui:
            print(f"  {Colors.CYAN}[Fix Step 2 - Chronicle UI Scopes]{Colors.RESET}")
            print(f"    {item.remedy_secops_ui}")

    print("\n" + "=" * 95)
    print(f"{Colors.BOLD}Quick Reference: Difference between Chronicle Roles in IAM:{Colors.RESET}")
    print("  • roles/chronicle.admin  : Grants ALL permissions including chronicle.dataAccessScopes.permit (Required for scoped rules).")
    print("  • roles/chronicle.editor : Grants rule & retrohunt execution, but LACKS chronicle.dataAccessScopes.permit.")
    print("=" * 95 + "\n")


def main():
    parser = argparse.ArgumentParser(
        description="Google SecOps Service Account Permission & Scope Diagnostic Tool."
    )
    parser.add_argument(
        "--credentials-path",
        type=str,
        help="Path to Service Account JSON key (defaults to GOOGLE_APPLICATION_CREDENTIALS or ADC)",
    )
    parser.add_argument(
        "--instances-file",
        type=str,
        help="Path to instances.csv or instances.json inventory file to test target instances",
    )
    parser.add_argument(
        "--customer-id",
        type=str,
        help="Chronicle Customer UUID (e.g. 08189574-f559-4428-92dd-0314f7723c6f)",
    )
    parser.add_argument(
        "--project-id",
        type=str,
        help="GCP Project ID hosting the Chronicle instance (e.g. apac-workshop-1)",
    )
    parser.add_argument(
        "--region",
        type=str,
        default="asia-southeast1",
        help="Chronicle region (default: asia-southeast1)",
    )
    parser.add_argument(
        "--rule-filter",
        type=str,
        help="Regex filter on deployed rule names or IDs (e.g. '(?i)hac|mse')",
    )
    parser.add_argument(
        "--rule-id",
        type=str,
        help="Specific Chronicle rule ID to probe for Data Access Scope access (e.g. ru_b0e4c1eb-7335-4902-b933-8cc1bee32cad)",
    )

    args = parser.parse_args()

    sa_identity = load_sa_identity(args.credentials_path)
    targets = load_targets(args)

    if not targets:
        print(f"{Colors.RED}Error: No target instance specified.{Colors.RESET}")
        print("Please provide --instances-file instances.csv OR --customer-id and --project-id.")
        sys.exit(1)

    # Initialize client
    try:
        if args.credentials_path and os.path.exists(args.credentials_path):
            client = SecOpsClient(service_account_path=args.credentials_path)
        elif os.getenv("GOOGLE_APPLICATION_CREDENTIALS") and os.path.exists(os.getenv("GOOGLE_APPLICATION_CREDENTIALS")):
            client = SecOpsClient(service_account_path=os.getenv("GOOGLE_APPLICATION_CREDENTIALS"))
        else:
            client = SecOpsClient()
    except Exception as e:
        print(f"{Colors.RED}Authentication Initialization Error: {e}{Colors.RESET}")
        sys.exit(1)

    print(f"\n{Colors.BOLD}Testing permissions for identity: {Colors.CYAN}{sa_identity['client_email']}{Colors.RESET} across {len(targets)} target instance(s)...")

    for target in targets:
        results = run_permission_diagnostic(
            client=client,
            target=target,
            sa_identity=sa_identity,
            probe_rule_id=args.rule_id,
            rule_filter=args.rule_filter,
        )
        print_diagnostic_report(target, sa_identity, results)


if __name__ == "__main__":
    main()
