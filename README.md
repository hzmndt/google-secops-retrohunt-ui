# Google SecOps Multi-Tenant Retrohunt Dashboard (Web UI)

A real-time, interactive web dashboard to monitor and orchestrate large-scale batch retrohunts across multi-tenant enterprise and MSSP Google SecOps (Chronicle) instances.

Built with **Flask**, **Bootstrap 5 (Dark Mode)**, and **Gunicorn**, this application provides live visibility into retrohunt execution progress, quota saturation, tenant health, and historical threat detections across dozens of child tenant environments.

---

## Key Features

* **Live KPI Dashboard**: Instant visibility into Target Tenants, Total Queued Rules, Active Workers, Completed Jobs, Failed Jobs, and Total Detections.
* **Partner API Dynamic Discovery**: Automatically discovers child tenants from the central parent instance using Google SecOps's Customer Management / Partner API (`chronicle.tenants.list`).
* **Active Execution Matrix**: Real-time sliding-window view of currently executing retrohunts per tenant, showing rule IDs, start times, and animated status badges.
* **Continuous Concurrency Management**: Strictly respects the Google SecOps quota limit of **at most 3 concurrent retrohunts per SIEM instance**, continuously dispatching new jobs as worker slots free up without manual intervention.
* **Safe Mode Protection**: Prevents SOAR (Siemplify) alert storms by temporarily disabling alerting on deployed rules during the retrohunt and safely restoring the original state upon completion.
* **Tabular Results & Sample Detections**: Inspect duration, detection counts, and error diagnostics per rule upon completion.
* **Live Streaming Console**: Real-time server-sent log terminal displaying worker events, quota backoffs, and Chronicle operation state transitions.

---

## Architecture Overview

```
                      ┌─────────────────────────────────────────────────────────┐
                      │ Browser / SOC Analyst                                   │
                      │ (Live Status Polling & Interactive Controls)           │
                      └───────────────────────────┬─────────────────────────────┘
                                                  │ HTTPS
                                                  ▼
                      ┌─────────────────────────────────────────────────────────┐
                      │ Google Cloud Run (secops-retrohunt-ui)                  │
                      │ Gunicorn + Flask (Non-blocking Background Thread Pool)   │
                      └───────────────────────────┬─────────────────────────────┘
                                                  │ Service Account (ADC / Secret)
                                                  ▼
                      ┌─────────────────────────────────────────────────────────┐
                      │ Google SecOps Partner API & Chronicle REST API          │
                      │ - Dynamic Tenant Discovery (tenants.list)               │
                      │ - Rule Inspection & Safe Mode Alert Management          │
                      │ - Retrohunt Operations (create, get, detections)        │
                      └─────────────────────────────────────────────────────────┘
```

---

## Quickstart: Local Development

### 1. Prerequisites
* Python 3.10+
* Google Cloud SDK (`gcloud`) authenticated or a Service Account key with `roles/chronicle.editor`

### 2. Installation
```bash
git clone https://github.com/hzmndt/google-secops-retrohunt-ui.git
cd google-secops-retrohunt-ui
pip install -r requirements.txt
```

### 3. Environment Variables
```bash
# Configure credentials and parent instance settings
export GOOGLE_APPLICATION_CREDENTIALS="/path/to/service_account.json"
export PARENT_INSTANCE_ID="YOUR_PARENT_INSTANCE_ID"
export PARENT_PROJECT_ID="YOUR_PARENT_PROJECT_ID"
export SECOPS_REGION="asia-southeast1" # or "us", "europe", etc.
export PORT=8080
```

### 4. Run the Server
```bash
python3 app.py
```
Open your browser at `http://localhost:8080`.

---

## Deployment to Google Cloud Run

Deploying to Google Cloud Run allows the dashboard to run securely in your GCP project with seamless IAM authentication and Secret Manager integration.

### 1. Store Service Account Key in Secret Manager
```bash
# Create the secret
gcloud secrets create secops-retrohunt-sa-key \
  --replication-policy="automatic" \
  --project="YOUR_PROJECT_ID"

# Upload your service account key
gcloud secrets versions add secops-retrohunt-sa-key \
  --data-file="/path/to/service_account.json" \
  --project="YOUR_PROJECT_ID"

# Grant Secret Accessor to the Cloud Run runtime service account
gcloud secrets add-iam-policy-binding secops-retrohunt-sa-key \
  --member="serviceAccount:secops-retrohunt-sa@YOUR_PROJECT_ID.iam.gserviceaccount.com" \
  --role="roles/secretmanager.secretAccessor" \
  --project="YOUR_PROJECT_ID"
```

### 2. Build Container Image via Cloud Build
```bash
gcloud builds submit \
  --tag "asia-southeast1-docker.pkg.dev/YOUR_PROJECT_ID/YOUR_REPO/secops-retrohunt-ui:latest" \
  --project="YOUR_PROJECT_ID"
```

### 3. Deploy Service to Cloud Run
> **Important**: Configure `--no-cpu-throttling` and `--min-instances=1` so that background worker threads continue executing and polling Chronicle even when HTTP client requests are not actively arriving.

```bash
gcloud run deploy secops-retrohunt-ui \
  --image="asia-southeast1-docker.pkg.dev/YOUR_PROJECT_ID/YOUR_REPO/secops-retrohunt-ui:latest" \
  --region="asia-southeast1" \
  --project="YOUR_PROJECT_ID" \
  --service-account="secops-retrohunt-sa@YOUR_PROJECT_ID.iam.gserviceaccount.com" \
  --set-secrets="GOOGLE_APPLICATION_CREDENTIALS=secops-retrohunt-sa-key:latest" \
  --set-env-vars="PARENT_INSTANCE_ID=YOUR_PARENT_INSTANCE_ID,PARENT_PROJECT_ID=YOUR_PARENT_PROJECT_ID,SECOPS_REGION=asia-southeast1" \
  --no-cpu-throttling \
  --min-instances=1 \
  --allow-unauthenticated
```

---

## REST API Specification

| Endpoint | Method | Description |
| :--- | :--- | :--- |
| `/` | `GET` | Main HTML dashboard user interface |
| `/api/status` | `GET` | Fetches live execution metrics, active jobs, completed results, and console logs |
| `/api/tenants` | `GET` | Discovers child tenants dynamically via Partner API (`?parent_instance=...&parent_project=...&region=...`) |
| `/api/rules` | `GET` | Lists rules deployed in a specific instance (`?instance_id=...&project_id=...&region=...`) |
| `/api/start` | `POST` | Initiates a batch retrohunt run in a background worker thread |

### Example `/api/start` Payload
```json
{
  "tenant_ids": ["ad390129-a027-4b65-bc30-3213e7a2d8f7"],
  "limit_rules": 5,
  "hours": 24,
  "dry_run": false,
  "safe_mode": true
}
```

---

## Required IAM Permissions

For multi-tenant and scoped environments, assign **`roles/chronicle.admin`** (which includes `chronicle.dataAccessScopes.permit`), or configure a least-privilege custom role with the verified permissions:
* `chronicle.tenants.list`
* `chronicle.instances.get`
* `chronicle.dataAccessScopes.permit` (CRITICAL for rules bound to custom scopes)
* `chronicle.globalDataAccessScopes.permit` (for global/unscoped rules)
* `chronicle.dataAccessScopes.list`
* `chronicle.rules.list`
* `chronicle.rules.get`
* `chronicle.rules.create`
* `chronicle.rules.delete`
* `chronicle.rules.listRevisions`
* `chronicle.rules.verifyRuleText`
* `chronicle.ruleDeployments.get`
* `chronicle.ruleDeployments.update`
* `chronicle.retrohunts.create`
* `chronicle.retrohunts.get`
* `chronicle.retrohunts.list`
* `chronicle.legacies.legacySearchDetections`
* `chronicle.legacies.legacyTestRuleStreaming`
* `chronicle.operations.get`

---

## License

Apache 2.0
