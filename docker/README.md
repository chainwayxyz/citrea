# Prometheus & Grafana Setup Guide

This document explains how to run Prometheus and Grafana locally for two audiences:

1) **Node runners** who want to view dashboards alongside their nodes  
2) **Citrea developers** who want to update dashboards locally and sync changes to production

---

## 1) For Node Runners: View Grafana Dashboards Next to Your Node

1. Go to the Docker directory:
   - `<project_dir>/docker`

2. Start the user telemetry stack:
   ```bash
   docker compose -f docker-compose.telemetry.user.yaml up
   ```

3. Open Grafana:
   - `http://localhost:3000`

4. Import a dashboard:
   - Navigate to:
     - `<project_dir>/resources/grafana/user`
   - Copy the JSON for the node type you want.
   - Import it into Grafana.

**Note:** Don’t forget to add the telemetry config to your `rollup_config.toml`.

---

## 2) For Citrea Developers: Update Dashboards Locally and Sync to Production

### Run Prometheus + Grafana Locally

1. Go to the Docker directory:
   - `<project_dir>/docker`

2. Start the developer telemetry stack:
   ```bash
   docker compose -f docker-compose.telemetry.yaml up
   ```

3. Open Grafana and make your dashboard changes:
   - `http://localhost:3000`

---

### Update the Production Dashboard

4. When exporting your updated dashboard:
   - Select **Export as code → Classic**
   - Disable **Export for sharing externally**
     - This ensures the local data source UID remains compatible with production.

5. In production Grafana:
   - Open the dashboard
   - Click **Edit**
   - Go to **Settings → JSON Model**
   - Paste the updated JSON.

6. Save the updated production dashboard JSON under:
   - `resources/grafana/prod`

---

### Update User Dashboards

7. After updating the production dashboard, generate the user version using:
   ```bash
   python ./resource/grafana/remove_labels.py \
     ./resources/grafana/prod/<node_type>.dashboard.json \
     > ./resources/grafana/user/<node_type>.dashboard.json
   ```

8. Validate:
   - Run Prometheus/Grafana in **user mode**
   - Import the newly generated user dashboard
   - Confirm everything looks correct.

---

## Summary

- **Node runners** should use:
  - `docker-compose.telemetry.user.yaml`
  - User dashboards from `resources/grafana/user`

- **Developers** should:
  - Update locally with `docker-compose.telemetry.yaml`
  - Export carefully to preserve UID compatibility
  - Paste into prod JSON Model
  - Commit the updated JSON in:
    - `resources/grafana/prod`
  - Regenerate user dashboards using `remove_labels.py`

---
