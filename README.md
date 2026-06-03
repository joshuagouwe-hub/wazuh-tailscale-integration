# Wazuh Tailscale Integration

Automated log collection and direct SIEM integration for Tailscale networks with Wazuh.

## Architecture

```
Tailscale → Log Collector → Wazuh Manager API → Wazuh SIEM → Alerts
```

## Overview

This integration enables containers and systems running Tailscale to send metrics and logs **directly to Wazuh** for real-time security monitoring and alerting. The system uses:

- **Direct API Integration**: Containers send Tailscale metrics directly to the Wazuh Manager API (no GitHub intermediary)
- **Real-time Collection**: Collects Tailscale status and system journal logs continuously
- **Wazuh-native Format**: Logs are formatted specifically for Wazuh ingestion and analysis

## Components

- **Log Collector** (`collect_tailscale_logs.py`): Python script that extracts Tailscale logs and status information from containers
- **Wazuh Sender** (`send_to_wazuh.py`): Sends collected logs directly to Wazuh Manager API using JWT authentication
- **System Integration**: Runs via cron or Kubernetes CronJob to periodically collect and send metrics

## Key Features

- ✅ Direct API communication with Wazuh Manager
- ✅ JWT token-based authentication
- ✅ Real-time Tailscale status monitoring
- ✅ System journal log collection
- ✅ Container-native (Docker/Kubernetes ready)
- ✅ No external dependencies (GitHub Actions removed)

## Setup Status

- [x] Repository created
- [x] Log collector script added
- [x] Wazuh direct API integration implemented
- [x] Direct container-to-Wazuh pipeline
- [ ] Wazuh custom rules added
- [ ] Kubernetes deployment manifests

## Configuration

### Environment Variables

```bash
WAZUH_API_URL=https://wazuh-manager:55000      # Wazuh Manager API URL
WAZUH_API_USER=admin                            # Wazuh API user
WAZUH_API_PASSWORD=<secure-password>            # Wazuh API password
WAZUH_AGENT_ID=000                              # Wazuh agent ID (default: manager)
```

## Quick Start

### 1. Install Dependencies

```bash
pip install requests
```

### 2. Collect and Send Logs

```bash
# Collect Tailscale logs
python3 scripts/collect_tailscale_logs.py /var/log/tailscale-custom

# Send directly to Wazuh
python3 scripts/send_to_wazuh.py
```

### 3. Schedule with Cron

```bash
*/5 * * * * python3 /path/to/scripts/send_to_wazuh.py >> /var/log/wazuh-tailscale.log 2>&1
```

### 4. Docker/Kubernetes Integration

Run as a CronJob in Kubernetes:

```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: tailscale-wazuh-collector
spec:
  schedule: "*/5 * * * *"  # Every 5 minutes
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: collector
            image: python:3.9
            command: ["/bin/bash", "-c"]
            args: ["pip install requests && python3 /scripts/send_to_wazuh.py"]
            env:
            - name: WAZUH_API_URL
              valueFrom:
                secretKeyRef:
                  name: wazuh-config
                  key: api-url
            - name: WAZUH_API_USER
              valueFrom:
                secretKeyRef:
                  name: wazuh-config
                  key: api-user
            - name: WAZUH_API_PASSWORD
              valueFrom:
                secretKeyRef:
                  name: wazuh-config
                  key: api-password
```

## Data Flow

1. **Collection**: `collect_tailscale_logs.py` gathers:
   - Tailscale node status (`tailscale status --json`)
   - System logs (`journalctl -u tailscaled`)

2. **Formatting**: Logs are formatted in Wazuh-compatible JSON structure

3. **Authentication**: `send_to_wazuh.py` authenticates to Wazuh Manager API

4. **Transmission**: Events are sent directly to `/events` API endpoint

5. **Processing**: Wazuh ingests, processes, and triggers alerts based on rules

## API Integration

The integration uses Wazuh's REST API:

- **Authentication**: `POST /security/user/authenticate`
- **Event Ingestion**: `POST /events`

JWT tokens are obtained via basic auth and used for subsequent API calls.

## Troubleshooting

### Failed to authenticate with Wazuh
- Verify `WAZUH_API_URL`, `WAZUH_API_USER`, and `WAZUH_API_PASSWORD` are correct
- Check Wazuh Manager is running and API port (55000) is accessible
- Verify SSL certificates if using self-signed certs

### Cannot get Tailscale status
- Ensure `tailscale` CLI is installed on the host
- Container must have access to Tailscale socket (`/var/run/tailscale/`)

### System logs not collected
- This script requires `journalctl` (Linux systemd)
- May need root/sudo access to read full journal
- On non-Linux systems, modify `get_system_logs()` method

## Documentation

- [Wazuh API Documentation](https://documentation.wazuh.com/current/user-manual/api/index.html)
- [Tailscale Documentation](https://tailscale.com/kb)

## Requirements

- Python 3.7+
- `requests` library
- Wazuh Manager with API enabled
- Tailscale CLI installed
- Network access from container/host to Wazuh API (default port 55000)

## License

See LICENSE file for details.
