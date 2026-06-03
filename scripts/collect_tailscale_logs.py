#!/usr/bin/env python3
"""
Tailscale Activity Monitor
Collects Tailscale logs and connection activity for security monitoring.
Detects potential shadow IT usage and unauthorized network access.
Output: JSON formatted for Wazuh ingestion via Listening Post.
"""
 
import json
import subprocess
import datetime
import os
import sys
from pathlib import Path

class TailscaleActivityMonitor:
    def __init__(self, output_dir="/var/log/shadow-it-monitor"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.log_file = self.output_dir / "tailscale-activity.log"
        
    def get_tailscale_status(self):
        """Get current Tailscale status and connected peers"""
        try:
            result = subprocess.run(
                ['tailscale', 'status', '--json'],
                capture_output=True,
                text=True,
                check=True
            )
            return json.loads(result.stdout)
        except subprocess.CalledProcessError as e:
            print(f"❌ Error getting Tailscale status: {e}")
            return None
        except FileNotFoundError:
            print("⚠️  Tailscale CLI not found on this system")
            return None

    def get_tailscale_activity_logs(self, lines=100):
        """Get Tailscale logs from system journal"""
        try:
            result = subprocess.run(
                ['journalctl', '-u', 'tailscaled', '-n', str(lines), '--output=json'],
                capture_output=True,
                text=True,
                check=True
            )
            logs = []
            for line in result.stdout.strip().split('\n'):
                if line:
                    try:
                        logs.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
            return logs
        except subprocess.CalledProcessError:
            print("⚠️  Could not retrieve Tailscale system logs")
            return []
        except FileNotFoundError:
            print("⚠️  journalctl not found - Linux systemd required")
            return []

    def get_tailscale_netstat(self):
        """Get Tailscale network connections"""
        try:
            result = subprocess.run(
                ['ss', '-tunap', '|', 'grep', 'tailscale'],
                capture_output=True,
                text=True,
                shell=True
            )
            connections = []
            for line in result.stdout.strip().split('\n'):
                if line and 'tailscale' in line.lower():
                    connections.append(line)
            return connections
        except Exception:
            return []

    def format_for_wazuh(self, status_data, activity_logs, netstat_data):
        """
        Format activity data in Wazuh-friendly JSON structure
        Security-focused: highlights unauthorized activity
        """
        timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
        
        # Extract key security indicators
        security_flags = {
            "tailscale_active": bool(status_data),
            "peer_count": len(status_data.get('Peers', {})) if status_data else 0,
            "exit_node_active": status_data.get('ExitNodeStatus', {}).get('Using', False) if status_data else False,
            "subnets_active": bool(status_data.get('AdvertisedRoutes', [])) if status_data else False,
        }
        
        wazuh_event = {
            "timestamp": timestamp,
            "source": "tailscale",
            "event_type": "shadow_it_detection",
            "severity": "medium",
            "collector_version": "2.0",
            "collection_method": "cloudflare_tunnel",
            "security_flags": security_flags,
            "status": status_data,
            "activity": [],
            "network_connections": netstat_data
        }
        
        # Process activity logs into security events
        for log in activity_logs:
            message = log.get("MESSAGE", "")
            
            # Flag suspicious activity
            suspicious = any(keyword in message.lower() for keyword in [
                'connect', 'disconnect', 'error', 'warning', 'auth', 'peer',
                'route', 'exit', 'subnet', 'unauthorized'
            ])
            
            event = {
                "timestamp": log.get("__REALTIME_TIMESTAMP", timestamp),
                "message": message,
                "priority": log.get("PRIORITY", "6"),
                "unit": log.get("_SYSTEMD_UNIT", "tailscaled"),
                "hostname": log.get("_HOSTNAME", "unknown"),
                "suspicious": suspicious
            }
            wazuh_event["activity"].append(event)
        
        return wazuh_event

    def save_logs(self, logs):
        """Save activity logs for Wazuh ingestion"""
        try:
            with open(self.log_file, 'a') as f:
                json.dump(logs, f)
                f.write('\n')
            
            print(f"✅ Tailscale activity logged to: {self.log_file}\")\n            return self.log_file\n            \n        except PermissionError:\n            print(f\"❌ Permission denied writing to {self.log_file}. Try sudo?\")\n            return None\n\n    def collect(self):\n        \"\"\"Main collection method\"\"\"\n        print(\"🔍 Monitoring Tailscale activity...\")\n        \n        status = self.get_tailscale_status()\n        activity_logs = self.get_tailscale_activity_logs(lines=100)\n        netstat_data = self.get_tailscale_netstat()\n        \n        if status or activity_logs or netstat_data:\n            formatted_event = self.format_for_wazuh(status, activity_logs, netstat_data)\n            self.save_logs(formatted_event)\n        else:\n            print(\"ℹ️  No Tailscale activity detected\")\n\ndef main():\n    output_dir = sys.argv[1] if len(sys.argv) > 1 else \"/var/log/shadow-it-monitor\"\n    monitor = TailscaleActivityMonitor(output_dir=output_dir)\n    monitor.collect()\n\nif __name__ == \"__main__\":\n    main()\n