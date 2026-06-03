#!/usr/bin/env python3
"""
Tailscale Log Collector
Collects Tailscale logs and formats them for Wazuh ingestion.
Output: Compact JSON (NDJSON) suitable for Wazuh Agent.
"""
 
import json
import subprocess
import datetime
import os
import sys
from pathlib import Path

class TailscaleLogCollector:
    def __init__(self, output_dir="/var/log/tailscale-custom"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        # We use a fixed filename so Wazuh can watch it consistently
        self.log_file = self.output_dir / "tailscale.log"
        
    def get_tailscale_status(self):
        """Get current Tailscale status"""
        try:
            # We use tailscale status --json directly
            result = subprocess.run(
                ['tailscale', 'status', '--json'],
                capture_output=True,
                text=True,
                check=True
            )
            return json.loads(result.stdout)
        except subprocess.CalledProcessError as e:
            print(f"Error getting Tailscale status: {e}")
            return None
        except FileNotFoundError:
            print("Tailscale CLI not found. Please install Tailscale.")
            return None

    def get_system_logs(self, lines=100):
        """Get Tailscale logs from system journal (Linux)"""
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
            print("Could not retrieve system logs. Running without sudo?")
            return []
        except FileNotFoundError:
            print("journalctl not found. This script works best on Linux with systemd.")
            return []

    def format_for_wazuh(self, status_data, system_logs):
        """Format logs in a Wazuh-friendly JSON structure"""
        timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
        
        wazuh_logs = {
            "timestamp": timestamp,
            "source": "tailscale",
            "collector_version": "1.0",
            "status": status_data,
            # We include the last 100 system events inside this object
            # Note: If this becomes too large, Wazuh might truncate it.
            "events": [] 
        }
        
        # Process system logs into events
        for log in system_logs:
            event = {
                "timestamp": log.get("__REALTIME_TIMESTAMP", timestamp),
                "message": log.get("MESSAGE", ""),
                "priority": log.get("PRIORITY", "6"),
                "unit": log.get("_SYSTEMD_UNIT", "tailscaled"),
                "hostname": log.get("_HOSTNAME", "unknown")
            }
            wazuh_logs["events"].append(event)
        
        return wazuh_logs

    def save_logs(self, logs):
        """
        Save logs to the fixed log file.
        IMPORTANT: We use 'a' (append) and NO indent to mimic 'jq -c'
        """
        try:
            with open(self.log_file, 'a') as f:
                # json.dump with NO indent creates the "flattened" one-line JSON
                # This is exactly what 'jq -c' does.
                json.dump(logs, f)
                f.write('\n') # Wazuh expects a newline after every JSON object
            
            print(f"Log appended to: {self.log_file}")
            return self.log_file
            
        except PermissionError:
            print(f"Error: Permission denied writing to {self.log_file}. Try sudo?")
            return None

    def collect(self):
        """Main collection method"""
        print("Collecting Tailscale logs...")
        
        # Get Tailscale status
        status = self.get_tailscale_status()
        
        if status:
            # Get system logs
            system_logs = self.get_system_logs(lines=50) # Reduced to 50 to keep JSON size manageable
            
            # Format for Wazuh
            formatted_logs = self.format_for_wazuh(status, system_logs)
            
            # Save to file
            self.save_logs(formatted_logs)
        else:
            print("Failed to collect status.")

def main():
    # Allow overriding output dir via command line, else use default
    output_dir = sys.argv[1] if len(sys.argv) > 1 else "/var/log/tailscale-custom"
    
    collector = TailscaleLogCollector(output_dir=output_dir)
    collector.collect()

if __name__ == "__main__":
    main()
