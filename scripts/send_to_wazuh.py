#!/usr/bin/env python3
"""
Send Tailscale logs directly to Wazuh Manager API
Replaces git commit approach with direct API integration
"""

import json
import subprocess
import datetime
import os
import sys
import requests
from pathlib import Path
from requests.auth import HTTPBasicAuth
import urllib3

# Disable SSL warnings if self-signed cert
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class WazuhLogSender:
    def __init__(self):
        self.wazuh_url = os.getenv('WAZUH_API_URL')
        self.wazuh_user = os.getenv('WAZUH_API_USER')
        self.wazuh_password = os.getenv('WAZUH_API_PASSWORD')
        self.agent_id = os.getenv('WAZUH_AGENT_ID', '000')  # Default to manager
        self.auth_token = None
        
        if not self.wazuh_url:
            raise ValueError("WAZUH_API_URL not set")
    
    def authenticate(self):
        """Get JWT token from Wazuh API"""
        try:
            auth_url = f"{self.wazuh_url}/security/user/authenticate"
            response = requests.post(
                auth_url,
                auth=HTTPBasicAuth(self.wazuh_user, self.wazuh_password),
                verify=False,
                timeout=10
            )
            response.raise_for_status()
            self.auth_token = response.json()['data']['token']
            print("✅ Authenticated with Wazuh")
            return True
        except Exception as e:
            print(f"❌ Wazuh authentication failed: {e}")
            return False
    
    def get_tailscale_status(self):
        """Get current Tailscale status"""
        try:
            result = subprocess.run(
                ['tailscale', 'status', '--json'],
                capture_output=True,
                text=True,
                check=True
            )
            return json.loads(result.stdout)
        except Exception as e:
            print(f"Error getting Tailscale status: {e}")
            return None
    
    def get_system_logs(self, lines=50):
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
        except Exception as e:
            print(f"Could not retrieve system logs: {e}")
            return []
    
    def format_for_wazuh(self, status_data, system_logs):
        """Format logs in Wazuh-friendly JSON structure"""
        timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
        
        return {
            "timestamp": timestamp,
            "source": "tailscale",
            "collector_version": "1.0",
            "status": status_data,
            "events": [
                {
                    "timestamp": log.get("__REALTIME_TIMESTAMP", timestamp),
                    "message": log.get("MESSAGE", ""),
                    "priority": log.get("PRIORITY", "6"),
                    "unit": log.get("_SYSTEMD_UNIT", "tailscaled"),
                    "hostname": log.get("_HOSTNAME", "unknown")
                }
                for log in system_logs
            ]
        }
    
    def send_event_to_wazuh(self, event):
        """Send event to Wazuh Events API"""
        try:
            headers = {
                'Authorization': f'Bearer {self.auth_token}',
                'Content-Type': 'application/json'
            }
            
            # Use the events API endpoint
            url = f"{self.wazuh_url}/events"
            
            response = requests.post(
                url,
                json=event,
                headers=headers,
                verify=False,
                timeout=10
            )
            
            if response.status_code in [200, 201, 202]:
                print(f"✅ Event sent to Wazuh: {response.status_code}")
                return True
            else:
                print(f"⚠️  Wazuh response: {response.status_code} - {response.text}")
                return False
        except Exception as e:
            print(f"❌ Error sending event to Wazuh: {e}")
            return False
    
    def collect_and_send(self):
        """Main method: collect logs and send to Wazuh"""
        print("Starting Tailscale log collection and Wazuh integration...")
        
        # Authenticate first
        if not self.authenticate():
            sys.exit(1)
        
        # Collect logs
        status = self.get_tailscale_status()
        if not status:
            print("Failed to get Tailscale status")
            sys.exit(1)
        
        system_logs = self.get_system_logs(lines=50)
        formatted_logs = self.format_for_wazuh(status, system_logs)
        
        # Send to Wazuh
        if self.send_event_to_wazuh(formatted_logs):
            print("✅ All logs successfully sent to Wazuh")
        else:
            print("⚠️  Some logs failed to send")
            sys.exit(1)

def main():
    sender = WazuhLogSender()
    sender.collect_and_send()

if __name__ == "__main__":
    main()
