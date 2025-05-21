#!/usr/bin/env python3

import subprocess
import re
import json
import logging
from datetime import datetime
import os
from pathlib import Path
import time

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/security-monitor/security_monitor.log'),
        logging.StreamHandler()
    ]
)

class SecurityMonitor:
    def __init__(self, config_file='monitor_config.json'):
        self.config = self.load_config(config_file)
        self.blocked_ips = set()
        self.load_blocked_ips()
        
    def load_config(self, config_file):
        default_config = {
            "patterns": {
                "binary_injection": r"\\x[0-9a-fA-F]{2}",
                "sql_injection": r"(?i)(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER|EXEC)",
                "xss": r"(?i)(<script|javascript:|onerror=|onload=)",
                "path_traversal": r"\.\./|\.\.\\",
                "command_injection": r"(?i)(;|&&|\|\||`|\\$)"
            },
            "thresholds": {
                "max_failed_auth": 5,
                "max_pattern_matches": 3
            },
            "docker_containers": ["fleetbase-httpd-latest"],
            "block_duration": 86400,  # 24 hours in seconds
            "check_interval": 1800  # 30 minutes in seconds
        }
        
        if os.path.exists(config_file):
            with open(config_file, 'r') as f:
                return {**default_config, **json.load(f)}
        return default_config

    def load_blocked_ips(self):
        blocked_file = 'blocked_ips.json'
        if os.path.exists(blocked_file):
            with open(blocked_file, 'r') as f:
                self.blocked_ips = set(json.load(f))

    def save_blocked_ips(self):
        with open('blocked_ips.json', 'w') as f:
            json.dump(list(self.blocked_ips), f)

    def get_container_logs(self, container_id):
        try:
            result = subprocess.run(
                ['docker', 'logs', '--tail', '1000', container_id],
                capture_output=True,
                text=True
            )
            return result.stdout
        except Exception as e:
            logging.error(f"Error getting logs for container {container_id}: {e}")
            return ""

    def analyze_logs(self, logs):
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        ip_matches = {}
        
        for line in logs.split('\n'):
            # Extract IP address
            ip_match = re.search(ip_pattern, line)
            if not ip_match:
                continue
                
            ip = ip_match.group(0)
            if ip in self.blocked_ips:
                continue
                
            if ip not in ip_matches:
                ip_matches[ip] = {
                    'patterns': {},
                    'failed_auth': 0
                }
            
            # Check for failed authentication
            if 'authentication failure' in line.lower():
                ip_matches[ip]['failed_auth'] += 1
            
            # Check for malicious patterns
            for pattern_name, pattern in self.config['patterns'].items():
                if re.search(pattern, line):
                    if pattern_name not in ip_matches[ip]['patterns']:
                        ip_matches[ip]['patterns'][pattern_name] = 0
                    ip_matches[ip]['patterns'][pattern_name] += 1
        
        return ip_matches

    def block_ip(self, ip, reason):
        if ip in self.blocked_ips:
            return
            
        try:
            # Add IP to blocked list
            self.blocked_ips.add(ip)
            self.save_blocked_ips()
            
            # Update firewall rules
            subprocess.run(['iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'])
            
            logging.warning(f"Blocked IP {ip} for reason: {reason}")
            
            # Schedule unblock after block_duration
            unblock_time = datetime.now().timestamp() + self.config['block_duration']
            with open('blocked_ips.json', 'r+') as f:
                data = json.load(f)
                data[ip] = {'unblock_time': unblock_time, 'reason': reason}
                f.seek(0)
                json.dump(data, f)
                f.truncate()
                
        except Exception as e:
            logging.error(f"Error blocking IP {ip}: {e}")

    def check_and_unblock_ips(self):
        try:
            with open('blocked_ips.json', 'r') as f:
                blocked_data = json.load(f)
                
            current_time = datetime.now().timestamp()
            for ip, data in list(blocked_data.items()):
                if current_time >= data['unblock_time']:
                    subprocess.run(['iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP'])
                    self.blocked_ips.remove(ip)
                    logging.info(f"Unblocked IP {ip}")
            
            self.save_blocked_ips()
        except Exception as e:
            logging.error(f"Error checking blocked IPs: {e}")

    def run(self):
        logging.info("Starting security monitoring...")
        
        while True:
            try:
                # Check and unblock expired IPs
                self.check_and_unblock_ips()
                
                # Get running containers
                result = subprocess.run(['docker', 'ps', '--format', '{{.ID}}'], capture_output=True, text=True)
                container_ids = result.stdout.strip().split('\n')
                
                for container_id in container_ids:
                    if container_id in self.config['docker_containers']:
                        logs = self.get_container_logs(container_id)
                        ip_matches = self.analyze_logs(logs)
                        
                        for ip, data in ip_matches.items():
                            # Check failed authentication
                            if data['failed_auth'] >= self.config['thresholds']['max_failed_auth']:
                                self.block_ip(ip, f"Too many failed authentication attempts: {data['failed_auth']}")
                            
                            # Check pattern matches
                            for pattern_name, count in data['patterns'].items():
                                if count >= self.config['thresholds']['max_pattern_matches']:
                                    self.block_ip(ip, f"Detected {pattern_name} pattern {count} times")
                
                logging.info("Completed security check cycle")
                time.sleep(self.config['check_interval'])
                
            except Exception as e:
                logging.error(f"Error in monitoring cycle: {e}")
                time.sleep(30)  # Wait 30 seconds before retrying on error

if __name__ == "__main__":
    monitor = SecurityMonitor()
    monitor.run() 