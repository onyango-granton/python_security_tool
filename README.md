# Docker Security Monitor

A comprehensive security monitoring system for Docker containers that automatically detects and blocks malicious activities.

## Overview

This tool monitors Docker container logs for suspicious activities and automatically blocks IP addresses that show malicious behavior. It's designed to protect your Docker containers from common attack patterns like:

- Binary injection attacks
- SQL injection attempts
- Cross-site scripting (XSS)
- Path traversal attacks
- Command injection
- PHP injection attempts
- Suspicious shell commands
- Suspicious HTTP headers

## How It Works

### 1. Log Monitoring
The system continuously monitors your Docker container logs for:
- Failed authentication attempts
- Suspicious patterns in requests
- Malicious payloads
- Unusual behavior

### 2. Pattern Detection
The tool uses predefined patterns to identify potential attacks:
```json
{
    "binary_injection": "\\x[0-9a-fA-F]{2}",  // Detects binary data in requests
    "sql_injection": "(?i)(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER|EXEC)",  // SQL commands
    "xss": "(?i)(<script|javascript:|onerror=|onload=)",  // XSS attempts
    "path_traversal": "\\.\\./|\\.\\.\\\\",  // Directory traversal attempts
    "command_injection": "(?i)(;|&&|\\|\\||`|\\$)"  // Command injection attempts
}
```

### 3. IP Blocking
When suspicious activity is detected, the system:
1. Identifies the source IP address
2. Adds it to a blocked list
3. Updates firewall rules to block the IP
4. Logs the incident
5. Automatically unblocks the IP after 24 hours (configurable)

## Components

### 1. Security Monitor Script (`security_monitor.py`)
The main Python script that:
- Monitors Docker container logs
- Analyzes log entries for suspicious patterns
- Manages IP blocking and unblocking
- Maintains logs of security events

### 2. Configuration File (`monitor_config.json`)
Contains all configurable settings:
- Attack patterns to detect
- Thresholds for blocking
- Docker containers to monitor
- Block duration
- Log retention period
- Email notification settings

### 3. Systemd Service (`security-monitor.service`)
Manages the monitoring service:
- Runs the monitor every 30 minutes
- Automatically restarts if it fails
- Runs with necessary permissions

### 4. Installation Script (`install.sh`)
Sets up the entire system:
- Creates required directories
- Sets proper permissions
- Installs the service
- Starts the monitoring

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd <repository-directory>
```

2. Make the installation script executable:
```bash
chmod +x install.sh
```

3. Run the installation script as root:
```bash
sudo ./install.sh
```

## Configuration

Edit `monitor_config.json` to customize:

### Attack Patterns
Add or modify patterns to detect specific types of attacks:
```json
"patterns": {
    "your_pattern_name": "your_regex_pattern"
}
```

### Thresholds
Adjust when IPs get blocked:
```json
"thresholds": {
    "max_failed_auth": 5,        // Number of failed login attempts
    "max_pattern_matches": 3,    // Number of pattern matches
    "max_requests_per_minute": 100  // Rate limiting
}
```

### Docker Containers
Specify which containers to monitor:
```json
"docker_containers": ["container-name-1", "container-name-2"]
```

## Monitoring and Logs

### View Service Status
```bash
systemctl status security-monitor
```

### View Security Logs
```bash
tail -f /var/log/security-monitor/security_monitor.log
```

### View Blocked IPs
```bash
cat /opt/security-monitor/blocked_ips.json
```

## Security Features

1. **Automatic Detection**
   - Monitors logs in real-time
   - Uses pattern matching to identify attacks
   - Tracks failed authentication attempts

2. **IP Blocking**
   - Automatically blocks malicious IPs
   - Uses iptables for firewall rules
   - Temporary blocking (24 hours by default)

3. **Logging**
   - Detailed logs of all security events
   - IP blocking/unblocking events
   - Pattern matches and thresholds

4. **Self-Healing**
   - Automatic service restart
   - Regular monitoring checks
   - Error recovery

## Best Practices

1. **Regular Updates**
   - Keep the patterns updated
   - Monitor new attack vectors
   - Update thresholds based on your traffic

2. **Log Monitoring**
   - Regularly check security logs
   - Review blocked IPs
   - Adjust patterns if needed

3. **Configuration**
   - Start with strict thresholds
   - Adjust based on your traffic
   - Monitor false positives

## Troubleshooting

### Common Issues

1. **Service Not Starting**
   - Check permissions
   - Verify Docker is running
   - Check systemd logs

2. **False Positives**
   - Adjust pattern thresholds
   - Review blocked IPs
   - Modify patterns if needed

3. **High Resource Usage**
   - Adjust monitoring interval
   - Reduce log retention
   - Optimize patterns

## Contributing

Feel free to:
- Add new attack patterns
- Improve detection methods
- Add new features
- Report issues

## License

[Your License Here]

## Support

For issues and support:
- Open an issue in the repository
- Contact [Your Contact Information] 