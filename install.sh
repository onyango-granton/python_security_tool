#!/bin/bash

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "Please run as root"
    exit 1
fi

# Create installation directory
INSTALL_DIR="/opt/security-monitor"
mkdir -p $INSTALL_DIR

# Copy files to installation directory
cp security_monitor.py $INSTALL_DIR/
cp monitor_config.json $INSTALL_DIR/
cp security-monitor.service /etc/systemd/system/

# Set proper permissions
chmod +x $INSTALL_DIR/security_monitor.py
chown -R root:root $INSTALL_DIR

# Create log directory
mkdir -p /var/log/security-monitor
chown root:root /var/log/security-monitor

# Reload systemd
systemctl daemon-reload

# Enable and start the service
systemctl enable security-monitor
systemctl start security-monitor

echo "Security monitor has been installed and started."
echo "You can check the status with: systemctl status security-monitor"
echo "Logs are available at: /var/log/security-monitor/security_monitor.log" 