#!/bin/bash

#Variables
SOURCE_SCRIPT="tracee_analysis.sh"
TARGET_DIR="/usr/local/bin/$SOURCE_SCRIPT"
SERVICE_NAME="tracee_analyzer.service"
SERVICE_PATH="/etc/systemd/system/$SERVICE_NAME"

echo "[info] Tracee Analyzer deployment started..."

#Check if former service is still active
if systemctl is-active --quiet "$SERVICE_NAME"; then
    echo "[info] Stopping the older version of $SERVICE_NAME ..."
    systemctl stop "$SERVICE_NAME"
fi

#Check if the executor has root privilege
if [ "$EUID" -ne 0 ]; then
  echo "[error] You need root privilege to deploy the service."
  exit 1
fi

#Check if ./tracee_analysis.sh is exist
if [ ! -f "$SOURCE_SCRIPT" ]; then
  echo "[error] $SOURCE_SCRIPT not found, please make sure $SOURCE_SCRIPT is in the same directory."
  exit 1
fi

#Copy the shell code
cp "$SOURCE_SCRIPT" "$TARGET_DIR"
chown root:root "$TARGET_DIR"
chmod 700 "$TARGET_DIR"

#Generate systemd config
echo "[info] Generating Systemd configuration file ($SERVICE_PATH)..."
cat <<EOF > "$SERVICE_PATH"
[Unit]
Description=Tracee LD_PRELOAD Behavior Analyzer
After=network.target docker.service
Wants=docker.service

[Service]
Type=simple
ExecStart=$TARGET_DIR
Restart=always
RestartSec=5
User=root
# 將腳本的 echo 輸出導向系統日誌 (journald)
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
chmod 644 "$SERVICE_PATH"

#Starting the service
echo "[info] Starting the Systemd service..."
systemctl daemon-reload
systemctl enable "$SERVICE_NAME"
systemctl restart "$SERVICE_NAME"

#Check if the service is active
if systemctl is-active --quiet "$SERVICE_NAME"; then
    echo -e "\033[0;32m[success] Tracee Analyzer deployment successed.\033[0m"
    echo "You can use \`sudo journalctl -u $SERVICE_NAME -f\` to track down the output of the service."
else
    echo -e "\033[0;31m[error] The service is registered, but it encountered some problem, the service is inactive.\033[0m"
    echo "Please check \`sudo systemctl status $SERVICE_NAME\` for more information."
fi