#!/bin/bash

#Variables
SOURCE_CPP="pam_guard.cpp"
BINARY_NAME="pam_guard"
TARGET_DIR="/usr/local/bin"
TARGET_BINARY="$TARGET_DIR/$BINARY_NAME"
SERVICE_NAME="pam_guard.service"
SERVICE_PATH="/etc/systemd/system/$SERVICE_NAME"

echo "[info] PAM Guard deployment started..."

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

#Check if ./pam_guard.cpp is exist
if [ ! -f "$SOURCE_CPP" ]; then
  echo "[error] $SOURCE_CPP not found, please make sure $SOURCE_CPP is in the same directory."
  exit 1
fi

#Check if the system has g++
if ! command -v g++ &> /dev/null; then
    echo "[error] The system didn't install g++."
    exit 1
fi

#Compile the code
echo "Compiling $SOURCE_CPP ..."
g++ -o "$BINARY_NAME" "$SOURCE_CPP" -lssl -lcrypto
if [ $? -ne 0 ]; then
    echo "[error] Please check whether you had install OpenSSL."
    exit 1
fi
#echo "-> 編譯成功！已產生執行檔: $BINARY_NAME"

#Copy the executable
echo "[info] Compiled successfully."
cp "$BINARY_NAME" "$TARGET_BINARY"
chown root:root "$TARGET_BINARY"
chmod 700 "$TARGET_BINARY"
#echo "-> 執行檔權限已設定為 700 (僅 root 可執行)"

#Generate systemd config
echo "[info] Generating Systemd configuration file ($SERVICE_PATH)..."
cat <<EOF > "$SERVICE_PATH"
[Unit]
Description=PAM Integrity Guard
After=network.target

[Service]
Type=simple
ExecStart=$TARGET_BINARY
Restart=always
RestartSec=3
User=root
# 設定 OOMScoreAdjust 防止系統資源耗盡時優先殺除此防禦服務
OOMScoreAdjust=-1000

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
    echo -e "\033[0;32m[success] PAM Guard deployment successed.\033[0m"
    echo "You can use \`sudo journalctl -u $SERVICE_NAME -f\` or \`tail -f /var/log/pam_guard.log\`"
    echo "to track down the output of the service."
else
    echo -e "\033[0;31m[error] The service is registered, but it encountered some problem, the service is inactive.\033[0m"
    echo "Please check \`sudo systemctl status $SERVICE_NAME\` for more information."
fi