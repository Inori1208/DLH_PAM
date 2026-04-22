#!/bin/bash


cleanup() {
    echo -e "\n[*] 收到中斷訊號，正在關閉 Tracee 容器..."
    sudo docker rm -f tracee >/dev/null 2>&1
    echo "[*] 監控已安全結束。"
    exit 0
}
trap cleanup EXIT SIGINT SIGTERM

analyze_stream() {
echo "[*] 啟動靜態分析器..."
DANGEROUS_FUNCTIONS=("pam_authenticate" "pam_acct_mgmt" "open" "execve")
declare -A SCANNED_FILES
jq --unbuffered -r '.args[]? | select(.name=="pathname") | .value' | while read -r so_file; do
    
    if [ ! -f "$so_file" ] || [ ! -r "$so_file" ]; then continue; fi

    file_hash=$(sha256sum "$so_file" | awk '{print $1}')

    # 去重機制
    if [[ -n "${SCANNED_FILES[$file_hash]}" ]]; then continue; fi
    SCANNED_FILES[$file_hash]=1

    echo "[*] [$(date '+%H:%M:%S')] 載入: $so_file (Hash: ${file_hash:0:8}...)"
    
    # 靜態分析
    defined_symbols=$(nm -D "$so_file" 2>/dev/null | grep -v ' U ' | awk '{print $3}')
    
    hook_found=0
    for func in "${DANGEROUS_FUNCTIONS[@]}"; do
        if echo "$defined_symbols" | grep -qx "$func"; then
            echo -e "  \033[0;31m[!] 警告: 發現危險 Hook 實作 -> ${func}()\033[0m"
            hook_found=1
        fi
    done

    if [ $hook_found -eq 0 ]; then
         echo "  [+] 安全: 未發現已知特徵。"
    fi
    echo "---------------------------------------------------"
done
}

echo "[*] 啟動Tracee..."

sudo docker run --name tracee --rm \
  --pid=host --cgroupns=host --privileged \
  -v /etc/os-release:/etc/os-release-host:ro \
  -v /var/run:/var/run:ro \
  -v /sys/fs/cgroup:/sys/fs/cgroup:ro \
  -v /lib/modules:/lib/modules:ro \
  -v /usr/src:/usr/src:ro \
  -v /boot:/boot:ro \
  -v /tmp/tracee:/tmp/tracee \
  aquasec/tracee:latest \
  --output json \
  --output option:exec-env \
  --events ld_preload \
  --events shared_object_loaded \
  --events "shared_object_loaded.args.pathname!=/lib/*" \
  --events "shared_object_loaded.args.pathname!=/usr/lib/*" \
  --events "shared_object_loaded.args.pathname!=/lib64/*" | analyze_stream


