#!/bin/bash

# This code utilizes security/forensics tool `Tracee` from Aqua Security
# (https://github.com/aquasecurity/tracee) for event collection.


cleanup() {
    echo -e "\n[*] 收到中斷訊號，正在關閉 Tracee 容器..."
    sudo docker rm -f tracee >/dev/null 2>&1
    echo "[*] 監控已安全結束。"
    exit 0
}
trap cleanup EXIT SIGINT SIGTERM

perform_analysis() {
    local so_file=$1
    local defined_symbols=$(nm -D "$so_file" 2>/dev/null | grep -v ' U ' | awk '{print $3}')
    local hook_found=0
    
    for func in "${DANGEROUS_FUNCTIONS[@]}"; do
        if echo "$defined_symbols" | grep -qx "$func"; then
            echo -e "  \033[0;31m[!] 警告: 發現危險 Hook 實作 -> ${func}()\033[0m"
            hook_found=1
        fi
    done

    if [ $hook_found -eq 0 ]; then
         echo "  [+] 安全: 未發現已知特徵。"
    fi
}

analyze_stream() {
    echo "[*] 啟動靜態分析器..."
    DANGEROUS_FUNCTIONS=("pam_authenticate" "pam_acct_mgmt" "open" "execve")
    declare -A SCANNED_FILES
    jq --unbuffered -r '
        select(.eventName == "shared_object_loaded" or .eventName == "ld_preload") | 

        (
        (.args[]? | select(.name=="pathname") | .value) //
	    (.args[]? | select(.name=="detectedFrom") | .value.args[]? | select(.name=="pathname") | .value) //
	    ""
	    ) as $pathname |

        ([.args[]? | select(.name=="detectedFrom") | .value.name? | select(. != null)] | join(" ")) as $arg_names |
        
        "\(.eventName)\t\($pathname)\t\($arg_names)"
        
        ' | while IFS=$'\t' read -r event_name target_file arg_names; do

        # 過濾空行
        if [ -z "$event_name" ]; then continue; fi

        case "$event_name" in
            
            "ld_preload")
                echo "---------------------------------------------------"
                if [[ " $arg_names " == *" sched_process_exec "* ]]; then
                    echo -e "\033[1;35m[!] 警報: environment variables changed\033[0m"
                    echo "    目標程序: $target_file"
                
                elif [[ " $arg_names " == *" security_file_open "* ]]; then
                    echo -e "\033[1;41;37m[!!!] 嚴重警報: /etc/ld.so.preload being accessed\033[0m"
                
                elif [[ " $arg_names " == *" security_inode_rename "* ]]; then
                    echo -e "\033[1;41;37m[!!!] 嚴重警報: /etc/ld.so.preload renamed\033[0m"
                
                else
                    echo -e "\033[1;33m[?] 警告: 未歸類的 LD_PRELOAD 觸發事件 (包含特徵: $arg_names)\033[0m"
                fi
                echo "---------------------------------------------------"
                ;;

            "shared_object_loaded")
                if [ ! -f "$target_file" ] || [ ! -r "$target_file" ]; then continue; fi

                file_hash=$(sha256sum "$target_file" | awk '{print $1}')
                if [[ -n "${SCANNED_FILES[$file_hash]}" ]]; then continue; fi
                SCANNED_FILES[$file_hash]=1

                echo "[*] [$(date '+%H:%M:%S')] 載入: $target_file (Hash: ${file_hash:0:8}...)"
                perform_analysis "$target_file"
                echo "---------------------------------------------------"
                ;;
        esac
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


