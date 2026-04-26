#!/bin/bash

# This code utilizes security/forensics tool `Tracee` from Aqua Security
# (https://github.com/aquasecurity/tracee) for event collection.


cleanup() {
    echo -e "\n[info] Shutting down Tracee container..."
    sudo docker rm -f tracee >/dev/null 2>&1
    echo "[info] The service has ended safely."
    exit 0
}
trap cleanup EXIT SIGINT SIGTERM

perform_analysis() {
    local so_file=$1
    local defined_symbols=$(nm -D "$so_file" 2>/dev/null | grep -v ' U ' | awk '{print $3}')
    local hook_found=0
    
    for func in "${DANGEROUS_FUNCTIONS[@]}"; do
        if echo "$defined_symbols" | grep -qx "$func"; then
            echo -e "\033[1;41;37m[Alert] Dangerous hooking implementation detected -> ${func}()\033[0m"
            hook_found=1
        fi
    done

    if [ $hook_found -eq 0 ]; then
         echo -e "\033[0;32m[safe] No known denger function detected.\033[0m"
    fi
}

analyze_stream() {
    echo "[info] Activating analyzer..."
    DANGEROUS_FUNCTIONS=("pam_authenticate" "pam_acct_mgmt" "open" "execve" "pam_get_password" "pam_log_password" "pam_open_session" "pam_sm_authenticate")
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
                    echo -e "\033[1;33m[warning]: Environment variables changed\033[0m"
                    echo -e "\033[1;33m| Target file: $target_file\033[0m"
                
                elif [[ " $arg_names " == *" security_file_open "* ]]; then
                    echo -e "\033[1;41;37m[alert]: /etc/ld.so.preload being accessed\033[0m"
                
                elif [[ " $arg_names " == *" security_inode_rename "* ]]; then
                    echo -e "\033[1;41;37m[alert]: /etc/ld.so.preload renamed\033[0m"
                
                else
                    echo -e "\033[1;33m[warning?] Uncategorized LD_PRELOAD event triggered (Detected feature: $arg_names)\033[0m"
                fi
                echo "---------------------------------------------------"
                ;;

            "shared_object_loaded")
                if [ ! -f "$target_file" ] || [ ! -r "$target_file" ]; then continue; fi

                file_hash=$(sha256sum "$target_file" | awk '{print $1}')
                if [[ -n "${SCANNED_FILES[$file_hash]}" ]]; then continue; fi
                SCANNED_FILES[$file_hash]=1

                echo "[info] [$(date '+%H:%M:%S')] Loaded: $target_file (Hash: ${file_hash:0:8}...)"
                perform_analysis "$target_file"
                echo "---------------------------------------------------"
                ;;
        esac
    done
}

echo "[info] Activating Tracee..."

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


