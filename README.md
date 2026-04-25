# Monitoring and detecting Dynamic Linker Hijacking against Linux Pluggable Authentication Module

## Requirement

> [!NOTE]
> This project is tested and ran on Ubuntu 22.04 LTS.

This project required following tools to install in advanced:
- OpenSSL dev
- Docker
- jq
You can use following bash to install the requirement.
```
sudo apt update
sudo apt install build-essential libssl-dev docker.io jq
```

## TODOs:
- [x] Monitoring service for /etc/pam.d & PAM core module.
- [x] Monitoring daemon service deployment script.
- [x] Tracee construction.
- [x] Analyzing scripts for Tracee output.
- [x] Daemon service for Tracee implementation.
- [x] Daemon service for analyzing scripts.
- [ ] Tidy up the codes to get formal output logs
- [ ] (Optional) Output the Tracee Analyzer logs to files

## Acknowledgement
Special thanks to the team at Aqua Security for developing [Tracee](https://github.com/aquasecurity/tracee). This project utilizes its powerful eBPF-based system monitoring and event tracing framework to gather events and analyze advanced execution flow hijacking techniques.

## Good luck

This is good luck Hoshino.

![image](https://cdn.discordapp.com/emojis/1346556552945078404.webp?size=96)
