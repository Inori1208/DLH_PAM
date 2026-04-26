# DLH_PAM

This project aims to monitor and detect Dynamic Linker Hijacking against Linux Pluggable Authentication Module(PAM).

## Requirement

> [!NOTE]
> This project is tested and runs on Ubuntu 22.04 LTS.

This project required the following tools to be installed in advance:
- OpenSSL dev
- Docker
- jq

You can use the following bash script to install the requirements.
```
sudo apt update
sudo apt install build-essential libssl-dev docker.io jq
```

## How to use

This project will deploy 2 daemon services, `pam_guard.service` and `tracee_analyzer.service`.
You can run `sudo pam_guard_deploy.sh` and `sudo tracee_analyzer_deploy.sh` scripts to deploy the monitoring service.

> If you ran into a problem with executing the scripts, use `sudo chmod +x pam_guard_deploy.sh tracee_analyzer_deploy.sh tracee_analysis.sh` to change the execution permissions.
> If this didn't solve your problem, please read the error information output by the scripts.

After deploying the services, you can use `sudo systemctl status pam_guard.service` and `sudo systemctl status tracee_analyzer.service` to see the service status.

To inspect the output log from the services:
- Use `sudo journalctl -u pam_guard.service -f` or `tail -f /var/log/pam_guard.log` to check changes from PAM configuration and PAM Modules.
- Use `sudo journalctl -u tracee_analyzer.service -f` to track down events related to Dynamic Linker Hijacking 
> [!NOTE]
> The output mainly shows file access/modification, function hooking, shared object loading, etc.

## Simple attack rehearsal implementation

To test the functionality of the service, please open both services' log on the terminal after deployed.
> [!WARNING]
> Please **avoid** changing any contents inside PAM configuration and module as much as possible, or testing it while in *VM* or *sandbox environment*. Since the module is in charge of the system authentication process, it might cause some issues with the system security.

- File modification
    - Try adding a description to files inside `/etc/pam.d` and check if pam_guard's log output anything.
    - Try adding a description to files inside `/etc/ld.so.preload` and check if tracee_analyzer's log output anything.

- Changing LD_PRELOAD environment variable
    - Inside `./simple_attack_implementation` contains 2 files, `Login` and `always_true.so`. Try `./Login` first, the Login executable asks for the username and the password, and the login process will run through PAM. After that, try `LD_PRELOAD=./always_true.so ./Login` in the terminal, you'll see that, whatever you type into username, it'll output **passed** in the result. Please check if tracee_analyzer's log output anything.

- /etc/ld.so.preload
    - The content inside `/etc/ld.so.preload` will be preloaded by the Linux system. Try adding the ***absolute path*** of the `always_true.so` inside the file. And you'll see that every action you do won't need authentication, sudo, or login into the system, even ssh connection's authentication has lost its functionality (ssh's authentication will process through PAM in the default setting). Please check if tracee_analyzer's log output anything.


## TODOs:

- [x] Monitoring service for /etc/pam.d & PAM core module.
- [x] Monitoring daemon service deployment script.
- [x] Tracee construction.
- [x] Analyzing scripts for Tracee output.
- [x] Daemon service for Tracee implementation.
- [x] Daemon service for analyzing scripts.
- [x] Tidy up the codes to get formal output logs
- [ ] (Optional) Output the Tracee Analyzer logs to files

## Acknowledgement

Special thanks to the team at Aqua Security for developing [Tracee](https://github.com/aquasecurity/tracee). This project utilizes its powerful eBPF-based system monitoring and event tracing framework to gather events and analyze advanced execution flow hijacking techniques.

## Good luck

This is good luck Hoshino.

![image](https://cdn.discordapp.com/emojis/1346556552945078404.webp?size=96)
