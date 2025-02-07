### /SCRIPTS/ENUM

    fw.sh - Firewall (Network) Rules.

      [INFO]:
        - Checks if distro uses "pkg" (FreeBSD), if so, list pfctl rules and info.
        - Else, list iptables rules.
      [USAGE]:
        (if needed) chmod +x fw.sh
        ./fw.sh

    inventory.sh - Machine Information.

      [INFO]:
        - Detect OS.
        - List hostname, OS, RAM, storage, IP, users, sudoers, etc.
        - List running services.
        - List services such as:
            1. ssh
            2. docker
            3. apache2
            4. ftp
        - If docker detected, list active containers, anonymous mounts, and volume usage.
        - List listening ports.
        - Capture TCP/UDP port bindings and their services.
        - List files with SUID and world-writable.
        - List Apache config.

      [USAGE]:
        (if needed) chmod +x inventory.sh
        ./inventory.sh

    pam.sh - PAM Integrity.

      [INFO]:
        - Check PAM config.
        - Check file integrity.
        - Check module exec order.
        - Output pam_unix.so.

      [USAGE]:
        (if needed) chmod +x pam.sh
        ./pam.sh

    pii.sh - Search for PII.

      [INFO]:
        - Check for phone numbers, addresses, etc. in a variety of files and locations.

      [USAGE]:
        (if needed) chmod +x pii.sh
        ./pii.sh

    processes.sh - Display Running Processes.

      [INFO]:
        - Runs ps -ef --forest
        - Runs ps auxw
        - Runs ps -ef

      [USAGE]:
        (if needed) chmod +x pii.sh
        ./processes.sh

    real_ports.sh - Active Sockets & Connections

      [INFO]:
        - Get info using sockstat, ss, and/or netstat.

      [USAGE]:
        (if needed) chmod +x real_ports.sh
        ./real_ports.sh

    shells.sh - System Shell Integrity

      [INFO]:
        - Use sha256sum to calculate hashes for shells in /etc/passwd.
        - Get hashes in /etc/shells.
        - Compare to other files on system to see if they have the same hash.

      [USAGE]:
        (if needed) chmod +x shells.sh
        ./shells.sh

    webdb.sh - DB Config/Testing

      [INFO]:
        - Display OS.
        - Scan active services.
        - Scan for Docker, Apache, MySQL, PHP, etc.
        - Attempt to log in to databases with weak/default creds, and report results.
        - Collect users and configs.

      [USAGE]:
        (if needed) chmod +x webdb.sh
        ./webdb.sh

### /SCRIPTS/HARDEN

    cron.sh - Start/Restart/Stop Cron

      [INFO]:
        - If revert, start/restart cron.
        - Else, stop cron.

      [USAGE]:
        (REVERT=true) ./cron.sh

    kernel.sh - Network/Kernel/FS Hardening

      [INFO]:
        - Apply TCP/IP and Network hardening.
            1. Enable SYN cookies. (net.ipv4.tcp_syncookies)
            2. Set SYN/ACK retries = 2. (net.ipv4.tcp_synack_retries)
            3. Limit challenge ACKs = 1000000. (net.ipv4.tcp_challenge_ack_limit)
            4. Prevents TIME_WAIT assassination via RFC 1337. (net.ipv4.tcp_rfc1337)
            5. Ignore invalid ICMP errors. (net.ipv4.icmp_ignore_bogus_error_responses)
            6. Disable ICMP redirects. (net.ipv4.conf.all.accept_redirects)
            7. Disable ICMP echo responses. (net.ipv4.icmp_echo_ignore_all)
        - Apply Kernel hardening.
            1. Append PID to core dump filenames. (kernel.core_uses_pid)
            2. Hide kernel pointers from non-root. (kernel.kptr_restrict)
            3. Disable loading kernel modules after boot. (kernel.modules_disabled)
            4. Restrict access to performance events. (kernel.perf_event_paranoid)
            5. Enable full ASLR. (kernel.randomize_va_space)
            6. Disable SysRq key combinations. (kernel.sysrq)
            7. Restrict process tracing to parent processes. (kernel.yama.ptrace_scope)
        - Apply FS hardening.
            1. Protect against privilage escalation via hardlinks. (fs.protected_hardlinks)
            2. Prevent exploitation of symlinks in world-writable directories. (fs.protected_symlinks)
            3. Prevent core dumps from setuid programs. (fs.suid_dumpable)
            4. Disable creating unprivileged user namespaces. (kernel.unprivileged_userns_clone)
            5. Protect against unauthorized access to named pipes. (fs.protected_fifos)
            6. Regular files in world-writable directories cannot be accessed by unauthorized users. (fs.protected_regular)

      [USAGE]:
        ./kernel.sh

    pam.sh - Backup/Restore/Reinstall PAM Files.

      [INFO]:
        - Backup config to $BCK/pam.d.
        - Backup binary to $BCK/pam_libraries.
        - Reinstall/Revert if specified.

      [USAGE]:
        (REINSTALL=true) (REVERT=true) (UNTESTED=true) (BCK=/backup/dir) ./pam_manager.sh
          - $BCK defaults to "/root/.cache", can be set to different directory.
          - If REINSTALL=true, will reinstall PAM and update config.
          - If REVERT=true, restore PAM config and binaries from backup.
          - ALLOW/DENY=true will allow/deny network traffic after script runs.
          - UNTESTED=true will allow the script to run on untested distros.



    rbash.sh - Apply RBASH.

      [INFO]:
        - Backup /etc/passwd to $BCK/passwd.bak and /etc/passwd.bak.
        - $BCK defaults to "/root/.cache", can be set to different directory.
        - If REVERT=true, restore files from backup.
        - Update user shells to user /bin/rbash.

      [USAGE]:
        (BCK="/backup/dir") (REVERT=true) ./rbash.sh

    ssh.sh - SSH Config.

      [INFO]:
        - Target: /etc/ssh/sshd_config
        - Disable TCP forwarding.
        - Disable X11 forwarding.

      [USAGE]:
        (NOPUB=true) (AUTHKEY="/path/to/keys") (PERMITUSERS="user1 user2") (ROOTPUB=true) ./ssh.sh
          - If $NOPUB=true, disable public key auth.
          - $AUTHKEY can be used to set custom auth keys.
          - $PERMITUSERS restricts SSH access to specific users.
          - $ROOTPUB allows only the root user to auth with public keys.

### SCRIPTS/INITIAL

    firstrun.ssh - Initial Linux Configuration.

      [INFO]:
        - Backup /etc/passwd, /etc/group, and PAM files to $BCK.
        - Install tools, such as:
            1. net-tools
            2. curl
            3. iptables
            4. tar
            5. etc.
        - Disable SELinux, set to permissive.
        - Install Snoopy Logger, logs to $BCK/snoopy.log.
        - Get state of listening ports and established connections.
        - Enforce secure php.ini settings system-wide.
        - Restart key services to apply config.
        - Remove shell config files from all user home directories.

      [USAGE]:
        (ALLOW=true) (DENY=true) (BCK=/backup/dir) ./firstrun.sh
          - $BCK defaults to /root/.cache.
          - ALLOW/DENY=true will allow/deny traffic. Defaults to allowing traffic during software, then dropping after.

    fw.sh - Firewall Config,

      [INFO]:
        - Back up /etc/pf.conf to $BCK.
        - Allows loopback.
        - Create cron job to open firewall every 5 minutes.
        - Block all other traffic.

      [USAGE]:
        (DISPATCHER="192.168.1.1") (CCSHOST="192.168.0.2") (NOTNATS=true) (LOCALNETWORK="192.168.1.0/24") (BCK="/backup/dir") ./fw.sh
          - $DISPATCHER = IP to allow SSH.
          - $LOCALNETWORK = Permit traffic within $LOCALNETWORK.
          - $CCSHOST = If $NOTNATS is not set to 1, expects IP. Allows unrestricted traffic.
          - $BCK defaults to /root/.cache.

### /SCRIPTS/INJECT

    admins.sh - List users in sudo/wheel.

      [INFO]:
        - cat /etc/group | grep -E '(sudo|wheel)'

      [USAGE]:
        ./admins.sh

    faillog.sh - Search for Failed Logins.

      [INFO]:
        - Search for "Failed password" in:
            1. /var/log/secure
            2. /var/log/auth.log
            3. /var/log/messages

      [USAGE]:
        ./faillog.sh

    succlog.sh - Search for Successful Logins.

      [INFO]:
        - Search for "Accepted password" in:
            1. /var/log/secure
            2. /var/log/auth.log
            3. /var/log/messages

      [USAGE]:
        ./succlog.sh

    tenlog.sh - Login Attempt Usernames/IPs.

      [INFO]:
        - Search for "(Failed/Accepted) password" in:
            1. /var/log/secure
            2. /var/log/auth.log
            3. /var/log/messages
        - Display associated username/IP with login.

      [USAGE]:
        ./tenlog.sh

    totallog.sh - Combined succlog.sh and faillog.sh.

      [INFO]:
        - Search for "(Failed/Accepted) password" in:
            1. /var/log/secure
            2. /var/log/auth.log
            3. /var/log/messages

      [USAGE]:
        ./totallog.sh

### /SCRIPTS/LOGGING

    wazuh.sh - Install and Start Wazuh Agent.

      [INFO]:
        - Install Wazuh.
        - Login.
        - Start service.

      [USAGE]:
        WAZUH_MANAGER="www.example.com" DOWNLOAD_URL="www.example.com"
          - $WAZUH_MANAGER (URL) = Address of Wazuh Manager.
          - $DOWNLOAD_URL (URL) = Address of Wazuh Manager download.
              1. $package = wazuh-agent_4.9.2-1_${ARCH_PKG}.deb/rpm
              2. ARCH_PKG is a built in function variable to detect x86_64 or i386.
              3. Download command: wget/curl/fetch -O $package $DOWNLOAD_URL/$package.
          - $WAZUH_REGISTRATION_PASSWORD (String) = Registration password, if provided.

### /SCRIPTS/MISC

    allow_fw.sh - Allow All Traffic

      [INFO]:
        - Sets input, output, and foward to all.

      [USAGE]:
        ./allow_fw.sh

    deploy_key.sh - Add SSH Key.

      [INFO]:
        - Writes $KEY to $FILE.
        - $FILE defaults to "~/.ssh/authorized_keys".
        - Sets file ownership to root.
        - Set file permissions to read/write for root, read for other users.

      [USAGE]:
        KEY="KEY" (FILE="/path/to/file") ./deploy_key.sh
          - $KEY = Key to be imported.
          - $FILE = Location to import key.

    netdiff.sh - Display Network Differences.

      [INFO]:
        - Compares current output for netstat/sockstat/ss to output located in $BCK/initial.
        - Displays differences.

      [USAGE]:
        (BCK="/backup/dir") ./netdiff.sh
          - $BCK defaults to "/root/.cache".

    password.sh - Change User/Root Password(s).

      [INFO]:
        - Check if $ROOTPASS is set.
        - If $SSHUSER is set, $PASS must be set, and vice versa.
        - If $SSHUSER not defined, it assigns a non-existent string to $SSHUSER: "LOLNONEXISTANTSTRINGHEREBRUH".
        - Runs CHANGEPASSWORD().
        - Changes root password to $ROOTPASS.
        - Other users get random passwords.
        - Outputs results, "$user,$pass".

      [USAGE]:
        ROOTPASS="ROOTPASS" (SSHUSER="SSHUSER" PASS="PASS") (IGNOREUSERS="user1,user2")
          - $ROOTPASS = Specified new root password. If set to "YOLO", generate new root password.
          - $IGNOREUSERS = Users to not change passwords for.
          - $SSHUSER = Set SSH user.
          - $PASS = Set SSH user password.

    permit_root_ssh.sh - Allow root SSH.

      [INFO]:
        - Allow root login via sed. (PermitRootLogin)
        - Restart SSH.

      [USAGE]:
        ./permit_root_ssh.sh

    ping.sh - Connected SSH Client Info.

      [INFO]:
        - Outputs $SSH_CLIENT info.

      [USAGE]:
        ./ping.sh

    remove_fw_crontab.sh - Remove Crontab Entries & Backup Firewall.

      [INFO]:
        - Remove specific crontab entries (ones including -F or -d).
        - Backup firewall to $BCK.
        - Add cron job to restore firewall rules from $BCK/rules.v4 or $BCK/pf.conf every minute.

      [USAGE]:
        (BCK="/backup/dir") ./remove_fw_crontab.sh
          - $BCK = Backup directory path. Defaults to /root/.cache.

    snoopy.sh - Display Snoopy Logs.

      [INFO]:
        - Displays /etc/snoopy.ini.
        - Displays $BCK/snoopy.log.

      [USAGE]:
        (BCK="/backup/dir") (LAST=10) ./snoopy.sh
          - $BCK = The backup directory path.
          - $LAST = The number of recent lines to display.
              1. If LAST = 10, the 10 most recent lines will be displayed.

    sudo_tty.sh - Modify Sudoers.

      [INFO]:
        - Remove requiretty.
        - Add root to list of sudoers.

      [USAGE]:
        ./sudo_tty.sh

    userdiff.sh - Compare Current passwd & group Files to Backup.

      [INFO]:
        - Compare /etc/passwd to $BCK/users.
        - Compare /etc/group to $BCK/groups.

      [USAGE]:
        (BCK="/backup/dir") ./userdiff.sh
