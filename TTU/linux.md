/SCRIPTS/ENUM

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

/SCRIPTS/HARDEN

    TODO.
