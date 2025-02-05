```SC = Server Core
DC = Domain Controller
WinRM = Windows Remote Management
RDP = Remote Desktop
GPO = Group Policy Object
LSAAS: Local Security Authority Subsystem Service
ASR = Attack Surface Reduction
IIS = Internet Information Services
UAC = User Access Control

> Windows
    Comp.ps1 - List System Events.
        - List hostname/domain.
        - List IP.
        - List information about service creation events.
            1. Creation date.
            2. Service name.
            3. Binary path.
        - List information about password change events.
            1. Computer name.
            2. User name.
            3. Password change date.
        - List information about share access events.
            1. Share name.
            2. Username accessing the share.
            3. IP.
            4. Access Mask.
            5. Event time.
    DisableFWTask.ps1 - Disable FWRevert. (defined in FWALL.ps1)
    FWALL.ps1 ($Dispatcher, $Localnetwork, $Notnats) - Set Firewall Rules.
        - Export current firewall config.
        - Setup FWRevert. FWRevert will run in 5 minutes.
        - Disable firewall profiles.
        - Block all traffic.
        - Delete firewall rules with name=all.
        - Allow WinRM. (ports: 80, 5985, 5986)
        - Allow RDP. (port 3389)
        - Allow in/out traffic for $Localnetwork.
        - If $Notnats != "NOTNATS", open in/out for $Notnats.
        - Enable Firewall.
    Fix.ps1 - Set UI Changes.
        - List hostname/domain.
        - List IP.
        - Reset group policy after making copy at C:\gp.
        - Set fonts to Segoe UI, and delete substitutes.
        - Set font activation to auto and delete inactive fonts/langs.
        - Set keyboard to EN-US.
        - Set UI to EN-US.
        - Expose hidden files, show file ext.s, show super hidden files (sys files).
    Gpo.ps1 - Disable GPOs.
        - List hostname/domain.
        - List IP.
        - Disable all settings in GPO.
    Hard.ps1 - Harden System.
        - List hostname/domain.
        - List IP.
        - Detect if machine == DC
        - GENERAL REGKEYS:
            1. Disable LM hashes for passwords < 15 chars.
            2. Force NTLMv2.
            3. Disable plaintext WDigest creds.
            4. Enable UAC for local accs.
            5. Enable LSASS.
            6. Configure Auditing for LSASS.
        - DEFENDER REGKEYS:
            1. Enable cloud-based prot.
            2. Enable RTM.
            3. Enable advanced protection.
            4. etc.
        - ASR rules blocking:
            1. Office applications injecting code.
            2. Scripts launching executables.
            3. Untrusted/Unsigned USB processes.
            4. etc.
        - Disable print spooler.
        - Enable RDP NLA.
        - Mitigate CVE-2020-1472. (Netlogon)
        - Mitigate CVE-2021-42278, CVE-2021-42287. (AD domain)
        - Mitigate CVE-2021-34527. (Restrict driver installs; Print spooler config)
        - Enforce LDAP signing requirements. (client & server)
        - Disable BITS transfers.
        - Enforce high security for UAC. (LUA, Consent Prompts, Installer Detection)
    Inv.ps1 - List System Info.
        - List hostname/domain.
        - List IP.
        - List current user info.
        - List OS info.
        - Detect if DC or SC.
        - If DC: Query DNS.
        - SMB shares info.
        - Detect IIS, if installed, import WebAdministration and report site bindings.
        - Scan for SQL, Apache, Nginx, etc.
        - Detect NSSM services.
        - List group memberships info.
        - List all users.
        - List info on current TCP connections. (netstat)
        - List installed programs.
        - List DNS servers.
        - List startup registry entries.
        - List scheduled tasks.
        - List installed Windows features.
    LEADInv.ps1 - Altered Inv.ps1.
        - List hostname/domain.
        - List OS.
        - Detect if backup DC or main DC.
        - List IP.
        - List gateway.
        - List DNS.
        - RAM and Storage info.
        - Scan for SQL, Apache, Nginx, etc.
        - List all users.
        - List info on current TCP connections. (netstat)
    Log.ps1 - Enable Logging for PS, IIS, & auditpol; Install Sysmon & smce.
        - List hostname/domain.
        - List IP.
        - Enable auditpol.
        - Allow process creation events to include command line args.
        - Enable PowerShell command transcription. Saves activity to PSLogs.
        - Log scripts & modules.
        - Enable IIS logging.
        - Configure Sysmon.
    Prop.ps1 ($Hosts, $Cred, $Timeout, $Purge) - File Transfer / Network Drive Removal.
        - Check if port 445 is open, if so, establish TCP connection.
        - Map a network drive to C$ share on target, and copy files from local (.\bins) to target (C$\Windows\System32).
        - If $Purge, remove all mapped drives.
    Run.ps1 - Run Scripts.
        - Connect to computers via hosts or Active Directory if $NonDomain is not used.
        - If $NonDomain used, script operates on non-domain computers.
        - Check ports 5985, 5986 to verify connectivity.
        - If connection fails or $Repair, attempt to re-establish connections.
        - Once established, copy/run file on remote systems.
        - Results saved in specified output dir.

        USAGE NOTES:
        - $Include & $Exclude are used to specify which machines should be selected.
        - $ScriptArgs contains args for the remote script.
        - $Path is where destination files will be copied.
        - $Hosts is a path to list of hostnames/IPs to operate on.
        - $File is the path to the file to be copied.
        - $Script is the path to the script to be executed.
        - $Out is the directory for saving outputs from scripts.
    SMB.ps1 - Configure SMB.
        - List hostname/domain.
        - List IP.
        - Disable SMBv1.
        - Enable "RequireSecuritySignature" for server and workstation.
        - If share is not exempt, apply read-only for all accounts that have access.
    TestPort.ps1 ($IP, $Port, $Timeout, $Verbose) - Check if TCP Port is Open.
    Usr.ps1 ($UserPassword, $AdminPassword, $Exclude) - Change User Passwords.
        - If $UserPassowrd == "YOLO", GeneratePassword().
            1. If secondary DC, skip password reset.
            2. Else, if primary DC:
                - Handles user ttuccdc (would need to change to efscccdc?), checking if it exists, settings password, and adding to groups. (Admin, Remote Desktop, Domain Admin)
                - Retrieves all AD users and changes passwords. (Skip if in $Exclude)
            3. Else, if not DC:
                - Change passwords of local users. (Skip if in $Exclude)
                - Check for user ttuccdc, if not, create it, set password, and add to groups.
            4. Results logged in $CSVArray and outputted.
    Wazuh.ps1 ($Manager, $RegistrationPassword) - Install Wazuh and Run.
        - If installer located at $DownloadPath, install Wazuh agent silently (msiexec), and pass manager IP/hostname, as well as RegistrationPassword if provided.
        - Set WazuhSvc to start automatically.
    Web.ps1 - HTTP Server.
        - Serves files from $Webroot on $IP on $Port.
        - Responds to URL path.
        - If path exists and is directory, list files in directory, and if path leads to file, read contents.
    Webshell_Hunter.ps1 - Scanning for Webshells.
        - Search for cmd.exe or powershell.exe processes that belong to w3wp.exe or httpd.exe, and flag such instances.
    echo.ps1 - WinRM Connection Info.
        - Check if WinRM ports are in use, and if so, print remote IP addresses.
    php.ps1 - PHP Config.
        - Locate PHP on system and load config files.
        - Edit config to disable PHP functions such as exec and passthru.
        - Disable file uploads.
    pii_search_task.ps1 - Create Task for pii_search.ps1 (which is located in /bins)
    postprocessing.ps1 ($InventoryFolder, $Extension) - Compare Outputs
        - Search for files with specific extension in specified folder.
        - Extract data between "start" and "end" lines of given text. e.g., start = "#### Start IP ####".
            1. Parse Host data, IP, DNS, IIS, DC, Users, Group Members, Start Features, Registry Startups, Scheduled tasks, etc.
        - Compares data between outputs.
    > Bins
        Reset-KrbTgt-Password-For-RWDCs-And-RODCs.ps1 - Self Explanatory.
            - OG source: https://jorgequestforknowledge.wordpress.com/2018/12/30/powershell-script-to-reset-the-krbtgt-account-password-keys-for-both-rwdcs-and-rodcs/
        pii_search.ps1 - Search for PII.
            - Create directory C:\Windows\System32\PII if it does not exist.
            - Checks for files like .docx, .pdf, etc. and scan for types of PII (phone, SSN, addresses, etc.).
            - If 20+ matches, log findings in file pii.txt in C:\Windows\System32\PII and sort.
        A long list of .exes for ease of install during competition.
            - https://github.com/LByrgeCP/dumbssh/tree/main/Windows/bins
