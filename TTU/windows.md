SC: Server Core
DC: Domain Controller
WinRM: Windows Remote Management
RDP: Remote Desktop
GPO: Group Policy Object
LSAAS: Local Security Authority Subsystem Service
ASR: Attack Surface Reduction
IIS: Internet Information Services
UAC: User Access Control

## > Windows

    ### Comp.ps1 - List System Events.
        - List hostname/domain.
        - List IP.
        - List information about service creation events.
            - Creation date.
            - Service name.
            - Binary path.
        - List information about password change events.
            - Computer name.
            - User name.
            - Password change date.
        - List information about share access events.
            - Share name.
            - Username accessing the share.
            - IP.
            - Access Mask.
            - Event time.

        #### [USAGE]:
            .\Comp.ps1

    ### DisableFWTask.ps1 - Disable FWRevert. (defined in FWALL.ps1)

        #### [USAGE]:
            .\DisableFWTask.ps1

    ### FWALL.ps1 - Set Firewall Rules.
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

        #### [USAGE]:
            .\FWALL.ps1 -ScriptArgs "$Dispatcher;$Localnetwork;$Notnats"
            - $Dispatcher (IP addr.) = IP to allow WinRM and RDP requests from.
            - $Localnetwork (IP addr.) = Allow in/out TCP traffic from/to IP.
            - $Notnats (IP addr.) = Allow all in/out traffic from/to IP. If $Notnats = "NOTNATS", this operation will be skipped.

        #### [EXAMPLE]:
            .\FWALL.ps1 -ScriptArgs "192.168.1.1;192.168.0.0/24;10.0.0.0/8"

    ### Fix.ps1 - Set UI Changes.
        - List hostname/domain.
        - List IP.
        - Reset group policy after making copy at C:\gp.
        - Set fonts to Segoe UI, and delete substitutes.
        - Set font activation to auto and delete inactive fonts/langs.
        - Set keyboard to EN-US.
        - Set UI to EN-US.
        - Expose hidden files, show file ext.s, show super hidden files (sys files).

        #### [USAGE]:
            .\Fix.ps1

    ### Gpo.ps1 - Disable GPOs.
        - List hostname/domain.
        - List IP.
        - Disable all settings in GPO.

        #### [USAGE]:
            .\Gpo.ps1

    ### Hard.ps1 - Harden System.
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

        #### [USAGE]:
            .\Hard.ps1

    ### Inv.ps1 - List System Info.
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

        #### [USAGE]:
            .\Inv.ps1

    ### LEADInv.ps1 - Altered Inv.ps1.
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

        #### [USAGE]:
            .\LEADInv.ps1

    ### Log.ps1 - Enable Logging for PS, IIS, & auditpol; Install Sysmon & smce.
        - List hostname/domain.
        - List IP.
        - Enable auditpol.
        - Allow process creation events to include command line args.
        - Enable PowerShell command transcription. Saves activity to PSLogs.
        - Log scripts & modules.
        - Enable IIS logging.
        - Configure Sysmon.

        #### [USAGE]:
            .\Log.ps1

    ### Prop.ps1 - File Transfer / Network Drive Removal.
        - Check if port 445 is open, if so, establish TCP connection.
        - Map a network drive to C$ share on target, and copy files from local (.\bins) to target (C$\Windows\System32).
        - If $Purge, remove all mapped drives.

        #### [USAGE]:
            .\Prop.ps1 -Hosts "C:\path\to\file.txt" (-Cred $Cred) (-Timeout $Timeout)
            .\Prop.ps1 -Purge
            - $Hosts (Path) = File path to .txt file containing one IP per line. EX: -Hosts "C:\path\to\hosts.txt
            - $Cred (Admin Share Auth) = Credential object. Defaults to $Global:Cred. Manually set by doing "$Cred = Get-Credential" in PowerShell and setting username & pass.
            - $Timeout (Value) = Defaults to 3000ms. EX: -Timeout 5000
            - $Purge (Flag) = Remove all mapped drives.

        #### [EXAMPLE]:
            .\Prop.ps1 -Hosts ".\hosts.txt" -Cred $Cred -Timeout 5000
            .\Prop.ps1 -Purge

    ### Run.ps1 - Run Scripts.
        - Connect to computers via hosts or Active Directory if $NonDomain is not used.
        - If $NonDomain used, script operates on non-domain computers.
        - Check ports 5985, 5986 to verify connectivity.
        - If connection fails or $Repair, attempt to re-establish connections.
        - Once established, copy/run file on remote systems.
        - Results saved in specified output dir.

        #### [USAGE]:
            .\Run.ps1 -Connect (-Repair) (-Nondomain) -Hosts $Hosts (-File $File) (-Script $Script) (-Out $Out) (-ScriptArgs $ScriptArgs) (-Include $Include) (-Exclude $Exclude)
            - $Repair (Flag) = Repair broken connection.
            - $Nondomain (Flag) = Specifies to operate on computers not part of a domain.
            - $Hosts (Path) = File path to .txt file containing one IP per line. EX: -Hosts "C:\path\to\hosts.txt
            - $File (Path) = File path to the file you wish to copy to targets. EX: -File "C:\path\to\file.xyz"
            - $Script (Path) = File path to .ps1 file to run on target machines. EX: -Script "C:\path\to\script.ps1"
            - $Out (Path) = Path to save outputs from the script running on targets. EX: -Out "C:\path\to\outputdir"
            - $ScriptArgs (Values) = Pass args to the script running on targets. EX: -ScriptArgs "-param1 arg1 -param2 arg2"
            - $Include (Values) = Specify which machines should be included. EX: -Include "Computer1", "Computer2"
            - $Exclude (Values) = Specify which machines should be excluded. EX: -Exclude "Computer3"

        #### [EXAMPLE]:
            .\Run.ps1 -Connect -Hosts "C:\path\to\hosts.txt" -Script "C:\path\to\script.ps1" -Out "C:\path\to\outputdir"
            .\Run.ps1 -Connect -Repair -File "C:\path\to\rickroll.mp4"
            .\Run.ps1 -Connect -Hosts "C:\path\to\hosts.txt" -Script "C:\path\to\Usr.ps1" -Out "C:\path\to\outputdir" -ScriptArgs "-param1 $UserPassword;$AdminPassword"

    ### SMB.ps1 - Configure SMB.
        - List hostname/domain.
        - List IP.
        - Disable SMBv1.
        - Enable "RequireSecuritySignature" for server and workstation.
        - If share is not exempt, apply read-only for all accounts that have access.

        #### [USAGE]:
            .\SMB.ps1

    ### TestPort.ps1 - Check if TCP Port is Open.

        #### [USAGE]:
            .\TestPort.ps1 -Ip $Ip -Port $Port -Timeout $Timeout -Verbose $Verbose
            - $Ip (IP addr.) = IP addr. of target. EX: -Ip "192.168.1.1"
            - $Port (Port) = Port on target. EX: -Port 22
            - $Timeout (Value) = Defaults to 3000ms. EX: -Timeout 5000
            - $Verbose (Flag) = Enables verbose mode.

        #### [EXAMPLE]:
            .\TestPort.ps1 -Ip "192.168.1.1" -Port 443 -Timeout 5000

    ### Usr.ps1 ($UserPassword, $AdminPassword, $Exclude) - Change User Passwords.
        - If $UserPassowrd == "YOLO", GeneratePassword().
            - If secondary DC, skip password reset.
            - Else, if primary DC:
                - Handles user ttuccdc (would need to change to efscccdc?), checking if it exists, settings password, and adding to groups. (Admin, Remote Desktop, Domain Admin)
                - Retrieves all AD users and changes passwords. (Skip if in $Exclude)
            - Else, if not DC:
                - Change passwords of local users. (Skip if in $Exclude)
                - Check for user ttuccdc, if not, create it, set password, and add to groups.
            - Results logged in $CSVArray and outputted.

        #### [USAGE]:
            .\Usr.ps1 -ScriptArgs $UserPassword;$AdminPassword;$Exclude1,$Exclude2
            - $UserPassword (String) = New user password. If == "YOLO", generates password.
            - $AdminPassword (String) = Password for admin user "ttuccdc".
            - $Exclude (String) = Users to exclude from password change. EX: ...;user1,user2

        #### [EXAMPLE]:
            .\Usr.ps1 -ScriptArgs "YOLO;password123;user1,user2"
            .\User.ps1 -ScriptArgs "Pass123;Word456"

    ### Wazuh.ps1 ($Manager, $RegistrationPassword) - Install Wazuh and Run.
        - If installer located at $DownloadPath, install Wazuh agent silently (msiexec), and pass manager IP/hostname, as well as RegistrationPassword if provided.
        - Set WazuhSvc to start automatically.
        - Script assumes that $DownloadPath == C:\Windows\System32\wazuh-agent-4.9.2-1.msi.

        #### [USAGE]:
            .\Wazuh.ps1 -ScriptArgs "$Manager(;$RegistrationPassword)"
            - $Manager (URL) = Address of Wazuh manager.
            - $RegistrationPassword (String) = Registration password, if provided.

        #### [EXAMPLE]:
            .\Wazuh.ps1 -ScriptArgs "wazuh.example.com;password123"
            .\Wazuh.ps1 -ScriptArgs "wazuh.example.com"

    ### Web.ps1 - HTTP Server.
        - Serves files from $Webroot on $IP on $Port.
        - Responds to URL path.
        - If the path exists and is a directory, list files in that directory. If the path leads to file, read contents of that file.

        #### [USAGE]:
            .\Web.ps1 -Ip $Ip -Webroot $Webroot -Port $Port
            - $Ip (IP addr.) = Target IP address.
            - $Webroot (Path) = Path to the directory to serve files from.
            - $Port (Port) = Port to open.

        #### [EXAMPLE]:
            .\Web.ps1 -Ip "127.0.0.1" -Webroot "C:\path\to\folder" -Port 8080
            (Client-Side): http://127.0.0.1:8080/docs/example.exe

    ### Webshell_Hunter.ps1 - Scanning for Webshells.
        - Search for cmd.exe or powershell.exe processes that belong to w3wp.exe or httpd.exe, and flag such instances.

        #### [USAGE]:
            .\Webshell_Hunter.ps1

    ### echo.ps1 - WinRM Connection Info.
        - Check if WinRM ports are in use, and if so, print remote IP addresses.

        #### [USAGE]:
            .\echo.ps1

    ### php.ps1 - PHP Config.
        - Locate PHP on system and load config files.
        - Edit config to disable PHP functions such as exec and passthru.
        - Disable file uploads.

        #### [USAGE]:
            .\php.ps1

    ### pii_search_task.ps1 - Create Task for pii_search.ps1 (which is located in /bins)

        #### [USAGE]:
            .\pii_search_task.ps1

    ### postprocessing.ps1 ($InventoryFolder, $Extension) - Output Sorting for Previous Scripts
        - Search for files with specific extensions in the specified folder.
        - Extract data between "start" and "end" lines of given text. e.g., start = "#### Start IP ####".
            - Parse Host data, IP, DNS, IIS, DC, Users, Group Members, Start Features, Registry Startups, Scheduled tasks, etc.
        - Compares data between outputs.

        #### [USAGE]:
            - .\postprocessing.ps1 -InventoryFolder $InventoryFolder -Extension $Extension
            - $InventoryFolder (Path) = Path to where data files are stored.
            - $Extension (String) = File extension for data files.

        #### [EXAMPLE]:
            .\postprocessing.ps1 -InventoryFolder "C:\path\to\files" -Extension "txt"

    ## > Bins

        ### Reset-KrbTgt-Password-For-RWDCs-And-RODCs.ps1 - Self Explanatory.
            - OG source: https://jorgequestforknowledge.wordpress.com/2018/12/30/powershell-script-to-reset-the-krbtgt-account-password-keys-for-both-rwdcs-and-rodcs/

        ### pii_search.ps1 - Search for PII.
            - Create directory C:\Windows\System32\PII if it does not exist.
            - Checks for files like .docx, .pdf, etc. and scan for types of PII (phone, SSN, addresses, etc.).
            - If 20+ matches, log findings in file pii.txt in C:\Windows\System32\PII and sort.

            #### [USAGE]:
                .\pii_search.ps1
                .\pii_search_task.ps1

        ### A long list of .exes for ease of install during competition.
            - https://github.com/LByrgeCP/dumbssh/tree/main/Windows/bins
