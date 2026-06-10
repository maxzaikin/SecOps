@echo off

:: ==============================================================================
:: NAME: OT-System-Collector
:: VERSION: 3.1.0
:: AUTHOR: Maks V. Zaikin & GPT LLM
:: COMPATIBILITY: Windows XP,11.
:: ==============================================================================

chcp 437 >nul

set "VER=3.1.0"

:: OUT_DIR = subfolder "report_<hostname>" next to the script itself
set "OUT_DIR=%~dp0report_%COMPUTERNAME%"
:: Strip trailing backslash if dp0 already ends with one (it always does)
if "%OUT_DIR:~-1%"=="\" set "OUT_DIR=%OUT_DIR:~0,-1%"

set "LOG_FILE=%OUT_DIR%\collection_log.txt"
set "META_JSON=%OUT_DIR%\metadata.json"

md "%OUT_DIR%" 2>nul

call :log "Starting OT-System-Collector v%VER%"

cls
echo ==============================================================================
echo   OT-System-Collector - Operation Technology+ Systems Collector v%VER%
echo ==============================================================================
echo   Target  : %COMPUTERNAME%
echo   Output  : %OUT_DIR%
echo   Log     : %LOG_FILE%
echo ==============================================================================
echo.
echo   LEGAL DISCLAIMER ^& OPERATIONAL SAFETY
echo   ----------------------------------------
echo   1. Provided AS IS - no warranties.
echo   2. On legacy hardware execution may take 10-30+ min.
echo      DO NOT TERMINATE THE PROCESS.
echo   3. Ensure critical services have active redundancy before running.
echo   4. Ensure you have enough disk space before running.(size may significantly varry depending on log files)
echo   5. Output contains sensitive config data - handle per security policy.
echo ==============================================================================
echo.

set /p "PROCEED=  Do you understand the risks and wish to proceed? (Y/N): "
if /i "%PROCEED%" neq "Y" (
    echo   Cancelled by user.
    pause
    exit /b 0
)
call :log "User accepted disclaimer."

:: =============================================================================
:: PHASE 0: PRE-FLIGHT CHECKS
:: =============================================================================
call :phase_start "0" "Pre-flight Checks"

:: --- Running context info (informational only - no hard stop) ---
call :step "Current user context"
echo      User    : %USERNAME%
echo      Domain  : %USERDOMAIN%
echo      Host    : %COMPUTERNAME%
echo.
echo      NOTE: This script requires Administrator privileges to collect
echo      all data. If you are not running it as Administrator, some files
echo      may be empty or missing. Check collection_log.txt for [WARN] entries.
call :log "  INFO: Running as %USERDOMAIN%\%USERNAME% on %COMPUTERNAME%"

:: --- WMIC check ---
set "HAS_WMIC=0"
call :step "Checking WMIC availability"
wmic /? >nul 2>nul
if not errorlevel 1 (
    set "HAS_WMIC=1"
    call :ok "WMIC is available"
) else (
    call :warn "WMIC not available - some modules will be skipped"
)

:: --- OS version ---
call :step "Detecting OS version"
set "OS_VER=unknown"
for /f "tokens=* delims=" %%L in ('ver') do (
    for /f "tokens=2 delims=[]" %%B in ("%%L") do (
        for /f "tokens=2 delims= " %%C in ("%%B") do set "OS_VER=%%C"
    )
)
set "IS_LEGACY=0"
for /f "tokens=1 delims=." %%M in ("%OS_VER%") do if "%%M"=="5" set "IS_LEGACY=1"
if "%IS_LEGACY%"=="1" (
    call :ok "OS: %OS_VER% [Windows XP / 2003 - legacy mode active]"
) else (
    call :ok "OS: %OS_VER% [modern mode]"
)

call :phase_end "0"

:: =============================================================================
:: PHASE 1: IDENTITY & HARDWARE
:: =============================================================================
call :phase_start "1" "Identity and Hardware Fingerprint"
md "%OUT_DIR%\1_identity" 2>nul

call :step "System summary (systeminfo)"
call :dots
systeminfo > "%OUT_DIR%\1_identity\systeminfo.txt" 2>nul
call :saved "1_identity\systeminfo.txt" "Full OS, hardware, hotfix summary"

call :step "Environment variables"
set > "%OUT_DIR%\1_identity\env_vars.txt"
call :saved "1_identity\env_vars.txt" "All current environment variables"

call :step "PATH variable"
echo %PATH% > "%OUT_DIR%\1_identity\path.txt"
call :saved "1_identity\path.txt" "Executable search path"

call :step "System clock timestamp"
echo %DATE% %TIME% > "%OUT_DIR%\1_identity\system_time.txt"
call :saved "1_identity\system_time.txt" "Date and time at moment of collection"

call :step "Internet Explorer version"
reg query "HKLM\Software\Microsoft\Internet Explorer" /v Version > "%OUT_DIR%\1_identity\ie_version.txt" 2>nul
call :saved "1_identity\ie_version.txt" "IE version from registry"

call :step "Timezone (registry)"
reg query "HKLM\SYSTEM\CurrentControlSet\Control\TimeZoneInformation" /s > "%OUT_DIR%\1_identity\timezone.txt" 2>nul
call :saved "1_identity\timezone.txt" "Active timezone name and bias"

call :step "Service Pack marker (XP legacy)"
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Windows" /v CSDVersion > "%OUT_DIR%\1_identity\servicepack.txt" 2>nul
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v CSDVersion >> "%OUT_DIR%\1_identity\servicepack.txt" 2>nul
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v ServicePackInEffect >> "%OUT_DIR%\1_identity\servicepack.txt" 2>nul
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v CurrentVersion >> "%OUT_DIR%\1_identity\servicepack.txt" 2>nul
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v CurrentBuildNumber >> "%OUT_DIR%\1_identity\servicepack.txt" 2>nul
call :saved "1_identity\servicepack.txt" "SP level, build number, CSDVersion - key aging marker"

if "%HAS_WMIC%"=="1" (
    call :step "Boot and uptime"
    wmic os get LocalDateTime,LastBootUpTime /value > "%OUT_DIR%\1_identity\boot_time.txt" 2>nul
    call :saved "1_identity\boot_time.txt" "Last boot time and current datetime"

    call :step "BIOS serial"
    wmic bios get SerialNumber,Version,ReleaseDate /value > "%OUT_DIR%\1_identity\serials.txt" 2>nul
    call :saved "1_identity\serials.txt" "BIOS serial, version, release date"

    call :step "Chassis product info"
    wmic csproduct get Vendor,Name,IdentifyingNumber /format:csv > "%OUT_DIR%\1_identity\csproduct.csv" 2>nul
    call :saved "1_identity\csproduct.csv" "Vendor, model, asset tag"

    call :step "CPU details"
    wmic cpu get /format:csv > "%OUT_DIR%\1_identity\cpu.csv" 2>nul
    call :saved "1_identity\cpu.csv" "Processor name, cores, speed, socket"

    call :step "Motherboard details"
    wmic baseboard get /format:csv > "%OUT_DIR%\1_identity\baseboard.csv" 2>nul
    call :saved "1_identity\baseboard.csv" "Baseboard manufacturer, product, serial"

    call :step "Physical memory modules"
    wmic path Win32_PhysicalMemory get /format:csv > "%OUT_DIR%\1_identity\memory.csv" 2>nul
    call :saved "1_identity\memory.csv" "RAM: size, speed, slot, manufacturer"
)

call :step "Full system report (msinfo32/winmsd)"
call :dots
if "%IS_LEGACY%"=="1" (
    winmsd /nfo "%OUT_DIR%\1_identity\system_passport.nfo" 2>nul
) else (
    msinfo32 /report "%OUT_DIR%\1_identity\system_passport.nfo" 2>nul
)
call :saved "1_identity\system_passport.nfo" "Complete hardware and software inventory"

call :phase_end "1"

:: =============================================================================
:: PHASE 2: STORAGE AUDIT
:: =============================================================================
call :phase_start "2" "Storage Audit"
md "%OUT_DIR%\2_storage" 2>nul

if "%HAS_WMIC%"=="1" (
    call :step "Logical drives"
    wmic logicaldisk get /format:csv > "%OUT_DIR%\2_storage\logical.csv" 2>nul
    call :saved "2_storage\logical.csv" "Drive letters, filesystem, size, free space"

    call :step "Physical disks"
    wmic diskdrive get /format:csv > "%OUT_DIR%\2_storage\physical.csv" 2>nul
    call :saved "2_storage\physical.csv" "Disks: model, size, interface, serial"

    call :step "Partition table"
    wmic partition get /format:csv > "%OUT_DIR%\2_storage\partitions.csv" 2>nul
    call :saved "2_storage\partitions.csv" "Partitions: index, size, type, bootable"

) else (
    call :warn "WMIC unavailable - storage audit skipped"
)

call :phase_end "2"

:: =============================================================================
:: PHASE 3: NETWORK TOPOLOGY
:: =============================================================================
call :phase_start "3" "Network Topology"
md "%OUT_DIR%\3_network" 2>nul

call :step "IP configuration (all adapters)"
ipconfig /all > "%OUT_DIR%\3_network\ipconfig.txt" 2>nul
call :saved "3_network\ipconfig.txt" "IP, subnet, gateway, DNS, DHCP per adapter"

call :step "Routing table"
route print > "%OUT_DIR%\3_network\routes.txt" 2>nul
call :saved "3_network\routes.txt" "Active IP routing table"

call :step "Routing table (numeric)"
netstat -rn > "%OUT_DIR%\3_network\routes_num.txt" 2>nul
call :saved "3_network\routes_num.txt" "Numeric routing table (no DNS resolution)"

call :step "ARP cache"
arp -a > "%OUT_DIR%\3_network\arp.txt" 2>nul
call :saved "3_network\arp.txt" "IP-to-MAC mappings"

call :step "MAC addresses"
getmac /v > "%OUT_DIR%\3_network\mac_addresses.txt" 2>nul
call :saved "3_network\mac_addresses.txt" "MAC addresses with adapter names"

call :step "Active connections and listening ports"
netstat -aon > "%OUT_DIR%\3_network\connections.txt" 2>nul
call :saved "3_network\connections.txt" "All TCP/UDP connections with owning PID"

call :step "Local shared folders"
net share > "%OUT_DIR%\3_network\shares_local.txt" 2>nul
call :saved "3_network\shares_local.txt" "SMB shares hosted by this machine"

call :step "Mapped network drives"
net use > "%OUT_DIR%\3_network\shares_mapped.txt" 2>nul
call :saved "3_network\shares_mapped.txt" "Connected remote shares and drive letters"

call :step "Active SMB sessions"
net session > "%OUT_DIR%\3_network\sessions.txt" 2>nul
call :saved "3_network\sessions.txt" "Clients connected over SMB"

call :step "DNS resolver cache"
ipconfig /displaydns > "%OUT_DIR%\3_network\dns_cache.txt" 2>nul
call :saved "3_network\dns_cache.txt" "Cached resolved hostnames"

call :step "Hosts file"
type "%SystemRoot%\system32\drivers\etc\hosts" > "%OUT_DIR%\3_network\hosts_file.txt" 2>nul
call :saved "3_network\hosts_file.txt" "Static hostname overrides"

call :step "Workstation network config"
net config workstation > "%OUT_DIR%\3_network\net_config_ws.txt" 2>nul
call :saved "3_network\net_config_ws.txt" "Workstation name, domain, logon server"

call :step "Server network config"
net config server > "%OUT_DIR%\3_network\net_config_srv.txt" 2>nul
call :saved "3_network\net_config_srv.txt" "Server service config, session limits"

call :step "TCP/IP registry parameters"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /s > "%OUT_DIR%\3_network\tcpip_registry.txt" 2>nul
call :saved "3_network\tcpip_registry.txt" "TCP/IP stack tuning from registry"

call :step "Network interface registry entries"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /s > "%OUT_DIR%\3_network\interfaces_registry.txt" 2>nul
call :saved "3_network\interfaces_registry.txt" "Per-adapter IP config from registry"

if "%HAS_WMIC%"=="1" (
    call :step "NIC list (WMI)"
    wmic nic get /format:csv > "%OUT_DIR%\3_network\nics.csv" 2>nul
    call :saved "3_network\nics.csv" "Adapters: name, type, MAC, speed"

    call :step "NIC configuration (WMI)"
    wmic nicconfig get /format:csv > "%OUT_DIR%\3_network\nic_config.csv" 2>nul
    call :saved "3_network\nic_config.csv" "DHCP, IP, DNS, WINS per adapter"

    call :step "All network adapters (WMI)"
    wmic path Win32_NetworkAdapter get /format:csv > "%OUT_DIR%\3_network\pci_adapters.csv" 2>nul
    call :saved "3_network\pci_adapters.csv" "All Win32_NetworkAdapter incl. virtual"
)

call :phase_end "3"

:: =============================================================================
:: PHASE 4: ACCESS & SECURITY
:: =============================================================================
call :phase_start "4" "Access and Security"
md "%OUT_DIR%\4_access" 2>nul

call :step "Local user accounts list"
net user > "%OUT_DIR%\4_access\users.txt" 2>nul
call :saved "4_access\users.txt" "All local user accounts"

call :step "Detailed info per user account"
:: Write header
echo ===== Detailed user accounts ===== > "%OUT_DIR%\4_access\users_detail.txt"
for /f "skip=4 tokens=*" %%U in ('net user 2^>nul') do (
    for %%W in (%%U) do (
        net user "%%W" >> "%OUT_DIR%\4_access\users_detail.txt" 2>nul
        echo ---------------------------------------- >> "%OUT_DIR%\4_access\users_detail.txt"
    )
)
call :saved "4_access\users_detail.txt" "Per-user: last logon, expiry, group membership, flags"

call :step "Local groups"
net localgroup > "%OUT_DIR%\4_access\groups.txt" 2>nul
call :saved "4_access\groups.txt" "All local security groups"

call :step "Administrators group membership"
net localgroup Administrators > "%OUT_DIR%\4_access\group_administrators.txt" 2>nul
call :saved "4_access\group_administrators.txt" "Members of local Administrators group"

call :step "Remote Desktop Users group membership"
net localgroup "Remote Desktop Users" > "%OUT_DIR%\4_access\group_rdp_users.txt" 2>nul
call :saved "4_access\group_rdp_users.txt" "Members allowed to connect via RDP"

call :step "Password and lockout policy"
net accounts > "%OUT_DIR%\4_access\pwd_policy.txt" 2>nul
call :saved "4_access\pwd_policy.txt" "Password age, length, lockout thresholds"

if "%HAS_WMIC%"=="1" (
    call :step "User accounts detail (WMI)"
    wmic useraccount get /format:csv > "%OUT_DIR%\4_access\wmi_users.csv" 2>nul
    call :saved "4_access\wmi_users.csv" "SID, disabled, locked, password flags per account"
)

call :phase_end "4"

:: =============================================================================
:: PHASE 5: RUNTIME & DRIVERS
:: =============================================================================
call :phase_start "5" "Runtime State and Drivers"
md "%OUT_DIR%\5_runtime" 2>nul

call :step "All Windows services (sc query)"
sc query state= all > "%OUT_DIR%\5_runtime\services_all.txt" 2>nul
call :saved "5_runtime\services_all.txt" "Service names, state, type"

call :step "Service binary paths via sc qc (PathName for each service)"
call :dots
echo ===== Service configurations (sc qc) ===== > "%OUT_DIR%\5_runtime\service_paths.txt"
for /f "tokens=2" %%S in ('sc query state^= all 2^>nul ^| findstr /i "SERVICE_NAME"') do (
    echo ---- %%S ---- >> "%OUT_DIR%\5_runtime\service_paths.txt"
    sc qc "%%S" >> "%OUT_DIR%\5_runtime\service_paths.txt" 2>nul
)
call :saved "5_runtime\service_paths.txt" "CRITICAL: full binary path, start type, account per service"

call :step "Kernel drivers"
sc query type= driver state= all > "%OUT_DIR%\5_runtime\drivers_kernel.txt" 2>nul
call :saved "5_runtime\drivers_kernel.txt" "Kernel-mode drivers registered or loaded"

call :step "NTP / time sync status"
w32tm /query /status > "%OUT_DIR%\5_runtime\ntp_status.txt" 2>nul
call :saved "5_runtime\ntp_status.txt" "Time source, stratum, last sync"

tasklist /? >nul 2>nul
if not errorlevel 1 (
    call :step "Running processes"
    tasklist /v /fo csv > "%OUT_DIR%\5_runtime\tasks.csv" 2>nul
    call :saved "5_runtime\tasks.csv" "All processes: PID, name, user, memory, window"
)

driverquery /? >nul 2>nul
if not errorlevel 1 (
    call :step "Installed drivers (driverquery)"
    driverquery /v /fo csv > "%OUT_DIR%\5_runtime\drivers_list.csv" 2>nul
    call :saved "5_runtime\drivers_list.csv" "Drivers: name, type, start mode, state, path"
)

if "%HAS_WMIC%"=="1" (
    call :step "Services detail (WMI)"
    wmic service get /format:csv > "%OUT_DIR%\5_runtime\services_wmi.csv" 2>nul
    call :saved "5_runtime\services_wmi.csv" "Services: PathName, StartMode, StartName, State"
)

call :step "Open files / file locks"
openfiles /query >nul 2>nul
if not errorlevel 1 (
    openfiles /query > "%OUT_DIR%\5_runtime\open_files.txt" 2>nul
    call :saved "5_runtime\open_files.txt" "Files opened over network shares"
) else (
    echo openfiles tracking not enabled - skipped. > "%OUT_DIR%\5_runtime\open_files.txt"
    call :warn "openfiles not enabled (requires prior 'openfiles /local on' + reboot)"
)

call :phase_end "5"

:: =============================================================================
:: PHASE 6: SOFTWARE & COMPLIANCE
:: =============================================================================
call :phase_start "6" "Software Inventory and Compliance"
md "%OUT_DIR%\6_software" 2>nul

call :step "Installed programs - 64-bit registry hive (raw)"
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall" /s > "%OUT_DIR%\6_software\reg_uninstall_x64.txt" 2>nul
call :saved "6_software\reg_uninstall_x64.txt" "64-bit installed software raw registry dump"

call :step "Installed programs - 32-bit registry hive (raw)"
reg query "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall" /s > "%OUT_DIR%\6_software\reg_uninstall_x32.txt" 2>nul
call :saved "6_software\reg_uninstall_x32.txt" "32-bit WoW64 installed software raw registry dump"

:: Structured software inventory CSV - one row per application: Name,Version,Publisher,InstallDate
:: Uses reg_uninstall_x64.txt / x32.txt as raw source (already collected above).
:: No cp1251 switching - all output stays in cp437/ASCII. Cyrillic names will appear
:: as escaped hex in the raw reg dump; the WMI CSV (apps_wmic.csv) is the clean
:: cross-reference for Jupyter when name encoding matters.
:: software_inventory.csv is intentionally a schema-only file.
:: CMD cannot build one-row-per-app CSV from reg query without delayed expansion
:: (which is unsafe on XP): reg query returns one VALUE per line, not one APP per line,
:: so Name and Version arrive in separate iterations with no shared key.
:: The correct structured sources are:
::   apps_wmic.csv     - Name, Version, Vendor (WMI, clean, use as primary)
::   reg_uninstall_x64.txt / x32.txt - raw dump with all fields incl. UninstallString
:: Build the merged DataFrame in Jupyter with pd.read_csv + regex parse.
call :step "Software inventory schema file - 64-bit"
(
    echo # OT-System-Collector software inventory schema
    echo # Primary structured source: 6_software\apps_wmic.csv
    echo # Full raw source: 6_software\reg_uninstall_x64.txt
    echo # Fields in raw source: DisplayName, DisplayVersion, Publisher, InstallDate, UninstallString, InstallLocation
    echo # Encoding: cp437 ^(ASCII^); Cyrillic names preserved in apps_wmic.csv via WMI
    echo Name,Version,Publisher,InstallDate,UninstallString
) > "%OUT_DIR%\6_software\software_inventory.csv"
call :saved "6_software\software_inventory.csv" "Schema file: build rows in Jupyter from reg_uninstall_x64.txt + apps_wmic.csv"

call :step "Software inventory schema file - 32-bit"
(
    echo # OT-System-Collector software inventory schema
    echo # Primary structured source: 6_software\apps_wmic.csv
    echo # Full raw source: 6_software\reg_uninstall_x32.txt
    echo # Fields in raw source: DisplayName, DisplayVersion, Publisher, InstallDate, UninstallString, InstallLocation
    echo # Encoding: cp437 ^(ASCII^); Cyrillic names preserved in apps_wmic.csv via WMI
    echo Name,Version,Publisher,InstallDate,UninstallString
) > "%OUT_DIR%\6_software\software_inventory_x32.csv"
call :saved "6_software\software_inventory_x32.csv" "Schema file: build rows in Jupyter from reg_uninstall_x32.txt + apps_wmic.csv"

call :step ".NET Framework versions"
reg query "HKLM\SOFTWARE\Microsoft\NET Framework Setup\NDP" /s > "%OUT_DIR%\6_software\dotnet_versions.txt" 2>nul
call :saved "6_software\dotnet_versions.txt" "Installed .NET runtime versions"

certutil -? >nul 2>nul
if not errorlevel 1 (
    call :step "Trusted root certificates"
    certutil -store root > "%OUT_DIR%\6_software\root_certs.txt" 2>nul
    call :saved "6_software\root_certs.txt" "Certificates in Trusted Root store"
)

if "%HAS_WMIC%"=="1" (
    call :step "Full software list via WMI (slow)"
    call :dots
    wmic product get Name,Version,Vendor /format:csv > "%OUT_DIR%\6_software\apps_wmic.csv" 2>nul
    call :saved "6_software\apps_wmic.csv" "MSI-registered apps: name, version, vendor (po.csv equivalent)"

    call :step "Installed patches and hotfixes"
    wmic qfe get /format:csv > "%OUT_DIR%\6_software\patches.csv" 2>nul
    call :saved "6_software\patches.csv" "QFE patches: KB number, install date"

    call :step "Antivirus product status"
    wmic /namespace:\\root\SecurityCenter2 path AntiVirusProduct get displayName,productState /format:csv > "%OUT_DIR%\6_software\av_status.csv" 2>nul
    if errorlevel 1 (
        wmic /namespace:\\root\SecurityCenter path AntiVirusProduct get displayName,productState /format:csv > "%OUT_DIR%\6_software\av_status.csv" 2>nul
    )
    call :saved "6_software\av_status.csv" "AV product name and protection state"
)

call :phase_end "6"

:: =============================================================================
:: PHASE 7: PERSISTENCE & GPO
:: =============================================================================
call :phase_start "7" "Persistence Mechanisms and Group Policy"
md "%OUT_DIR%\7_persistence" 2>nul

schtasks /? >nul 2>nul
if not errorlevel 1 (
    call :step "Scheduled tasks"
    schtasks /query /fo csv /v > "%OUT_DIR%\7_persistence\scheduled_tasks.csv" 2>nul
    call :saved "7_persistence\scheduled_tasks.csv" "Tasks: name, trigger, action, run-as, state"
)

call :step "Autorun - HKLM Run"
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /s > "%OUT_DIR%\7_persistence\run_hklm.txt" 2>nul
call :saved "7_persistence\run_hklm.txt" "System startup programs (machine hive)"

call :step "Autorun - HKCU Run"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /s > "%OUT_DIR%\7_persistence\run_hkcu.txt" 2>nul
call :saved "7_persistence\run_hkcu.txt" "User logon startup programs"

call :step "RunOnce - HKLM"
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce" /s > "%OUT_DIR%\7_persistence\runonce_hklm.txt" 2>nul
call :saved "7_persistence\runonce_hklm.txt" "One-shot startup commands (machine)"

call :step "RunOnce - HKCU"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce" /s > "%OUT_DIR%\7_persistence\runonce_hkcu.txt" 2>nul
call :saved "7_persistence\runonce_hkcu.txt" "One-shot startup commands (user)"

call :step "Image File Execution Options (IFEO debugger hijacks)"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" /s > "%OUT_DIR%\7_persistence\ifeo.txt" 2>nul
call :saved "7_persistence\ifeo.txt" "IFEO: debugger substitution - common persistence/hijack technique"

secedit /? >nul 2>nul
if not errorlevel 1 (
    call :step "Local security policy export"
    secedit /export /cfg "%OUT_DIR%\7_persistence\local_policies.inf" /quiet 2>nul
    call :saved "7_persistence\local_policies.inf" "Security policy: rights, audit, account config"
)

call :step "Group Policy raw files"
xcopy "%SystemRoot%\system32\GroupPolicy" "%OUT_DIR%\7_persistence\GPO_Raw" /Y /E /C /I /H /Q >nul 2>nul
call :saved "7_persistence\GPO_Raw" "Raw GPO folder: registry.pol, GptTmpl, scripts"

call :step "Firewall rules"
if "%IS_LEGACY%"=="1" (
    netsh firewall show config > "%OUT_DIR%\7_persistence\firewall_rules.txt" 2>nul
    netsh firewall show state >> "%OUT_DIR%\7_persistence\firewall_rules.txt" 2>nul
) else (
    netsh advfirewall show allprofiles > "%OUT_DIR%\7_persistence\firewall_rules.txt" 2>nul
    netsh advfirewall firewall show rule name=all >> "%OUT_DIR%\7_persistence\firewall_rules.txt" 2>nul
)
call :saved "7_persistence\firewall_rules.txt" "Firewall profiles state and all rules"

call :phase_end "7"

:: =============================================================================
:: PHASE 8: OT-SPECIFIC HARDWARE
:: =============================================================================
call :phase_start "8" "OT-Specific Hardware Scan"
md "%OUT_DIR%\8_ot_specific" 2>nul

if "%HAS_WMIC%"=="1" (
    call :step "Plug-and-Play device enumeration (slow)"
    call :dots
    wmic path Win32_PnPEntity get /format:csv > "%OUT_DIR%\8_ot_specific\pnp.csv" 2>nul
    call :saved "8_ot_specific\pnp.csv" "All PnP devices: name, device ID, status, class"

    call :step "Serial (COM) ports"
    wmic path Win32_SerialPort get /format:csv > "%OUT_DIR%\8_ot_specific\com_ports.csv" 2>nul
    call :saved "8_ot_specific\com_ports.csv" "COM ports: name, port, baud, parity"

    call :step "USB controller devices"
    wmic path Win32_USBControllerDevice get /format:csv > "%OUT_DIR%\8_ot_specific\usb_ctrl.csv" 2>nul
    call :saved "8_ot_specific\usb_ctrl.csv" "USB controllers and connected device refs"

    call :step "Printer ports (LPT, virtual, network)"
    wmic path Win32_ParallelPort get /format:csv > "%OUT_DIR%\8_ot_specific\parallel_ports.csv" 2>nul
    call :saved "8_ot_specific\parallel_ports.csv" "Parallel/LPT ports - common in legacy ICS"

    call :step "Sound devices (sometimes used for ICS interfaces)"
    wmic path Win32_SoundDevice get /format:csv > "%OUT_DIR%\8_ot_specific\sound_devices.csv" 2>nul
    call :saved "8_ot_specific\sound_devices.csv" "Sound devices list"
) else (
    call :warn "WMIC unavailable - OT hardware scan skipped"
)

call :phase_end "8"

:: =============================================================================
:: PHASE 9: FORENSIC EVENT LOGS
:: =============================================================================
call :phase_start "9" "Forensic Event Logs"
md "%OUT_DIR%\9_forensics" 2>nul

wevtutil el >nul 2>nul
if not errorlevel 1 (
    call :step "Event log channel list"
    wevtutil el > "%OUT_DIR%\9_forensics\event_logs_list.txt" 2>nul
    call :saved "9_forensics\event_logs_list.txt" "All registered event log channel names"

    call :step "Security log export (slow)"
    call :dots
    wevtutil epl Security    "%OUT_DIR%\9_forensics\Security.evtx"    /ow:true 2>nul
    call :saved "9_forensics\Security.evtx" "Security: logon, privilege, policy change events"

    call :step "System log export"
    wevtutil epl System      "%OUT_DIR%\9_forensics\System.evtx"      /ow:true 2>nul
    call :saved "9_forensics\System.evtx" "System: driver, service, hardware errors"

    call :step "Application log export"
    wevtutil epl Application "%OUT_DIR%\9_forensics\Application.evtx" /ow:true 2>nul
    call :saved "9_forensics\Application.evtx" "Application: software errors and warnings"
) else (
    if exist "%SystemRoot%\system32\eventquery.vbs" (
        call :step "Security log via eventquery.vbs (XP)"
        call :dots
        cscript //nologo "%SystemRoot%\system32\eventquery.vbs" /l Security    /fo csv > "%OUT_DIR%\9_forensics\evt_security.csv"    2>nul
        call :saved "9_forensics\evt_security.csv" "Security events (XP eventquery)"

        call :step "System log via eventquery.vbs (XP)"
        cscript //nologo "%SystemRoot%\system32\eventquery.vbs" /l System      /fo csv > "%OUT_DIR%\9_forensics\evt_system.csv"      2>nul
        call :saved "9_forensics\evt_system.csv" "System events (XP eventquery)"

        call :step "Application log via eventquery.vbs (XP)"
        cscript //nologo "%SystemRoot%\system32\eventquery.vbs" /l Application /fo csv > "%OUT_DIR%\9_forensics\evt_application.csv" 2>nul
        call :saved "9_forensics\evt_application.csv" "Application events (XP eventquery)"
    ) else (
        call :step "Raw event log copy (XP fallback)"
        copy "%SystemRoot%\system32\config\SysEvent.Evt"  "%OUT_DIR%\9_forensics\SysEvent.Evt"  >nul 2>nul
        copy "%SystemRoot%\system32\config\SecEvent.Evt"  "%OUT_DIR%\9_forensics\SecEvent.Evt"  >nul 2>nul
        copy "%SystemRoot%\system32\config\AppEvent.Evt"  "%OUT_DIR%\9_forensics\AppEvent.Evt"  >nul 2>nul
        call :saved "9_forensics\*.Evt" "Raw binary event logs"
        call :warn "eventquery.vbs not found - copied raw .Evt binary files"
    )
)

call :step "USB storage device history"
reg query "HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR" /s > "%OUT_DIR%\9_forensics\usb_history.txt" 2>nul
call :saved "9_forensics\usb_history.txt" "Registry records of previously connected USB drives"

call :phase_end "9"

:: =============================================================================
:: PHASE 10: VOLATILE FORENSIC SNAPSHOT (NEW)
:: =============================================================================
call :phase_start "10" "Volatile Forensic Snapshot"
md "%OUT_DIR%\10_volatile" 2>nul

call :step "Prefetch folder listing (execution evidence)"
if exist "%SystemRoot%\Prefetch" (
    dir /o:d /t:w "%SystemRoot%\Prefetch\*.pf" > "%OUT_DIR%\10_volatile\prefetch_list.txt" 2>nul
    call :saved "10_volatile\prefetch_list.txt" "Prefetch files: last execution time per executable"
) else (
    echo Prefetch folder not found or disabled. > "%OUT_DIR%\10_volatile\prefetch_list.txt"
    call :warn "Prefetch not available (may be disabled in registry)"
)

call :step "Recent files (shell:recent)"
dir /o:d /t:w "%USERPROFILE%\Recent" > "%OUT_DIR%\10_volatile\recent_files.txt" 2>nul
call :saved "10_volatile\recent_files.txt" "Recently accessed files per current user"

call :step "Temp folder contents"
dir /s /b "%TEMP%" > "%OUT_DIR%\10_volatile\temp_contents.txt" 2>nul
call :saved "10_volatile\temp_contents.txt" "Files in TEMP - may reveal dropped payloads"

call :step "Loaded DLLs per process snapshot"
if "%HAS_WMIC%"=="1" (
    wmic process get ProcessId,Name,ExecutablePath /format:csv > "%OUT_DIR%\10_volatile\process_paths.csv" 2>nul
    call :saved "10_volatile\process_paths.csv" "Process full executable paths with PID"
)

call :step "Clipboard is not capturable from CMD - noting limitation"
echo Clipboard contents cannot be captured via CMD without additional tools. > "%OUT_DIR%\10_volatile\clipboard_note.txt"
call :saved "10_volatile\clipboard_note.txt" "Clipboard capture limitation note"

call :step "BAM/DAM background activity (Win10+ only)"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\bam\UserSettings" /s > "%OUT_DIR%\10_volatile\bam_activity.txt" 2>nul
reg query "HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings" /s >> "%OUT_DIR%\10_volatile\bam_activity.txt" 2>nul
call :saved "10_volatile\bam_activity.txt" "BAM/DAM: background app execution timestamps (Win10+)"

call :step "UserAssist (GUI program execution history per user)"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist" /s > "%OUT_DIR%\10_volatile\userassist.txt" 2>nul
call :saved "10_volatile\userassist.txt" "UserAssist: GUI program run counts and timestamps (ROT13 encoded)"

call :step "MUICache (executed programs display names)"
reg query "HKCU\Software\Microsoft\Windows\ShellNoRoam\MUICache" /s > "%OUT_DIR%\10_volatile\muicache.txt" 2>nul
reg query "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache" /s >> "%OUT_DIR%\10_volatile\muicache.txt" 2>nul
call :saved "10_volatile\muicache.txt" "MUICache: friendly names of programs ever executed"

call :step "ShimCache / AppCompatCache (application compatibility cache)"
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatibility" /s > "%OUT_DIR%\10_volatile\shimcache.txt" 2>nul
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache" /s >> "%OUT_DIR%\10_volatile\shimcache.txt" 2>nul
call :saved "10_volatile\shimcache.txt" "ShimCache: binary execution history with timestamps"

call :phase_end "10"

:: =============================================================================
:: PHASE 11: OT/ICS REGISTRY ARTIFACTS (NEW)
:: =============================================================================
call :phase_start "11" "OT/ICS Registry Artifacts"
md "%OUT_DIR%\11_ot_registry" 2>nul

call :step "COM port configuration (baud, parity, flow control)"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\Serial" /s > "%OUT_DIR%\11_ot_registry\com_port_config.txt" 2>nul
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Ports" /s >> "%OUT_DIR%\11_ot_registry\com_port_config.txt" 2>nul
call :saved "11_ot_registry\com_port_config.txt" "COM port baud/parity settings - critical for SCADA/Modbus"

call :step "DCOM configuration (affects OPC communication)"
reg query "HKLM\SOFTWARE\Microsoft\Ole" /s > "%OUT_DIR%\11_ot_registry\dcom_config.txt" 2>nul
call :saved "11_ot_registry\dcom_config.txt" "DCOM security limits - affects OPC DA/HDA connectivity"

call :step "RPC configuration"
reg query "HKLM\SOFTWARE\Microsoft\Rpc" /s > "%OUT_DIR%\11_ot_registry\rpc_config.txt" 2>nul
call :saved "11_ot_registry\rpc_config.txt" "RPC settings including endpoint mapper config"

call :step "Known ICS/SCADA software registry keys"
reg query "HKLM\SOFTWARE\ICONICS" /s > "%OUT_DIR%\11_ot_registry\ics_software.txt" 2>nul
reg query "HKLM\SOFTWARE\Wonderware" /s >> "%OUT_DIR%\11_ot_registry\ics_software.txt" 2>nul
reg query "HKLM\SOFTWARE\Inductive Automation" /s >> "%OUT_DIR%\11_ot_registry\ics_software.txt" 2>nul
reg query "HKLM\SOFTWARE\Siemens" /s >> "%OUT_DIR%\11_ot_registry\ics_software.txt" 2>nul
reg query "HKLM\SOFTWARE\Rockwell Software" /s >> "%OUT_DIR%\11_ot_registry\ics_software.txt" 2>nul
reg query "HKLM\SOFTWARE\OSIsoft" /s >> "%OUT_DIR%\11_ot_registry\ics_software.txt" 2>nul
reg query "HKLM\SOFTWARE\ABB" /s >> "%OUT_DIR%\11_ot_registry\ics_software.txt" 2>nul
reg query "HKLM\SOFTWARE\Kepware" /s >> "%OUT_DIR%\11_ot_registry\ics_software.txt" 2>nul
reg query "HKLM\SOFTWARE\MatrikonOPC" /s >> "%OUT_DIR%\11_ot_registry\ics_software.txt" 2>nul
reg query "HKLM\SOFTWARE\Emerson" /s >> "%OUT_DIR%\11_ot_registry\ics_software.txt" 2>nul
call :saved "11_ot_registry\ics_software.txt" "Registry presence of known ICS/SCADA vendors"

call :step "OPC server registrations (CLSID-based)"
reg query "HKLM\SOFTWARE\Classes\OPC" /s > "%OUT_DIR%\11_ot_registry\opc_servers.txt" 2>nul
reg query "HKCR\OPC" /s >> "%OUT_DIR%\11_ot_registry\opc_servers.txt" 2>nul
call :saved "11_ot_registry\opc_servers.txt" "Registered OPC servers (COM class registrations)"

call :step "Device class GUID registry (industrial adapters)"
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Class" /s > "%OUT_DIR%\11_ot_registry\device_classes.txt" 2>nul
call :saved "11_ot_registry\device_classes.txt" "All device class GUIDs - reveals installed adapter types"

call :phase_end "11"

:: =============================================================================
:: PHASE 12: REMOTE ACCESS INVENTORY (NEW)
:: =============================================================================
call :phase_start "12" "Remote Access Inventory"
md "%OUT_DIR%\12_remote_access" 2>nul

call :step "RDP configuration and state"
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /s > "%OUT_DIR%\12_remote_access\rdp_config.txt" 2>nul
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /s >> "%OUT_DIR%\12_remote_access\rdp_config.txt" 2>nul
call :saved "12_remote_access\rdp_config.txt" "RDP enabled/disabled, port, NLA, encryption level"

call :step "RDP recent connections (client-side history)"
reg query "HKCU\Software\Microsoft\Terminal Server Client\Default" /s > "%OUT_DIR%\12_remote_access\rdp_history.txt" 2>nul
reg query "HKCU\Software\Microsoft\Terminal Server Client\Servers" /s >> "%OUT_DIR%\12_remote_access\rdp_history.txt" 2>nul
call :saved "12_remote_access\rdp_history.txt" "RDP targets this machine connected TO"

call :step "VNC registry presence check"
reg query "HKLM\SOFTWARE\RealVNC" /s > "%OUT_DIR%\12_remote_access\vnc_config.txt" 2>nul
reg query "HKLM\SOFTWARE\TightVNC" /s >> "%OUT_DIR%\12_remote_access\vnc_config.txt" 2>nul
reg query "HKLM\SOFTWARE\ORL" /s >> "%OUT_DIR%\12_remote_access\vnc_config.txt" 2>nul
reg query "HKLM\SOFTWARE\UltraVNC" /s >> "%OUT_DIR%\12_remote_access\vnc_config.txt" 2>nul
call :saved "12_remote_access\vnc_config.txt" "VNC installations and their configuration"

call :step "TeamViewer registry presence and ID"
reg query "HKLM\SOFTWARE\TeamViewer" /s > "%OUT_DIR%\12_remote_access\teamviewer.txt" 2>nul
reg query "HKLM\SOFTWARE\Wow6432Node\TeamViewer" /s >> "%OUT_DIR%\12_remote_access\teamviewer.txt" 2>nul
call :saved "12_remote_access\teamviewer.txt" "TeamViewer install, version, machine ID"

call :step "WinRM configuration"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN" /s > "%OUT_DIR%\12_remote_access\winrm_config.txt" 2>nul
call :saved "12_remote_access\winrm_config.txt" "WinRM (PowerShell remoting) config"

call :step "SSH server presence (OpenSSH)"
reg query "HKLM\SOFTWARE\OpenSSH" /s > "%OUT_DIR%\12_remote_access\ssh_config.txt" 2>nul
sc query sshd > "%OUT_DIR%\12_remote_access\sshd_service.txt" 2>nul
call :saved "12_remote_access\ssh_config.txt" "OpenSSH server registry config"
call :saved "12_remote_access\sshd_service.txt" "SSHD service state"

call :step "Remote registry service state"
sc query RemoteRegistry > "%OUT_DIR%\12_remote_access\remote_registry.txt" 2>nul
call :saved "12_remote_access\remote_registry.txt" "Remote Registry service state - if running, registry is remotely accessible"

call :step "Anydesk presence"
reg query "HKLM\SOFTWARE\AnyDesk" /s > "%OUT_DIR%\12_remote_access\anydesk.txt" 2>nul
reg query "HKCU\SOFTWARE\AnyDesk" /s >> "%OUT_DIR%\12_remote_access\anydesk.txt" 2>nul
call :saved "12_remote_access\anydesk.txt" "AnyDesk remote access tool presence"

call :phase_end "12"

:: =============================================================================
:: PHASE 13: INTEGRITY MARKERS (NEW)
:: =============================================================================
call :phase_start "13" "Integrity Markers"
md "%OUT_DIR%\13_integrity" 2>nul

call :step "Critical system binary hash check (certutil -hashfile SHA256)"
echo ===== SHA256 hashes of critical system binaries ===== > "%OUT_DIR%\13_integrity\system_hashes.txt"
echo Generated: %DATE% %TIME% >> "%OUT_DIR%\13_integrity\system_hashes.txt"
echo. >> "%OUT_DIR%\13_integrity\system_hashes.txt"

certutil -? >nul 2>nul
if not errorlevel 1 (
    call :dots
    for %%F in (
        "%SystemRoot%\system32\cmd.exe"
        "%SystemRoot%\system32\notepad.exe"
        "%SystemRoot%\system32\regedit.exe"
        "%SystemRoot%\system32\services.exe"
        "%SystemRoot%\system32\lsass.exe"
        "%SystemRoot%\system32\svchost.exe"
        "%SystemRoot%\system32\winlogon.exe"
        "%SystemRoot%\system32\explorer.exe"
        "%SystemRoot%\system32\taskmgr.exe"
        "%SystemRoot%\system32\netstat.exe"
        "%SystemRoot%\system32\ipconfig.exe"
        "%SystemRoot%\system32\sc.exe"
        "%SystemRoot%\system32\reg.exe"
        "%SystemRoot%\system32\wmic.exe"
    ) do (
        if exist %%F (
            echo File: %%F >> "%OUT_DIR%\13_integrity\system_hashes.txt"
            certutil -hashfile %%F SHA256 >> "%OUT_DIR%\13_integrity\system_hashes.txt" 2>nul
            echo. >> "%OUT_DIR%\13_integrity\system_hashes.txt"
        )
    )
    call :saved "13_integrity\system_hashes.txt" "SHA256 of critical binaries - compare against known-good baseline"
) else (
    echo certutil not available - hashing skipped. >> "%OUT_DIR%\13_integrity\system_hashes.txt"
    call :warn "certutil not available - binary hashing skipped"
)

call :step "Hosts file hash"
certutil -? >nul 2>nul
if not errorlevel 1 (
    certutil -hashfile "%SystemRoot%\system32\drivers\etc\hosts" SHA256 > "%OUT_DIR%\13_integrity\hosts_hash.txt" 2>nul
    call :saved "13_integrity\hosts_hash.txt" "Hash of hosts file - detect DNS redirect tampering"
)

call :step "Windows File Protection / SFC log"
if exist "%SystemRoot%\system32\sfcapi.dll" (
    echo SFC available. > "%OUT_DIR%\13_integrity\sfc_note.txt"
)
if exist "%SystemRoot%\Logs\CBS\CBS.log" (
    copy "%SystemRoot%\Logs\CBS\CBS.log" "%OUT_DIR%\13_integrity\cbs.log" >nul 2>nul
    call :saved "13_integrity\cbs.log" "CBS log: Windows component integrity repair history"
)
if exist "%SystemRoot%\system32\LogFiles\SFC\SFCFix.log" (
    copy "%SystemRoot%\system32\LogFiles\SFC\SFCFix.log" "%OUT_DIR%\13_integrity\sfcfix.log" >nul 2>nul
)
call :saved "13_integrity\sfc_note.txt" "SFC/WFP availability marker"

call :phase_end "13"

:: =============================================================================
:: FINALIZATION
:: =============================================================================
echo.
echo   ----------------------------------------------------------------------
echo   Generating manifest and metadata...
echo   ----------------------------------------------------------------------

dir /s /b "%OUT_DIR%" > "%OUT_DIR%\manifest.txt" 2>nul

echo {                                    > "%META_JSON%"
echo   "host": "%COMPUTERNAME%",         >> "%META_JSON%"
echo   "domain": "%USERDOMAIN%",         >> "%META_JSON%"
echo   "user": "%USERNAME%",             >> "%META_JSON%"
echo   "collector_ver": "%VER%",         >> "%META_JSON%"
echo   "os_kernel": "%OS_VER%",          >> "%META_JSON%"
echo   "is_legacy": %IS_LEGACY%,         >> "%META_JSON%"
echo   "has_wmic": %HAS_WMIC%,           >> "%META_JSON%"
echo   "collection_date": "%DATE%",      >> "%META_JSON%"
echo   "collection_time": "%TIME%",      >> "%META_JSON%"
echo   "out_dir": "%OUT_DIR%"            >> "%META_JSON%"
echo }                                   >> "%META_JSON%"

call :log "Collection complete."

echo.
echo ==============================================================================
echo   COLLECTION COMPLETE
echo ==============================================================================
echo   Output folder : %OUT_DIR%
echo   Collection log: %LOG_FILE%
echo   Manifest      : %OUT_DIR%\manifest.txt
echo   Metadata      : %META_JSON%
echo ==============================================================================
echo.
echo   PHASES COLLECTED:
echo    0  Pre-flight checks
echo    1  Identity and hardware fingerprint
echo    2  Storage audit
echo    3  Network topology
echo    4  Access and security
echo    5  Runtime state and drivers  
echo    6  Software inventory         
echo    7  Persistence and GPO        
echo    8  OT hardware scan
echo    9  Forensic event logs
echo   10  Volatile forensic snapshot 
echo   11  OT/ICS registry artifacts  
echo   12  Remote access inventory    
echo   13  Integrity markers         
echo ==============================================================================
pause
exit /b 0

:: =============================================================================
:: SUBROUTINES
:: =============================================================================

:log
echo [%TIME%] %~1 >> "%LOG_FILE%"
goto :eof

:phase_start
set "PHASE_NUM=%~1"
set "PHASE_NAME=%~2"
set "T_START=%TIME%"
echo.
echo   ===========================================================
echo   PHASE %PHASE_NUM% : %PHASE_NAME%
echo   Started : %T_START%
echo   ===========================================================
call :log "=== PHASE %PHASE_NUM% START: %PHASE_NAME% ==="
goto :eof

:phase_end
echo   -----------------------------------------------------------
echo   PHASE %PHASE_NUM% done   [ %T_START% --^> %TIME% ]
echo   -----------------------------------------------------------
call :log "=== PHASE %PHASE_NUM% END ==="
goto :eof

:step
echo.
echo   ^>^> %~1
call :log "  STEP: %~1"
goto :eof

:saved
echo      Saved : %OUT_DIR%\%~1
echo      Info  : %~2
call :log "  SAVED: %~1 (%~2)"
goto :eof

:ok
echo      OK    : %~1
call :log "  OK: %~1"
goto :eof

:warn
echo      WARN  : %~1
call :log "  [WARN] %~1"
goto :eof

:fail
echo      ERROR : %~1
call :log "  [ERROR] %~1"
goto :eof

:dots
echo      [.........] please wait, this step may take a while
goto :eof