# Windows Live Response & Volatile Evidence Command Reference

> **RFC 3227–Inspired DFIR Command Checklist**

This reference maps common Windows command-line and PowerShell commands to volatile and semi-volatile evidence sources useful during live incident response.

The emphasis is on **information gathering**, not remediation.

> **Important:** No live-response command is truly "forensically neutral." Executing commands changes memory, process state, timestamps, logs, caches, and potentially other system artifacts. Record every command you execute.

---

# 1. Investigator Preparation

Before collecting evidence:

- [ ] Open an elevated PowerShell or Command Prompt if authorized.
- [ ] Record the case number.
- [ ] Record investigator identity.
- [ ] Record collection start time.
- [ ] Record all commands executed.
- [ ] Redirect command output to external or designated evidence storage where appropriate.
- [ ] Record tool and OS versions.

A useful evidence directory might be:

```powershell
$IR = "E:\IR-CASE-001"
New-Item -ItemType Directory -Path $IR
```

Note that creating directories on the suspect system alters evidence. Prefer trusted external storage where practical.

---

# 2. Current Date and Time

## PowerShell

```powershell
Get-Date
```

More detail:

```powershell
Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff K"
```

UTC:

```powershell
(Get-Date).ToUniversalTime()
```

Timezone:

```powershell
Get-TimeZone
```

## CMD

```cmd
date /t
time /t
```

## Useful collection

```powershell
Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff K" > system_time.txt
Get-TimeZone >> system_time.txt
```

Record investigator time separately so clock drift can later be established.

---

# 3. Host Identification

## Computer Name

```cmd
hostname
```

PowerShell:

```powershell
$env:COMPUTERNAME
```

## Operating-System Information

```cmd
systeminfo
```

PowerShell:

```powershell
Get-ComputerInfo
```

Focused alternative:

```powershell
Get-CimInstance Win32_OperatingSystem
```

Useful fields:

```powershell
Get-CimInstance Win32_OperatingSystem |
Select-Object Caption, Version, BuildNumber, OSArchitecture,
CSName, LastBootUpTime, LocalDateTime
```

---

# 4. System Uptime / Boot Time

```powershell
Get-CimInstance Win32_OperatingSystem |
Select-Object LastBootUpTime
```

Alternative:

```cmd
systeminfo | findstr /i "Boot Time"
```

---

# 5. Current User and Security Context

## Current User

```cmd
whoami
```

Detailed security context:

```cmd
whoami /all
```

Groups:

```cmd
whoami /groups
```

Privileges:

```cmd
whoami /priv
```

User SID:

```cmd
whoami /user
```

---

# 6. Logged-On Users and Sessions

## Local / RDP Sessions

```cmd
query user
```

or:

```cmd
quser
```

Session list:

```cmd
query session
```

PowerShell:

```powershell
Get-CimInstance Win32_LoggedOnUser
```

Another useful view:

```powershell
Get-CimInstance Win32_LogonSession
```

---

# 7. Kerberos Authentication State

List cached Kerberos tickets:

```cmd
klist
```

List sessions:

```cmd
klist sessions
```

Inspect ticket cache:

```cmd
klist tgt
```

Kerberos ticket state can be highly useful during investigations involving Active Directory compromise, lateral movement, pass-the-ticket, or credential theft.

Microsoft documents `klist` as the Windows command for viewing and managing Kerberos tickets.

---

# 8. Network Interfaces

## Traditional Command

```cmd
ipconfig /all
```

Useful for:

- IPv4 addresses
- IPv6 addresses
- MAC addresses
- DHCP state
- DNS servers
- Default gateways
- DNS suffixes
- Interface details

## PowerShell

```powershell
Get-NetIPConfiguration
```

Include disconnected, virtual, and loopback interfaces:

```powershell
Get-NetIPConfiguration -All
```

Detailed:

```powershell
Get-NetIPConfiguration -Detailed
```

Microsoft specifies that `Get-NetIPConfiguration` reports interfaces, IP addresses, DNS servers, and related network configuration.

---

# 9. Network Adapter Information

```powershell
Get-NetAdapter
```

Detailed:

```powershell
Get-NetAdapter |
Format-List *
```

Physical adapters:

```powershell
Get-NetAdapter -Physical
```

Useful fields:

```powershell
Get-NetAdapter |
Select-Object Name, InterfaceDescription, Status,
MacAddress, LinkSpeed
```

---

# 10. IP Addresses

```powershell
Get-NetIPAddress
```

IPv4 only:

```powershell
Get-NetIPAddress -AddressFamily IPv4
```

IPv6:

```powershell
Get-NetIPAddress -AddressFamily IPv6
```

---

# 11. Routing Table

## CMD

```cmd
route print
```

## PowerShell

```powershell
Get-NetRoute
```

IPv4:

```powershell
Get-NetRoute -AddressFamily IPv4
```

IPv6:

```powershell
Get-NetRoute -AddressFamily IPv6
```

---

# 12. ARP / Neighbor Cache

## Traditional

```cmd
arp -a
```

## PowerShell

```powershell
Get-NetNeighbor
```

IPv4:

```powershell
Get-NetNeighbor -AddressFamily IPv4
```

IPv6:

```powershell
Get-NetNeighbor -AddressFamily IPv6
```

Useful fields:

```powershell
Get-NetNeighbor |
Select-Object InterfaceAlias,IPAddress,
LinkLayerAddress,State
```

---

# 13. DNS Configuration

```cmd
ipconfig /all
```

PowerShell:

```powershell
Get-DnsClientServerAddress
```

DNS client settings:

```powershell
Get-DnsClient
```

---

# 14. DNS Resolver Cache

```cmd
ipconfig /displaydns
```

PowerShell:

```powershell
Get-DnsClientCache
```

This can provide evidence of recently resolved domains.

---

# 15. Active TCP Connections

## CMD

```cmd
netstat -ano
```

Useful fields include:

- protocol
- local address
- remote address
- connection state
- PID

Do not use DNS resolution during initial collection if avoidable:

```cmd
netstat -ano
```

rather than relying on hostname resolution.

## PowerShell

```powershell
Get-NetTCPConnection
```

Established:

```powershell
Get-NetTCPConnection -State Established
```

Listening:

```powershell
Get-NetTCPConnection -State Listen
```

Useful fields:

```powershell
Get-NetTCPConnection |
Select-Object LocalAddress,LocalPort,
RemoteAddress,RemotePort,State,
OwningProcess,CreationTime
```

`Get-NetTCPConnection` exposes current TCP connection properties including local/remote addresses, ports, states, owning PIDs, and creation times.

---

# 16. UDP Endpoints

```powershell
Get-NetUDPEndpoint
```

Traditional:

```cmd
netstat -ano -p udp
```

---

# 17. Map Network Connection to Process

Suppose a connection belongs to PID `4242`.

```powershell
Get-Process -Id 4242
```

Detailed:

```powershell
Get-Process -Id 4242 |
Format-List *
```

Executable information:

```powershell
Get-CimInstance Win32_Process -Filter "ProcessId=4242" |
Select-Object ProcessId,ParentProcessId,
Name,ExecutablePath,CommandLine
```

---

# 18. Running Processes

## CMD

```cmd
tasklist
```

Detailed:

```cmd
tasklist /v
```

Services hosted by processes:

```cmd
tasklist /svc
```

## PowerShell

```powershell
Get-Process
```

Microsoft documents `Get-Process` for enumerating processes running on local or remote systems.

---

# 19. Process Command Lines

This is particularly important during incident response.

```powershell
Get-CimInstance Win32_Process |
Select-Object ProcessId,ParentProcessId,
Name,ExecutablePath,CommandLine
```

More readable:

```powershell
Get-CimInstance Win32_Process |
Format-Table ProcessId,ParentProcessId,
Name,ExecutablePath,CommandLine -Wrap
```

---

# 20. Process Tree

Native PowerShell does not provide an ideal forensic process-tree view, but parent PID information can be collected:

```powershell
Get-CimInstance Win32_Process |
Select-Object ProcessId,ParentProcessId,
Name,CommandLine |
Sort-Object ParentProcessId
```

Important fields:

```text
ProcessId
ParentProcessId
Name
ExecutablePath
CommandLine
```

Students should learn to reconstruct parent-child relationships from these fields.

---

# 21. Process Start Times

```powershell
Get-Process |
Select-Object Id,ProcessName,StartTime
```

Some protected processes may return access errors.

---

# 22. Executable Path and Command Line

```powershell
Get-CimInstance Win32_Process |
Select ProcessId,Name,ExecutablePath,CommandLine
```

Useful for identifying processes running from locations such as:

```text
%TEMP%
%APPDATA%
%LOCALAPPDATA%
C:\Users\Public
Downloads
ProgramData
```

---

# 23. Loaded DLLs / Modules

For one process:

```powershell
Get-Process -Id 4242 -Module
```

Alternative:

```cmd
tasklist /m
```

Specific DLL:

```cmd
tasklist /m suspicious.dll
```

Be aware that protected processes may restrict module enumeration.

---

# 24. Services

## CMD

```cmd
sc query
```

All service states:

```cmd
sc query state= all
```

## PowerShell

```powershell
Get-Service
```

Running services:

```powershell
Get-Service |
Where-Object Status -eq Running
```

Service configuration:

```powershell
Get-CimInstance Win32_Service |
Select-Object Name,DisplayName,State,
StartMode,StartName,PathName
```

The last command is particularly useful because `PathName` reveals the executable command used by the service.

---

# 25. Drivers

```cmd
driverquery
```

Verbose:

```cmd
driverquery /v
```

PowerShell:

```powershell
Get-CimInstance Win32_SystemDriver
```

Running drivers:

```powershell
Get-CimInstance Win32_SystemDriver |
Where-Object State -eq Running
```

---

# 26. Scheduled Tasks

```cmd
schtasks /query
```

Verbose:

```cmd
schtasks /query /fo LIST /v
```

PowerShell:

```powershell
Get-ScheduledTask
```

Task details:

```powershell
Get-ScheduledTask |
Select-Object TaskPath,TaskName,State
```

---

# 27. Startup Commands

```powershell
Get-CimInstance Win32_StartupCommand
```

Useful fields:

```powershell
Get-CimInstance Win32_StartupCommand |
Select Name,Command,Location,User
```

---

# 28. Common Registry Run Keys

Current user:

```cmd
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
```

System:

```cmd
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
```

32-bit software on 64-bit Windows:

```cmd
reg query HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run
```

RunOnce:

```cmd
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
```

---

# 29. Environment Variables

## CMD

```cmd
set
```

## PowerShell

```powershell
Get-ChildItem Env:
```

Environment variables can reveal:

- user paths
- temporary directories
- application configuration
- cloud credentials accidentally placed in environment variables
- development environments
- suspicious path modifications

---

# 30. Mounted Volumes

```cmd
mountvol
```

PowerShell:

```powershell
Get-Volume
```

Disk information:

```powershell
Get-Disk
```

Partitions:

```powershell
Get-Partition
```

File-system drives:

```powershell
Get-PSDrive -PSProvider FileSystem
```

---

# 31. Physical Disks

```powershell
Get-Disk
```

Additional information:

```powershell
Get-CimInstance Win32_DiskDrive
```

Useful fields:

```powershell
Get-CimInstance Win32_DiskDrive |
Select Model,SerialNumber,InterfaceType,
MediaType,Size,DeviceID
```

---

# 32. BitLocker Status

```cmd
manage-bde -status
```

PowerShell:

```powershell
Get-BitLockerVolume
```

Forensic significance:

If an encrypted volume is currently mounted and unlocked, powering the system down may change your ability to acquire accessible data.

Do not change BitLocker configuration during collection.

---

# 33. Connected SMB Shares

```cmd
net use
```

PowerShell:

```powershell
Get-SmbConnection
```

Server-side sessions where applicable:

```powershell
Get-SmbSession
```

Shares hosted locally:

```powershell
Get-SmbShare
```

---

# 34. Open Files via SMB

On a file server:

```powershell
Get-SmbOpenFile
```

Traditional:

```cmd
net file
```

---

# 35. Local Users

```cmd
net user
```

PowerShell:

```powershell
Get-LocalUser
```

---

# 36. Local Groups

```cmd
net localgroup
```

Administrators:

```cmd
net localgroup administrators
```

PowerShell:

```powershell
Get-LocalGroup
```

Group members:

```powershell
Get-LocalGroupMember Administrators
```

---

# 37. Domain Information

```cmd
whoami /fqdn
```

```cmd
systeminfo
```

```cmd
nltest /dsgetdc:
```

PowerShell:

```powershell
Get-CimInstance Win32_ComputerSystem |
Select Name,Domain,PartOfDomain
```

Avoid unnecessarily querying large amounts of domain infrastructure during initial live response.

---

# 38. Firewall Configuration

```cmd
netsh advfirewall show allprofiles
```

PowerShell:

```powershell
Get-NetFirewallProfile
```

Rules:

```powershell
Get-NetFirewallRule
```

Enabled rules:

```powershell
Get-NetFirewallRule |
Where-Object Enabled -eq True
```

---

# 39. Proxy Configuration

WinHTTP:

```cmd
netsh winhttp show proxy
```

User Internet Settings:

```cmd
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
```

---

# 40. Wi-Fi State

Interfaces:

```cmd
netsh wlan show interfaces
```

Profiles:

```cmd
netsh wlan show profiles
```

Do **not** use commands intended to reveal stored Wi-Fi keys unless that information is specifically authorized and evidentially relevant.

---

# 41. Event Logs

List logs:

```cmd
wevtutil el
```

Inspect log metadata:

```cmd
wevtutil gli Security
```

Query recent events:

```cmd
wevtutil qe Security /c:20 /rd:true /f:text
```

Export a log:

```cmd
wevtutil epl Security E:\IR\Security.evtx
```

Microsoft documents `wevtutil` for retrieving information about Windows event logs and for querying/exporting them.

---

# 42. PowerShell Event Logs

```powershell
Get-WinEvent -LogName "Windows PowerShell"
```

PowerShell Operational log:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational"
```

Recent entries:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -MaxEvents 100
```

---

# 43. Windows Security Events

Recent:

```powershell
Get-WinEvent -LogName Security -MaxEvents 100
```

Selected event IDs:

```powershell
Get-WinEvent -FilterHashtable @{
    LogName='Security'
    Id=4624,4625,4688,4720,4728,4732
}
```

Examples of commonly investigated event categories include:

```text
4624  Successful logon
4625  Failed logon
4688  Process creation
4720  User account created
4728  Member added to global group
4732  Member added to local group
```

Availability depends on the system's audit configuration.

---

# 44. RDP-Related Logs

List relevant log names:

```powershell
Get-WinEvent -ListLog *RemoteDesktop*
```

Common operational source:

```powershell
Get-WinEvent `
-LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"
```

---

# 45. Defender State

```powershell
Get-MpComputerStatus
```

Preferences:

```powershell
Get-MpPreference
```

Threat detections:

```powershell
Get-MpThreatDetection
```

Do not trigger scans during initial evidence collection unless there is a specific reason: doing so can access files, alter timestamps, quarantine evidence, and change system state.

---

# 46. Installed Software

Registry-based collection:

```powershell
Get-ItemProperty `
HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |
Select DisplayName,DisplayVersion,Publisher,InstallDate
```

64-bit/32-bit consideration:

```powershell
Get-ItemProperty `
HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* |
Select DisplayName,DisplayVersion,Publisher,InstallDate
```

Avoid:

```cmd
wmic product get name
```

as a default forensic collection command because Windows Installer provider queries may have unwanted side effects.

---

# 47. Recent Downloads / Temporary Locations

List temp directory:

```powershell
Get-ChildItem $env:TEMP -Force
```

Sort newest first:

```powershell
Get-ChildItem $env:TEMP -Force |
Sort-Object LastWriteTime -Descending |
Select-Object -First 100
```

Downloads:

```powershell
Get-ChildItem "$env:USERPROFILE\Downloads" -Force |
Sort-Object LastWriteTime -Descending
```

Do not recursively hash or enumerate an entire large filesystem until you have considered the performance and forensic impact.

---

# 48. PowerShell History

Common PSReadLine location:

```powershell
(Get-PSReadLineOption).HistorySavePath
```

View:

```powershell
Get-Content (Get-PSReadLineOption).HistorySavePath
```

The file may contain sensitive data. Handle it as evidence.

---

# 49. Prefetch

Directory listing:

```cmd
dir C:\Windows\Prefetch
```

PowerShell:

```powershell
Get-ChildItem C:\Windows\Prefetch |
Sort-Object LastWriteTime -Descending
```

Do not interpret Prefetch purely from filenames; use appropriate forensic parsers during offline analysis.

---

# 50. Amcache

Common hive location:

```cmd
dir C:\Windows\AppCompat\Programs\Amcache.hve
```

Acquire the hive for offline parsing rather than attempting to interpret it manually.

---

# 51. Registry Hive Locations

Key system hives commonly include:

```text
C:\Windows\System32\config\SYSTEM
C:\Windows\System32\config\SOFTWARE
C:\Windows\System32\config\SAM
C:\Windows\System32\config\SECURITY
```

User artifacts commonly include:

```text
C:\Users\<USER>\NTUSER.DAT
C:\Users\<USER>\AppData\Local\Microsoft\Windows\UsrClass.dat
```

Use appropriate forensic acquisition methods for locked files.

---

# 52. Shadow Copies

```cmd
vssadmin list shadows
```

PowerShell/CIM:

```powershell
Get-CimInstance Win32_ShadowCopy
```

Do not create or delete shadow copies during evidence collection.

---

# 53. Running Virtual Machines / Hyper-V

Where Hyper-V tools are installed:

```powershell
Get-VM
```

Virtual switches:

```powershell
Get-VMSwitch
```

VM network adapters:

```powershell
Get-VMNetworkAdapter -All
```

---

# 54. Containers

Docker, if present:

```cmd
docker ps
```

All containers:

```cmd
docker ps -a
```

Inspect:

```cmd
docker inspect <container>
```

Images:

```cmd
docker images
```

Do not assume Docker is installed.

---

# 55. File Hashing

PowerShell:

```powershell
Get-FileHash suspicious.exe -Algorithm SHA256
```

Example:

```powershell
Get-FileHash C:\Temp\suspicious.exe -Algorithm SHA256
```

Hash evidence after acquisition:

```powershell
Get-FileHash E:\IR\memory.raw -Algorithm SHA256
```

Hashing reads data and therefore still has system impact, but it should not intentionally modify the target file.

---

# 56. Useful "First Five Minutes" Sequence

A compact first-response sequence might include:

```cmd
hostname
whoami /all
date /t
time /t
ipconfig /all
route print
arp -a
netstat -ano
tasklist /v
query user
klist
sc query
schtasks /query /fo LIST /v
```

PowerShell equivalent:

```powershell
Get-Date
Get-TimeZone
Get-ComputerInfo
Get-NetIPConfiguration -All
Get-NetRoute
Get-NetNeighbor
Get-NetTCPConnection
Get-NetUDPEndpoint
Get-CimInstance Win32_Process |
    Select ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine
Get-Service
Get-ScheduledTask
Get-CimInstance Win32_LoggedOnUser
```

---

# 57. Recommended Volatile Collection Order

For a typical live Windows endpoint:

```text
1. Document date/time and hostname
2. Logged-on users / authentication state
3. Network interfaces
4. ARP / neighbor cache
5. Routing table
6. DNS cache
7. TCP/UDP connections
8. Running processes
9. Process command lines / parent PIDs
10. Services / drivers
11. Scheduled tasks
12. Relevant volatile security state
13. RAM acquisition
14. Temporary data
15. Windows forensic artifacts
16. Event logs
17. Disk acquisition
18. Remote infrastructure evidence
```

This is a **decision aid**, not an immutable sequence.

---

# 58. Commands to Avoid During Initial Collection

Do not casually execute commands that:

- [ ] terminate processes
- [ ] restart services
- [ ] clear caches
- [ ] clear event logs
- [ ] flush DNS
- [ ] renew DHCP
- [ ] disconnect network interfaces
- [ ] change firewall rules
- [ ] modify registry values
- [ ] initiate antivirus remediation
- [ ] quarantine files
- [ ] delete temporary files
- [ ] update software
- [ ] reboot the system
- [ ] shut down the system

Examples of commands that are **not collection commands**:

```cmd
ipconfig /flushdns
ipconfig /release
ipconfig /renew
arp -d *
route delete ...
wevtutil cl Security
shutdown /r
```

Do not run them simply because they appear in an administrator's troubleshooting toolkit.

---

# 59. Student Rule

Before executing any command, ask:

> **What information will this give me, and what evidence could running it change?**

A good live responder does not execute every command available.

A good live responder collects the **minimum necessary information in a defensible order** and documents every action.