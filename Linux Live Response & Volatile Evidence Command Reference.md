# Linux Live Response & Volatile Evidence Command Reference

> **RFC 3227–Inspired DFIR Command Checklist**

This reference maps common Linux command-line tools to volatile and semi-volatile evidence useful during live incident response.

It assumes a modern Linux system but deliberately includes alternatives because distributions differ.

> **Important:** Executing commands on a live Linux host modifies system state. Commands create processes, consume memory, access files and may generate audit or shell-history artifacts. Document every action.

Linux exposes extensive runtime information through `/proc`, which the Linux kernel documentation describes as an interface to internal kernel data structures and running-system information.

---

# 1. Investigator Preparation

Record:

- [ ] Case identifier
- [ ] Investigator
- [ ] Collection start time
- [ ] Hostname
- [ ] Current user
- [ ] Privilege level
- [ ] Commands executed
- [ ] Tool versions
- [ ] Output destination
- [ ] Any errors

Where appropriate, store evidence on trusted external media rather than the suspect filesystem.

Example:

```bash
IR=/mnt/evidence/CASE-001
```

Creating directories or files on the suspect system changes evidence.

---

# 2. Current Date and Time

Local time:

```bash
date
```

ISO-style:

```bash
date --iso-8601=seconds
```

UTC:

```bash
date -u
```

Timezone:

```bash
timedatectl
```

Hardware clock where available:

```bash
hwclock --show
```

Record investigator time independently to identify clock drift.

---

# 3. Host Identification

Hostname:

```bash
hostname
```

Fully qualified hostname where configured:

```bash
hostname -f
```

System identity:

```bash
hostnamectl
```

Kernel/system:

```bash
uname -a
```

Kernel release:

```bash
uname -r
```

Architecture:

```bash
uname -m
```

OS release:

```bash
cat /etc/os-release
```

---

# 4. Uptime and Boot Time

```bash
uptime
```

Boot time:

```bash
who -b
```

With systemd:

```bash
uptime -s
```

---

# 5. Current User

```bash
whoami
```

User and group IDs:

```bash
id
```

Current environment identity:

```bash
logname
```

Be aware that `logname` may not always reflect the effective user in unusual session contexts.

---

# 6. Logged-On Users

```bash
who
```

Detailed activity:

```bash
w
```

Users:

```bash
users
```

Login history:

```bash
last
```

Failed logins, if available:

```bash
lastb
```

Systemd sessions:

```bash
loginctl list-sessions
```

Session details:

```bash
loginctl session-status <SESSION-ID>
```

---

# 7. Network Interfaces

Preferred modern command:

```bash
ip addr
```

Short form:

```bash
ip a
```

Link-layer information:

```bash
ip link
```

Compact:

```bash
ip -br addr
```

IPv4:

```bash
ip -4 addr
```

IPv6:

```bash
ip -6 addr
```

Legacy alternative where installed:

```bash
ifconfig -a
```

Prefer `ip` on modern Linux systems.

---

# 8. Interface Statistics

```bash
ip -s link
```

Kernel interface statistics:

```bash
cat /proc/net/dev
```

---

# 9. Routing Table

```bash
ip route
```

IPv4:

```bash
ip -4 route
```

IPv6:

```bash
ip -6 route
```

All routing tables:

```bash
ip route show table all
```

Policy routing rules:

```bash
ip rule
```

Legacy alternative:

```bash
route -n
```

or:

```bash
netstat -rn
```

---

# 10. ARP / Neighbor Cache

Modern command:

```bash
ip neigh
```

Detailed:

```bash
ip neigh show
```

IPv4 ARP legacy command:

```bash
arp -an
```

IPv6 neighbor state is also exposed through `ip neigh`.

---

# 11. DNS Configuration

Traditional resolver configuration:

```bash
cat /etc/resolv.conf
```

Systemd-resolved:

```bash
resolvectl status
```

Per-interface:

```bash
resolvectl dns
```

Be aware that `/etc/resolv.conf` may be a symbolic link into a resolver-managed location.

---

# 12. Hosts File

```bash
cat /etc/hosts
```

Inspect metadata:

```bash
stat /etc/hosts
```

---

# 13. Active TCP/UDP Connections

Preferred:

```bash
ss -tunap
```

Options conceptually provide:

```text
-t  TCP
-u  UDP
-n  numeric output
-a  all sockets
-p  process information
```

Listening sockets:

```bash
ss -lntup
```

Established TCP:

```bash
ss -tnp state established
```

TCP only:

```bash
ss -tanp
```

UDP only:

```bash
ss -uanp
```

Legacy alternative:

```bash
netstat -antup
```

Some process information requires root privileges.

---

# 14. UNIX Domain Sockets

```bash
ss -xap
```

This can be useful when investigating local inter-process communication.

---

# 15. Raw Socket Information from `/proc`

TCP:

```bash
cat /proc/net/tcp
```

TCP IPv6:

```bash
cat /proc/net/tcp6
```

UDP:

```bash
cat /proc/net/udp
```

UDP IPv6:

```bash
cat /proc/net/udp6
```

These are lower-level structures and require interpretation.

---

# 16. Running Processes

Standard:

```bash
ps aux
```

Alternative UNIX format:

```bash
ps -ef
```

Detailed:

```bash
ps -eo pid,ppid,user,lstart,etime,cmd
```

The `top` utility provides a dynamic view of processes and system activity.

For evidence collection, static `ps` output is generally easier to preserve than interactive `top`.

---

# 17. Process Tree

```bash
ps -ef --forest
```

or:

```bash
pstree -ap
```

If `pstree` is installed:

```bash
pstree -alp
```

Pay attention to unusual parent-child relationships.

---

# 18. Process Start Times

```bash
ps -eo pid,ppid,user,lstart,etime,cmd
```

Sort:

```bash
ps -eo pid,ppid,lstart,cmd --sort=lstart
```

---

# 19. Process Command Lines

All process command lines:

```bash
ps -eo pid,ppid,user,args
```

For one PID:

```bash
cat /proc/<PID>/cmdline
```

Because `/proc/<PID>/cmdline` contains NUL separators, improve readability with:

```bash
tr '\0' ' ' < /proc/<PID>/cmdline
```

Example:

```bash
tr '\0' ' ' < /proc/4242/cmdline
```

---

# 20. Process Executable

```bash
readlink -f /proc/<PID>/exe
```

Example:

```bash
readlink -f /proc/4242/exe
```

A suspicious result such as:

```text
/path/malware (deleted)
```

may indicate that the executable file was removed after the process started.

---

# 21. Process Working Directory

```bash
readlink -f /proc/<PID>/cwd
```

---

# 22. Process Environment

```bash
cat /proc/<PID>/environ
```

Readable:

```bash
tr '\0' '\n' < /proc/<PID>/environ
```

Environment data may contain:

- API keys
- cloud credentials
- proxy settings
- library paths
- application secrets
- command configuration

Treat it as sensitive evidence.

---

# 23. Process Status

```bash
cat /proc/<PID>/status
```

Useful fields can include:

```text
Name
State
Pid
PPid
Uid
Gid
Threads
Capabilities
Memory
```

---

# 24. Process Memory Maps

```bash
cat /proc/<PID>/maps
```

Detailed:

```bash
cat /proc/<PID>/smaps
```

These may help identify:

- loaded shared libraries
- anonymous executable memory
- unusual mappings
- deleted files still mapped
- injected code indicators

---

# 25. Open Files

`lsof` is designed to list information about files opened by processes.

All:

```bash
lsof
```

Specific process:

```bash
lsof -p <PID>
```

Network:

```bash
lsof -i
```

TCP:

```bash
lsof -iTCP
```

Deleted-but-open files:

```bash
lsof +L1
```

One of the most useful Linux forensic commands is:

```bash
lsof +L1
```

because malware, temporary payloads, or log files may have been deleted from the directory tree while remaining open by a running process.

---

# 26. File Descriptors

Without `lsof`:

```bash
ls -la /proc/<PID>/fd
```

Example:

```bash
ls -la /proc/4242/fd
```

Resolve:

```bash
readlink /proc/4242/fd/*
```

---

# 27. Loaded Kernel Modules

```bash
lsmod
```

Raw kernel view:

```bash
cat /proc/modules
```

Module information:

```bash
modinfo <module>
```

Do not load or unload modules during initial evidence collection.

---

# 28. Kernel Version and Runtime

```bash
uname -a
```

```bash
cat /proc/version
```

Kernel command line:

```bash
cat /proc/cmdline
```

---

# 29. Kernel Messages

```bash
dmesg
```

Human-readable timestamps where supported:

```bash
dmesg -T
```

Do not use commands that clear the kernel message buffer.

---

# 30. Memory Information

```bash
free -h
```

Kernel details:

```bash
cat /proc/meminfo
```

Virtual memory statistics:

```bash
vmstat
```

---

# 31. Swap

```bash
swapon --show
```

Alternative:

```bash
cat /proc/swaps
```

Swap can contain remnants of memory-resident evidence and may warrant acquisition.

---

# 32. Mounted File Systems

```bash
mount
```

Cleaner:

```bash
findmnt
```

Kernel view:

```bash
cat /proc/mounts
```

Process-specific mount view:

```bash
cat /proc/<PID>/mounts
```

---

# 33. Block Devices

```bash
lsblk
```

Detailed:

```bash
lsblk -f
```

Useful:

```bash
lsblk -o NAME,TYPE,SIZE,FSTYPE,MOUNTPOINTS,UUID,MODEL,SERIAL
```

---

# 34. Disk and Partition Information

```bash
fdisk -l
```

Often requires root.

Alternative:

```bash
lsblk
```

Mounted usage:

```bash
df -hT
```

---

# 35. Device UUIDs and Filesystems

```bash
blkid
```

---

# 36. Services — systemd

Running services:

```bash
systemctl --type=service --state=running
```

All services:

```bash
systemctl list-units --type=service --all
```

Installed unit files:

```bash
systemctl list-unit-files --type=service
```

Status:

```bash
systemctl status <service>
```

`systemctl` is the standard systemd interface for inspecting and controlling systemd unit state. During forensic collection, use its **inspection** capabilities rather than commands that start, stop, restart, enable, or disable services.

---

# 37. Non-systemd Service Alternatives

SysV:

```bash
service --status-all
```

Init scripts:

```bash
ls -la /etc/init.d/
```

Do not assume every Linux distribution uses systemd.

---

# 38. Systemd Timers

```bash
systemctl list-timers --all
```

Timers may represent persistence or scheduled execution.

---

# 39. Cron Jobs

System crontab:

```bash
cat /etc/crontab
```

Cron directories:

```bash
ls -la /etc/cron.*
```

Current user:

```bash
crontab -l
```

Other users generally require appropriate privilege:

```bash
crontab -u <USER> -l
```

Also examine:

```bash
ls -la /var/spool/cron/
```

or distribution-specific equivalents.

---

# 40. At Jobs

```bash
atq
```

---

# 41. User Accounts

```bash
cat /etc/passwd
```

Readable account database:

```bash
getent passwd
```

Groups:

```bash
getent group
```

Do not display `/etc/shadow` casually; it contains password hashes and requires careful evidentiary handling.

---

# 42. Sudo Configuration

Main configuration:

```bash
cat /etc/sudoers
```

Include directory:

```bash
ls -la /etc/sudoers.d/
```

Safer syntax-aware listing:

```bash
sudo -l
```

Note that executing `sudo` can itself generate authentication/audit evidence.

---

# 43. SSH Configuration

Server configuration:

```bash
cat /etc/ssh/sshd_config
```

Additional configuration:

```bash
ls -la /etc/ssh/sshd_config.d/
```

Client:

```bash
cat ~/.ssh/config
```

Authorized keys:

```bash
cat ~/.ssh/authorized_keys
```

Known hosts:

```bash
cat ~/.ssh/known_hosts
```

Check all user home directories when authorized and relevant.

---

# 44. Current SSH Connections

Network view:

```bash
ss -tnp | grep ':22'
```

Session view:

```bash
who
```

Process view:

```bash
ps -ef | grep '[s]shd'
```

---

# 45. Shell History

Bash:

```bash
cat ~/.bash_history
```

Zsh:

```bash
cat ~/.zsh_history
```

Other possible histories:

```text
~/.ash_history
~/.python_history
~/.mysql_history
~/.psql_history
~/.rediscli_history
```

Important limitation:

Current interactive commands may remain only in shell memory and may not yet have been written to the history file.

---

# 46. Environment Variables

```bash
env
```

or:

```bash
printenv
```

Sorted:

```bash
printenv | sort
```

---

# 47. Temporary Directories

Common locations:

```bash
ls -la /tmp
ls -la /var/tmp
ls -la /dev/shm
```

Newest first:

```bash
ls -lat /tmp
```

Recursive enumeration should be used thoughtfully on large systems.

---

# 48. Memory-Backed Filesystems

Identify tmpfs:

```bash
findmnt -t tmpfs
```

Alternative:

```bash
mount | grep tmpfs
```

Important locations commonly include:

```text
/dev/shm
/run
/run/user/<UID>
```

These may disappear on reboot.

---

# 49. Recently Modified Files

Example — last day:

```bash
find /tmp -type f -mtime -1 -ls
```

Last 60 minutes:

```bash
find /tmp -type f -mmin -60 -ls
```

Be careful with system-wide recursive `find` operations because they can be expensive and cause extensive metadata access.

---

# 50. System Logs — systemd Journal

Recent journal:

```bash
journalctl
```

Current boot:

```bash
journalctl -b
```

Previous boot:

```bash
journalctl -b -1
```

Recent period:

```bash
journalctl --since "1 hour ago"
```

Service:

```bash
journalctl -u ssh.service
```

Kernel:

```bash
journalctl -k
```

Systemd documents `journalctl` as the utility for reading entries stored by the system journal.

---

# 51. Journal Storage Mode

Inspect configuration:

```bash
grep -v '^[[:space:]]*#' /etc/systemd/journald.conf
```

Potential journal locations:

```bash
ls -ld /var/log/journal
ls -ld /run/log/journal
```

`/run/log/journal` may be volatile depending on configuration.

---

# 52. Traditional Log Files

Common Debian/Ubuntu-style locations:

```text
/var/log/auth.log
/var/log/syslog
/var/log/kern.log
```

Common RHEL-style locations:

```text
/var/log/secure
/var/log/messages
```

List:

```bash
ls -lah /var/log
```

Recent modification:

```bash
find /var/log -type f -printf '%TY-%Tm-%Td %TH:%TM:%TS %p\n' |
sort
```

GNU `find` options may not be available identically on all Unix-like systems.

---

# 53. Authentication Logs

Debian/Ubuntu:

```bash
grep -iE 'sshd|sudo|authentication|session' /var/log/auth.log
```

RHEL-like:

```bash
grep -iE 'sshd|sudo|authentication|session' /var/log/secure
```

Systemd:

```bash
journalctl _COMM=sshd
```

or depending on unit:

```bash
journalctl -u ssh
journalctl -u sshd
```

---

# 54. Firewall Rules — nftables

```bash
nft list ruleset
```

Do not modify the rules.

---

# 55. Firewall Rules — iptables

```bash
iptables -L -n -v
```

Rules:

```bash
iptables-save
```

IPv6:

```bash
ip6tables-save
```

Do not flush or alter firewall rules during initial evidence collection.

---

# 56. SELinux

State:

```bash
getenforce
```

Detailed:

```bash
sestatus
```

Do not disable enforcement as part of collection.

---

# 57. AppArmor

Where installed:

```bash
aa-status
```

---

# 58. Linux Capabilities

Process capabilities:

```bash
grep Cap /proc/<PID>/status
```

File capabilities:

```bash
getcap -r / 2>/dev/null
```

The recursive command can be expensive on large filesystems.

A more targeted collection is preferable.

---

# 59. Listening Services

```bash
ss -lntup
```

Cross-reference PID:

```bash
ps -fp <PID>
```

Executable:

```bash
readlink -f /proc/<PID>/exe
```

Command line:

```bash
tr '\0' ' ' < /proc/<PID>/cmdline
```

This sequence is particularly useful for answering:

> **What process owns this exposed port?**

---

# 60. Network Namespaces

```bash
ip netns list
```

Processes may also have network namespace references:

```bash
ls -l /proc/<PID>/ns/
```

---

# 61. Containers — Docker

Running:

```bash
docker ps
```

All:

```bash
docker ps -a
```

Images:

```bash
docker images
```

Inspect:

```bash
docker inspect <CONTAINER>
```

Processes:

```bash
docker top <CONTAINER>
```

Logs:

```bash
docker logs <CONTAINER>
```

Be aware that Docker commands communicate with the Docker daemon and may themselves generate activity.

---

# 62. Containers — containerd / CRI

Where available:

```bash
crictl ps
```

All:

```bash
crictl ps -a
```

Images:

```bash
crictl images
```

---

# 63. Kubernetes

Where credentials and authorization permit:

```bash
kubectl get pods -A -o wide
```

Nodes:

```bash
kubectl get nodes -o wide
```

Services:

```bash
kubectl get services -A
```

Events:

```bash
kubectl get events -A
```

Do not assume cluster-state queries are harmless: they may be logged by the API server.

---

# 64. Virtual Machines

libvirt:

```bash
virsh list --all
```

VM information:

```bash
virsh dominfo <VM>
```

Do not suspend, resume, destroy, or snapshot VMs unless the collection plan specifically requires it.

---

# 65. Package Inventory

Debian/Ubuntu:

```bash
dpkg -l
```

RHEL/Fedora:

```bash
rpm -qa
```

Modern Fedora/RHEL:

```bash
dnf list installed
```

Avoid upgrading or reinstalling packages.

---

# 66. Recently Installed Packages

Debian-family:

```bash
grep -iE 'install|upgrade|remove' /var/log/dpkg.log
```

RHEL-family:

```bash
rpm -qa --last
```

---

# 67. File Metadata

```bash
stat <FILE>
```

Example:

```bash
stat /tmp/suspicious
```

---

# 68. Hash a File

Common:

```bash
sha256sum suspicious.bin
```

Example:

```bash
sha256sum /tmp/suspicious
```

Other:

```bash
md5sum
sha1sum
sha512sum
```

Prefer modern cryptographic hashes such as SHA-256 for evidence identification.

---

# 69. File Type

```bash
file suspicious.bin
```

Do not execute an unknown file merely to learn what it is.

---

# 70. Deleted but Running Executables

One approach:

```bash
ls -l /proc/*/exe 2>/dev/null | grep deleted
```

Another:

```bash
lsof +L1
```

This can reveal executables or files that have been deleted from the filesystem but remain referenced by active processes.

---

# 71. Process Network + File Correlation

For PID 4242:

```bash
ps -fp 4242
```

```bash
tr '\0' ' ' < /proc/4242/cmdline
```

```bash
readlink -f /proc/4242/exe
```

```bash
ls -la /proc/4242/fd
```

```bash
lsof -p 4242
```

```bash
ss -tunap | grep 4242
```

```bash
cat /proc/4242/maps
```

This gives students a useful mini-investigation workflow around a suspicious process.

---

# 72. Persistence Locations

Inspect, where applicable:

```text
/etc/systemd/system/
/usr/lib/systemd/system/
/lib/systemd/system/
/etc/init.d/
/etc/rc.local
/etc/cron.d/
/etc/cron.daily/
/etc/cron.hourly/
/var/spool/cron/
/etc/profile
/etc/profile.d/
~/.profile
~/.bashrc
~/.bash_profile
~/.config/autostart/
```

Commands:

```bash
find /etc/systemd/system -type f -ls
```

```bash
systemctl list-unit-files
```

```bash
systemctl list-timers --all
```

---

# 73. Shared Libraries

Process mappings:

```bash
cat /proc/<PID>/maps
```

Library cache:

```bash
ldconfig -p
```

LD_PRELOAD:

```bash
cat /etc/ld.so.preload
```

Environment:

```bash
printenv LD_PRELOAD
```

A suspicious `/etc/ld.so.preload` warrants investigation.

---

# 74. Recent Reboots / Shutdowns

```bash
last reboot
```

Shutdown history:

```bash
last -x
```

Systemd:

```bash
journalctl --list-boots
```

---

# 75. USB / Hardware Information

USB:

```bash
lsusb
```

PCI:

```bash
lspci
```

Block storage:

```bash
lsblk
```

Kernel messages:

```bash
dmesg | grep -i usb
```

---

# 76. Network Configuration Files

Distribution dependent.

Common locations include:

```text
/etc/network/
/etc/netplan/
/etc/NetworkManager/
/etc/sysconfig/network-scripts/
```

Inspect only the applicable configuration.

---

# 77. NetworkManager

Where present:

```bash
nmcli connection show
```

Active:

```bash
nmcli connection show --active
```

Devices:

```bash
nmcli device status
```

---

# 78. Listening Ports + Associated Executables

Start with:

```bash
ss -lntup
```

Then:

```bash
ps -fp <PID>
```

Then:

```bash
readlink -f /proc/<PID>/exe
```

Then:

```bash
sha256sum "$(readlink -f /proc/<PID>/exe)"
```

Use the last step only when hashing the executable is justified.

---

# 79. Useful First-Five-Minutes Collection

A typical compact sequence:

```bash
date
date -u
hostname
uname -a
cat /etc/os-release
whoami
id
who
w
uptime
ip addr
ip route
ip neigh
cat /etc/resolv.conf
ss -tunap
ps -eo pid,ppid,user,lstart,etime,args
lsmod
mount
lsblk
free -h
cat /proc/meminfo
swapon --show
systemctl --type=service --state=running
systemctl list-timers --all
```

Then, where relevant:

```bash
lsof +L1
journalctl -b
```

---

# 80. Recommended Volatile Collection Order

For a typical live Linux system:

```text
1. Date/time and hostname
2. Logged-on users and sessions
3. Network interfaces
4. Neighbor/ARP cache
5. Routes
6. Active TCP/UDP sockets
7. Running processes
8. Process trees / command lines
9. Open files and file descriptors
10. Deleted-but-open files
11. Loaded kernel modules
12. Services / timers / cron
13. RAM acquisition
14. tmpfs / /dev/shm / temporary data
15. Kernel and system logs
16. Persistent forensic artifacts
17. Disk acquisition
18. Remote infrastructure evidence
```

The actual order should depend on the evidence's **effective volatility**.

---

# 81. Commands to Avoid During Initial Collection

Do not casually:

- [ ] kill processes
- [ ] restart services
- [ ] stop services
- [ ] unload kernel modules
- [ ] flush firewall rules
- [ ] clear logs
- [ ] clear caches
- [ ] delete temporary files
- [ ] rotate logs manually
- [ ] renew network configuration
- [ ] modify routes
- [ ] change DNS
- [ ] install packages
- [ ] update packages
- [ ] reboot
- [ ] shut down

Examples of non-collection actions:

```bash
kill -9 <PID>
systemctl restart sshd
systemctl stop <service>
iptables -F
nft flush ruleset
ip neigh flush all
dmesg -C
journalctl --rotate
reboot
shutdown -h now
```

These may destroy or alter evidence.

---

# 82. Know Your Commands

One of the most important Linux DFIR habits is:

```bash
man <command>
```

Examples:

```bash
man ss
man ps
man lsof
man find
man journalctl
```

Also:

```bash
<command> --help
```

Do not blindly copy commands from an incident-response cheat sheet onto a system you do not understand.

---

# 83. Student Rule

Before executing any live-response command, ask:

> **What evidence am I trying to preserve, and could this command destroy or alter more valuable evidence?**

Then ask:

> **Is there a more volatile source I should collect first?**

The goal is not to execute the largest number of commands.

The goal is to preserve **high-value evidence in a defensible order with the minimum reasonable impact on the system**.