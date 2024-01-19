#!/bin/bash
# Red Hat 7 Config Extraction Script v1.2 (220913)
# By PulseSecure
# Do not redistribute this script and output file without permission from PulseSecure
# Checklist Reference: CIS Red Hat Enterprise Linux 7 Benchmark v3.1.1
#
# Example:
# ./RHEL7_8.sh > "$(hostname).txt" 2>&1

echo -e '\n[Checklist: CIS_RHEL_7_v3.1.1]'
uname -a
cat /etc/redhat-release

echo -e '\n[1.1.1.1 Ensure mounting of cramfs filesystems is disabled]'
modprobe -n -v cramfs | grep -E '(cramfs|install)'
lsmod | grep cramfs

echo -e '\n[1.1.1.2 Ensure mounting of squashfs filesystems is disabled](L2)'
modprobe -n -v squashfs | grep -E '(squashfs|install)'
lsmod | grep squashfs

echo -e '\n[1.1.1.3 Ensure mounting of udf filesystems is disabled]'
modprobe -n -v udf | grep -E '(udf|install)'
lsmod | grep udf

echo -e '\n[1.1.1.4 Ensure mounting of FAT filesystems is limited](L2)'
grep -E -i '\svfat\s' /etc/fstab

echo -e '\n[1.1.2 Ensure /tmp is configured] and'
echo -e '\n[1.1.3 Ensure noexec option set on /tmp partition] and'
echo -e '\n[1.1.4 Ensure nodev option set on /tmp partition] and'
echo -e '\n[1.1.5 Ensure nosuid option set on /tmp partition]'
echo -e '\n not required to check for MSF'
findmnt -n /tmp
mount | grep -E '\s/tmp\s'
grep -E '\s/tmp\s' /etc/fstab | grep -E -v '^\s*#'
systemctl show "tmp.mount" | grep -i unitfilestate

echo -e '\n[1.1.6 Ensure /dev/shm is configured] and'
echo -e '\n[1.1.7 Ensure noexec option set on /dev/shm partition] and'
echo -e '\n[1.1.8 Ensure nodev option set on /dev/shm partition] and'
echo -e '\n[1.1.9 Ensure nosuid option set on /dev/shm partition]'
echo -e '\n not required to check for MSF'
findmnt -n /dev/shm
mount | grep -E '\s/dev/shm\s'
grep -E '\s/dev/shm\s' /etc/fstab

echo -e '\n[1.1.10 Ensure separate partition exists for /var](L2)'
echo -e '\n not required to check for MSF'
findmnt /var
mount | grep -E '\s/var\s'

echo -e '\n[1.1.11 Ensure separate partition exists for /var/tmp](L2) and'
echo -e '\n[1.1.12 Ensure noexec option set on /var/tmp partition] and'
echo -e '\n[1.1.13 Ensure nodev option set on /var/tmp partition ] and'
echo -e '\n[1.1.14 Ensure nosuid option set on /var/tmp partition] and'
echo -e '\n not required to check for MSF'
findmnt /var/tmp
mount | grep /var/tmp

echo -e '\n[1.1.15 Ensure separate partition exists for /var/log](L2)'
echo -e '\n not required to check for MSF'
findmnt /var/log
mount | grep -E '\s/var/log\s'

echo -e '\n[1.1.16 Ensure separate partition exists for /var/log/audit](L2)'
echo -e '\n not required to check for MSF'
findmnt /var/log/audit
mount | grep /var/log/audit

echo -e '\n[1.1.17 Ensure separate partition exists for /home](L2) and'
echo -e '\n[1.1.18 Ensure nodev option set on /home partition]' 
echo -e '\n not required to check for MSF'
findmnt /home
mount | grep /home

echo -e '\n[1.1.19 Ensure removable media partitions include noexec option]'
for rmpo in $(lsblk -o RM,MOUNTPOINT | awk -F " " '/ 1 / {print $2}'); do findmnt -n "$rmpo" | grep -Ev "\bnoexec\b" 
done

echo -e '\n[1.1.20 Ensure nodev option set on removable media partitions]'
for rmpo in $(lsblk -o RM,MOUNTPOINT | awk -F " " '/ 1 / {print $2}'); do findmnt -n "$rmpo" | grep -Ev "\bnodev\b" 
done

echo -e '\n[1.1.21 Ensure nosuid option set on removable media partitions]'
for rmpo in $(lsblk -o RM,MOUNTPOINT | awk -F " " '/ 1 / {print $2}'); do findmnt -n "$rmpo" | grep -Ev "\bnosuid\b" 
done

echo -e '\n[1.1.22 Ensure sticky bit is set on all world-writable directories]'
df --local -P 2> /dev/null | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null

echo -e '\n[1.1.23 Disable Automounting]'
systemctl is-enabled autofs
systemctl show "autofs.service" | grep -i unitfilestate=enabled

echo -e '\n[1.1.24 Disable USB Storage]'
modprobe -n -v usb-storage
lsmod | grep usb-storage

echo -e '\n[1.2.1 Ensure GPG keys are configured]'
rpm -q gpg-pubkey --qf '%{name}-%{version}-%{release} --> %{summary}\n'

echo -e '\n[1.2.2 Ensure package manager repositories are configured]'
yum repolist

echo -e '\n[1.2.3 Ensure gpgcheck is globally activated]'
grep ^\s*gpgcheck /etc/yum.conf
grep -P '^\h*gpgcheck=[^1\n\r]+\b(\h+.*)?$' /etc/yum.conf /etc/yum.repos.d/*.repo

echo -e '\n[1.2.4 Ensure Red Hat Subscription Manager connection is configured]'
subscription-manager identity

echo -e '\n[1.2.5 Disable the rhnsd Daemon](L2)]'
systemctl is-enabled rhnsd

echo -e '\n[1.3.1 Ensure AIDE is installed]'
rpm -q aide

echo -e '\n[1.3.2 Ensure filesystem integrity is regularly checked]'
crontab -u root -l | grep aide
grep -r aide /etc/cron.* /etc/crontab
echo -ne "aidecheck.service=";systemctl is-enabled aidecheck.service
echo -ne "aidecheck.timer=";systemctl is-enabled aidecheck.timer
systemctl status aidecheck.timer

echo -e '\n[1.4.1 Ensure bootloader password is set]'
echo -e '\n not required to check for MSF'
grep "^\s*password" /boot/grub2/grub.cfg
grep "^\s*GRUB2_PASSWORD" /boot/grub2/user.cfg
grep "^\s*GRUB2_PASSWORD" /boot/grub2/grub.cfg
tst1="" tst2="" output=""
efidir=$(find /boot/efi/EFI/* -type d -not -name 'BOOT')
gbdir=$(find /boot -maxdepth 1 -type d -name 'grub*')
if [ -f "$efidir"/grub.cfg ]; then
	grubdir="$efidir" && grubfile="$efidir/grub.cfg"
elif [ -f "$gbdir"/grub.cfg ]; then
	grubdir="$gbdir" && grubfile="$gbdir/grub.cfg"
fi
userfile="$grubdir/user.cfg" 
[ -f "$userfile" ] && grep -Pq '^\h*GRUB2_PASSWORD\h*=\h*.+$' "$userfile" && output="\n PASSED: bootloader password set in \"$userfile\"\n\n"
if [ -z "$output" ] && [ -f "$grubfile" ]; then
	grep -Piq '^\h*set\h+superusers\h*=\h*"?[^"\n\r]+"?(\h+.*)?$' "$grubfile" && tst1=pass
	grep -Piq '^\h*password\h+\H+\h+.+$' "$grubfile" && tst2=pass [ "$tst1" = pass ] && [ "$tst2" = pass ] && output="\n\n*** PASSED: bootloader password set in \"$grubfile\" ***\n\n"
fi
[ -n "$output" ] && echo -e "$output" || echo -e "\n\n *** FAILED: bootloader password is not set ***\n\n"

echo -e '\n[1.4.2 Ensure permissions on bootloader config are configured]'
stat /boot/grub2/grub.cfg
stat /boot/grub2/user.cfg
tst1="" tst2="" tst3="" tst4="" test1="" test2="" efidir="" gbdir=""
grubdir="" grubfile="" userfile=""
efidir=$(find /boot/efi/EFI/* -type d -not -name 'BOOT')
gbdir=$(find /boot -maxdepth 1 -type d -name 'grub*')
for file in "$efidir"/grub.cfg "$efidir"/grub.conf; do
	[ -f "$file" ] && grubdir="$efidir" && grubfile=$file
done
if [ -z "$grubdir" ]; then
	for file in "$gbdir"/grub.cfg "$gbdir"/grub.conf; do
		[ -f "$file" ] && grubdir="$gbdir" && grubfile=$file
	done
fi
userfile="$grubdir/user.cfg"
stat -c "%a" "$grubfile" | grep -Pq '^\h*[0-7]00$' && tst1=pass
output="Permissions on \"$grubfile\" are \"$(stat -c "%a" "$grubfile")\""
stat -c "%u:%g" "$grubfile" | grep -Pq '^\h*0:0$' && tst2=pass
output2="\"$grubfile\" is owned by \"$(stat -c "%U" "$grubfile")\" and belongs to group \"$(stat -c "%G" "$grubfile")\""
[ "$tst1" = pass ] && [ "$tst2" = pass ] && test1=pass
if [ -f "$userfile" ]; then
	stat -c "%a" "$userfile" | grep -Pq '^\h*[0-7]00$' && tst3=pass
	output3="Permissions on \"$userfile\" are \"$(stat -c "%a" "$userfile")\""
	stat -c "%u:%g" "$userfile" | grep -Pq '^\h*0:0$' && tst4=pass
	output4="\"$userfile\" is owned by \"$(stat -c "%U" "$userfile")\" and belongs to group \"$(stat -c "%G" "$userfile")\""
	[ "$tst3" = pass ] && [ "$tst4" = pass ] && test2=pass
else
	test2=pass
fi
[ "$test1" = pass ] && [ "$test2" = pass ] && passing=true
if [ "$passing" = true ] ; then
	# If passing is true we pass
	echo "PASSED:"
	echo "$output"
	echo "$output2"
	[ -n "$output3" ] && echo "$output3"
	[ -n "$output4" ] && echo "$output4"
else
	# print the reason why we are failing
	echo "FAILED:"
	echo "$output"
	echo "$output2"
	[ -n "$output3" ] && echo "$output3"
	[ -n "$output4" ] && echo "$output4"
fi

echo -e '\n[1.4.3 Ensure authentication required for single user mode]'
grep /sbin/sulogin /usr/lib/systemd/system/rescue.service
grep /sbin/sulogin /usr/lib/systemd/system/emergency.service

echo -e '\n[1.5.1 Ensure core dumps are restricted]'
grep -E "^\s*\*\s+hard\s+core" /etc/security/limits.conf
sysctl fs.suid_dumpable
grep "fs\.suid_dumpable" /etc/sysctl.conf /etc/sysctl.d/*
systemctl is-enabled coredump.service

echo -e '\n[1.2.2 Ensure XD/NX support is enabled]'
journalctl | grep 'protection: active' 
[[ -n $(grep noexec[0-9]*=off /proc/cmdline) || -z $(grep -E -i ' (pae|nx) ' /proc/cpuinfo) || -n $(grep '\sNX\s.*\sprotection:\s' /var/log/dmesg | grep -v active) ]] && echo "NX Protection is not active"

echo -e '\n[1.5.3 Ensure address space layout randomization (ASLR) is enabled]'
sysctl kernel.randomize_va_space
grep "kernel\.randomize_va_space" /etc/sysctl.conf /etc/sysctl.d/*

echo -e '\n[1.5.4 Ensure prelink is disabled]'
rpm -q prelink

echo -e '\n[1.6.1.1 Ensure SELinux is installed]'
rpm -q libselinux

echo -e '\n[1.6.1.2 Ensure SELinux is not disabled in bootloader configuration]'
grep "^\s*linux" /boot/grub2/grub.cfg | grep -E "(selinux=0|enforcing=0)"
# IF check passes return PASSED
efidir=$(find /boot/efi/EFI/* -type d -not -name 'BOOT')
gbdir=$(find /boot -maxdepth 1 -type d -name 'grub*')
if [ -f "$efidir"/grub.cfg ]; then
	grep "^\s*linux" "$efidir"/grub.cfg | grep -Eq "(selinux=0|enforcing=0)" && echo "FAILED: \"$()\" exists" || echo "PASSED"
elif [ -f "$gbdir"/grub.cfg ]; then
	grep "^\s*linux" "$gbdir"/grub.cfg | grep -Eq "(selinux=0|enforcing=0)" && echo "FAILED: \"$()\" exists" || echo "PASSED"
else
	echo "FAILED"
fi

echo -e '\n[1.6.1.3 Ensure SELinux policy is configured]'
grep SELINUXTYPE= /etc/selinux/config
sestatus | grep 'Loaded policy'

echo -e '\n[1.6.1.4 Ensure the SELinux mode is enforcing or permissive] and'
echo -e '\n[1.6.1.5 Ensure the SELinux mode is enforcing](L2)' 
getenforce
grep -Ei '^\s*SELINUX=(enforcing|permissive)' /etc/selinux/config

echo -e '\n[1.6.1.6 Ensure no unconfined services exist]'
echo -e '\n---Exclude accepted services:'
echo -e '\n   AWS Services: SSM, Cloudwatch'
echo -e '\n   Splunk and Nessus'
echo -e '\n   Anti-malware: Trend Micro, Symantec'
ps -eZ | grep unconfined_service_t

echo -e '\n[1.6.1.7 Ensure SETroubleshoot is not installed]'
rpm -q setroubleshoot

echo -e '\n[1.6.1.8 Ensure the MCS Translation Service (mcstrans) is not installed]'
rpm -q mcstrans

echo -e '\n[1.7.1 Ensure message of the day is configured properly]'
echo -e '\n not required to check for MSF'
cat /etc/motd
#grep -E -i "(\\\v|\\\r|\\\m|\\\s|$(grep '^ID=' /etc/os-release | cut -d= -f2 | sed -e 's/"//g'))" /etc/motd

echo -e '\n[1.7.2 Ensure local login warning banner is configured properly]'
echo -e '\n not required to check for MSF'
cat /etc/issue
#grep -E -i "(\\\v|\\\r|\\\m|\\\s|$(grep '^ID=' /etc/os-release | cut -d= -f2 | sed -e 's/"//g'))" /etc/issue

echo -e '\n[1.7.3 Ensure remote login warning banner is configured properly]'
echo -e '\n not required to check for MSF'
cat /etc/issue.net
#grep -E -i "(\\\v|\\\r|\\\m|\\\s|$(grep '^ID=' /etc/os-release | cut -d= -f2 | sed -e 's/"//g'))" /etc/issue.net

echo -e '\n[1.7.4 Ensure permissions on /etc/motd are configured]'
stat /etc/motd

echo -e '\n[1.7.5 Ensure permissions on /etc/issue are configured]'
stat /etc/issue

echo -e '\n[1.7.6 Ensure permissions on /etc/issue.net are configured]'
stat /etc/issue.net

echo -e '\n[1.8.1 Ensure GNOME Display Manager is removed]'
rpm -q gdm

echo -e '\n[1.8.2 Ensure GDM login banner is configured] and'
echo -e '\n[1.8.3 Ensure last logged in user display is disabled]'
cat /etc/dconf/profile/gdm
cat /etc/dconf/db/gdm.d/01-banner-message
cat /etc/dconf/db/gdm.d/00-login-screen

echo -e '\n[1.8.4 Ensure XDCMP is not enabled]'
grep -Eis '^\s*Enable\s*=\s*true' /etc/gdm/custom.conf

echo -e '\n[1.9 Ensure updates, patches, and additional security software are installed]'
yum check-update

echo -e '\n[2.1.2 Ensure xinetd is not installed]'
rpm -q xinetd

echo -e '\n[2.2.1.1 Ensure time synchronization is in use]'
rpm -q chrony
rpm -q ntp

echo -e '\n[2.2.1.2 Ensure chrony is configured]'
grep -E "^(server|pool)" /etc/chrony.conf
grep ^OPTIONS /etc/sysconfig/chronyd

echo -e '\n[2.2.1.3 Ensure ntp is configured]'
grep "^restrict" /etc/ntp.conf
grep -E "^(server|pool)" /etc/ntp.conf
grep "^OPTIONS" /etc/sysconfig/ntpd
grep "^ExecStart" /usr/lib/systemd/system/ntpd.service

echo -e '\n[2.2.2 Ensure X11 Server components are not installed]'
rpm -qa xorg-x11-server*

echo -e '\n[2.2.3 Ensure Avahi Server is not installed]'
rpm -q avahi-autoipd avahi
systemctl is-enabled avahi-daemon

echo -e '\n[2.2.4 Ensure CUPS is not installed]'
rpm -q cups
systemctl is-enabled cups

echo -e '\n[2.2.5 Ensure DHCP Server is not installed]'
rpm -q dhcp
systemctl is-enabled dhcpd

echo -e '\n[2.2.6 Ensure LDAP server is not installed]'
rpm -q openldap-servers
systemctl is-enabled slapd

echo -e '\n[2.2.7 Ensure DNS server is not installed]'
rpm -q bind
systemctl is-enabled named

echo -e '\n[2.2.8 Ensure FTP server is not installed]'
rpm -q vsftpd
systemctl is-enabled vsftpd

echo -e '\n[2.2.9 Ensure HTTP server is not installed]'
rpm -q httpd
systemctl is-enabled httpd

echo -e '\n[2.2.10 Ensure IMAP and POP3 server is not installed]'
rpm -q dovecot
systemctl is-enabled dovecot

echo -e '\n[2.2.11 Ensure Samba is not installed]'
rpm -q samba
systemctl is-enabled smb

echo -e '\n[2.2.12 Ensure HTTP Proxy Server is not installed]'
rpm -q squid 
systemctl is-enabled squid

echo -e '\n[2.2.13 Ensure net-snmp is not installed]'
rpm -q net-snmp
systemctl is-enabled snmpd

echo -e '\n[2.2.14 Ensure NIS server is not installed]'
rpm -q ypserv
systemctl is-enabled ypserv

echo -e '\n[2.2.15 Ensure telnet-server is not installed]'
rpm -q telnet-server
systemctl is-enabled telnet.socket

echo -e '\n[2.2.16 Ensure mail transfer agent is configured for local-only mode]'
ss -lntu | grep -E ':25\s' | grep -E -v '\s(127.0.0.1|\[?::1\]?):25\s'

echo -e '\n[2.2.17 Ensure nfs-utils is not installed or the nfs-server service is masked]'
rpm -q nfs-utils
echo -ne "nfs-server=";systemctl is-enabled nfs-server
echo -ne "nfs=";systemctl is-enabled nfs

echo -e '\n[2.2.18 Ensure rpcbind is not installed or the rpcbind services are masked]'
rpm -q rpcbind
echo -ne "rpcbind=";systemctl is-enabled rpcbind
echo -ne "rpcbind.socket=";systemctl is-enabled rpcbind.socket

echo -e '\n[2.2.19 Ensure rsync is not installed or the rsyncd service is masked]'
rpm -q rsync
systemctl is-enabled rsyncd

echo -e '\n[2.3.1 Ensure NIS Client is not installed]'
rpm -q ypbind

echo -e '\n[2.3.2 Ensure rsh client is not installed]'
rpm -q rsh
echo -ne "rsh.socket=";systemctl is-enabled rsh.socket
echo -ne "rlogin.socket=";systemctl is-enabled rlogin.socket
echo -ne "rexec.socket=";systemctl is-enabled rexec.socket

echo -e '\n[2.3.3 Ensure talk client is not installed]'
rpm -q talk
systemctl is-enabled talk

echo -e '\n[2.3.4 Ensure telnet client is not installed]'
rpm -q telnet

echo -e '\n[2.3.5 Ensure LDAP client is not installed]'
rpm -q openldap-clients

echo -e '\n[2.4 Ensure nonessential services are removed or masked]'
lsof -i -P -n | grep -v "(ESTABLISHED)"

echo -e '\n[3.1.1 Disable IPv6](L2)'
grep "^\s*linux" /boot/grub2/grub.cfg | grep -v ipv6.disable=1
sysctl net.ipv6.conf.all.disable_ipv6
sysctl net.ipv6.conf.default.disable_ipv6
grep -E '^\s*net\.ipv6\.conf\.(all|default)\.disable_ipv6\s*=\s*1\b(\s+#.*)?$' /etc/sysctl.conf /etc/sysctl.d/*.conf | cut -d: -f2

echo -e '\n[3.1.2 Ensure wireless interfaces are disabled]'
iw list
ip link show up
if command -v nmcli >/dev/null 2>&1 ; then
	if nmcli radio all | grep -Eq '\s*\S+\s+disabled\s+\S+\s+disabled\b'; then
		echo "Wireless is not enabled"
	else
		nmcli radio all
	fi
elif [ -n "$(find /sys/class/net/*/ -type d -name wireless)" ]; then
	t=0
	mname=$(for driverdir in $(find /sys/class/net/*/ -type d -name wireless | xargs -0 dirname); do basename "$(readlink -f "$driverdir"/device/driver/module)";done | sort -u)
	for dm in $mname; do
		if grep -Eq "^\s*install\s+$dm\s+/bin/(true|false)" /etc/modprobe.d/*.conf; then
			/bin/true
		else
			echo "$dm is not disabled"
			t=1
		fi
	done
	[ "$t" -eq 0 ] && echo "Wireless is not enabled"
else
	echo "Wireless is not enabled"
fi

echo -e '\n[3.2.1 Ensure IP forwarding is disabled]'
sysctl net.ipv4.ip_forward
grep -E -s "^\s*net\.ipv4\.ip_forward\s*=\s*1" /etc/sysctl.conf /etc/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /run/sysctl.d/*.conf
sysctl net.ipv6.conf.all.forwarding
grep -E -s "^\s*net\.ipv6\.conf\.all\.forwarding\s*=\s*1" /etc/sysctl.conf /etc/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /run/sysctl.d/*.conf

echo -e '\n[3.2.2 Ensure packet redirect sending is disabled]'
sysctl net.ipv4.conf.all.send_redirects
sysctl net.ipv4.conf.default.send_redirects
grep "net\.ipv4\.conf\.all\.send_redirects" /etc/sysctl.conf /etc/sysctl.d/*
grep "net\.ipv4\.conf\.default\.send_redirects" /etc/sysctl.conf /etc/sysctl.d/*

echo -e '\n[3.3.1 Ensure source routed packets are not accepted]'
sysctl net.ipv4.conf.all.accept_source_route
sysctl net.ipv4.conf.default.accept_source_route
grep "net\.ipv4\.conf\.all\.accept_source_route" /etc/sysctl.conf /etc/sysctl.d/*
grep "net\.ipv4\.conf\.default\.accept_source_route" /etc/sysctl.conf /etc/sysctl.d/*
sysctl net.ipv6.conf.all.accept_source_route
sysctl net.ipv6.conf.default.accept_source_route
grep "net\.ipv6\.conf\.all\.accept_source_route" /etc/sysctl.conf /etc/sysctl.d/*
grep "net\.ipv6\.conf\.default\.accept_source_route" /etc/sysctl.conf /etc/sysctl.d/*

echo -e '\n[3.3.2 Ensure ICMP redirects are not accepted]'
sysctl net.ipv4.conf.all.accept_redirects
sysctl net.ipv4.conf.default.accept_redirects
grep "net\.ipv4\.conf\.all\.accept_redirects" /etc/sysctl.conf /etc/sysctl.d/*
grep "net\.ipv4\.conf\.default\.accept_redirects" /etc/sysctl.conf /etc/sysctl.d/*
sysctl net.ipv6.conf.all.accept_redirects
sysctl net.ipv6.conf.default.accept_redirects
grep "net\.ipv6\.conf\.all\.accept_redirects" /etc/sysctl.conf /etc/sysctl.d/*
grep "net\.ipv6\.conf\.default\.accept_redirects" /etc/sysctl.conf /etc/sysctl.d/*

echo -e '\n[3.3.3 Ensure secure ICMP redirects are not accepted]'
sysctl net.ipv4.conf.all.secure_redirects
sysctl net.ipv4.conf.default.secure_redirects
grep "net\.ipv4\.conf\.all\.secure_redirects" /etc/sysctl.conf /etc/sysctl.d/*
grep "net\.ipv4\.conf\.default\.secure_redirects" /etc/sysctl.conf /etc/sysctl.d/*

echo -e '\n[3.3.4 Ensure suspicious packets are logged]'
sysctl net.ipv4.conf.all.log_martians
sysctl net.ipv4.conf.default.log_martians
grep "net\.ipv4\.conf\.all\.log_martians" /etc/sysctl.conf /etc/sysctl.d/*
grep "net\.ipv4\.conf\.default\.log_martians" /etc/sysctl.conf /etc/sysctl.d/*

echo -e '\n[3.3.5 Ensure broadcast ICMP requests are ignored]'
sysctl net.ipv4.icmp_echo_ignore_broadcasts
grep "net\.ipv4\.icmp_echo_ignore_broadcasts" /etc/sysctl.conf /etc/sysctl.d/*

echo -e '\n[3.3.6 Ensure bogus ICMP responses are ignored]'
sysctl net.ipv4.icmp_ignore_bogus_error_responses
grep "net.ipv4.icmp_ignore_bogus_error_responses" /etc/sysctl.conf /etc/sysctl.d/*

echo -e '\n[3.3.7 Ensure Reverse Path Filtering is enabled]'
sysctl net.ipv4.conf.all.rp_filter
sysctl net.ipv4.conf.default.rp_filter
grep "net\.ipv4\.conf\.all\.rp_filter" /etc/sysctl.conf /etc/sysctl.d/*
grep "net\.ipv4\.conf\.default\.rp_filter" /etc/sysctl.conf /etc/sysctl.d/*

echo -e '\n[3.3.8 Ensure TCP SYN Cookies is enabled]'
sysctl net.ipv4.tcp_syncookies
grep "net\.ipv4\.tcp_syncookies" /etc/sysctl.conf /etc/sysctl.d/*

echo -e '\n[3.3.9 Ensure IPv6 router advertisements are not accepted]'
sysctl net.ipv6.conf.all.accept_ra
sysctl net.ipv6.conf.default.accept_ra
grep "net\.ipv6\.conf\.all\.accept_ra" /etc/sysctl.conf /etc/sysctl.d/*
grep "net\.ipv6\.conf\.default\.accept_ra" /etc/sysctl.conf /etc/sysctl.d/*

echo -e '\n[3.4.1 Ensure DCCP is disabled](L2)'
modprobe -n -v dccp
lsmod | grep dccp

echo -e '\n[3.4.2 Ensure SCTP is disabled](L2)'
modprobe -n -v sctp
lsmod | grep sctp

echo -e '\n<ONLY ONE OF THE FOLLOWING SHOULD BE USED: -FIREWALLD-NFTABLES-IPTABLES->'
echo -e '\n<If FIREWALLD is used>'
echo -e '\n[3.5.1.1 Ensure firewalld is installed]'
rpm -q firewalld iptables

echo -e '\n[3.5.1.2 Ensure iptables-services not installed with firewalld]'
rpm -q firewalld
rpm -q iptables-services

echo -e '\n[3.5.1.3 Ensure nftables either not installed or masked with firewalld]'
rpm -q firewalld
rpm -q nftables
systemctl status nftables | grep "Active: " | grep -E " active \((running|exited)\) "
systemctl is-enabled nftables

echo -e '\n[3.5.1.4 Ensure firewalld service is enabled and running]'
systemctl status firewalld | grep "Active: " | grep -v "active (running) "
systemctl is-enabled firewalld
firewall-cmd --state

echo -e '\n[3.5.1.5 Ensure firewalld default zone is set]'
firewall-cmd --get-default-zone

echo -e '\n[3.5.1.6 Ensure network interfaces are assigned to appropriate zone]'
nmcli -t connection show | awk -F: '{if($4){print $4}}' | while read INT; do firewall-cmd --get-active-zones | grep -B1 $INT; done

echo -e '\n[3.5.1.7 Ensure unnecessary services and ports are not accepted]'
firewall-cmd --get-active-zones | awk '!/:/ {print $1}' | while read ZN; do firewall-cmd --list-all --zone=$ZN; done

echo -e '\n<If NFTABLES is used>'
echo -e '\n[3.5.2.1 Ensure nftables is installed]'
rpm -q nftables

echo -e '\n[3.5.2.2 Ensure firewalld is either not installed or masked with nftables]'
rpm -q nftables
rpm -q firewalld
systemctl is-enabled firewalld

echo -e '\n[3.5.2.3 Ensure iptables-services not installed with nftables]'
rpm -q nftables
rpm -q iptables-services

echo -e '\n[3.5.2.4 Ensure iptables are flushed with nftables]'
iptables -L
ip6tables -L

echo -e '\n[3.5.2.5 Ensure an nftables table exists]'
nft list tables

echo -e '\n[3.5.2.6 Ensure nftables base chains exist] and'
echo -e '\n[3.5.2.9 Ensure nftables default deny firewall policy]'
nft list ruleset | grep 'hook input'
nft list ruleset | grep 'hook forward'
nft list ruleset | grep 'hook output'

echo -e '\n[3.5.2.7 Ensure nftables loopback traffic is configured]'
nft list ruleset | awk '/hook input/,/}/' | grep 'iif "lo" accept'
nft list ruleset | awk '/hook input/,/}/' | grep 'ip saddr'
nft list ruleset | awk '/hook input/,/}/' | grep 'ip6 saddr'

echo -e '\n[3.5.2.8 Ensure nftables outbound and established connections are configured]'
nft list ruleset | awk '/hook input/,/}/' | grep -E 'ip protocol (tcp|udp|icmp) ct state'
nft list ruleset | awk '/hook output/,/}/' | grep -E 'ip protocol (tcp|udp|icmp) ct state'

echo -e '\n[3.5.2.10 Ensure nftables service is enabled]'
systemctl is-enabled nftables

echo -e '\n[3.5.2.11 Ensure nftables rules are permanent]'
if test -f "$FILE"; then
  awk '/hook input/,/}/' $(awk '$1 ~ /^\s*include/ { gsub("\"","",$2);print $2 }' /etc/sysconfig/nftables.conf)
  awk '/hook forward/,/}/' $(awk '$1 ~ /^\s*include/ { gsub("\"","",$2);print $2 }' /etc/sysconfig/nftables.conf)
  awk '/hook output/,/}/' $(awk '$1 ~ /^\s*include/ { gsub("\"","",$2);print $2 }' /etc/sysconfig/nftables.conf)
else
  echo "/etc/sysconfig/nftables.conf not exist"
fi

echo -e '\n<If IPTABLES is used>'
echo -e '\n[3.5.3.1.1 Ensure iptables packages are installed]'
rpm -q iptables iptables-services

echo -e '\n[3.5.3.1.2 Ensure nftables is not installed with iptables]'
rpm -q iptables
rpm -q nftables

echo -e '\n[3.5.3.1.3 Ensure firewalld is either not installed or masked with iptables]'
rpm -q iptables
rpm -q firewalld
systemctl is-enabled firewalld

echo -e '\n[3.5.3.2.1 Ensure iptables loopback traffic is configured]'
iptables -L INPUT -v -n
iptables -L OUTPUT -v -n

echo -e '\n[3.5.3.2.2 Ensure iptables outbound and established connections are configured]'
iptables -L -v -n

echo -e '\n[3.5.3.2.3 Ensure iptables rules exist for all open ports]'
ss -4tuln
iptables -L INPUT -v -n

echo -e '\n[3.5.3.2.4 Ensure iptables default deny firewall policy]'
iptables -L

echo -e '\n[3.5.3.2.5 Ensure iptables rules are saved]'
cat /etc/sysconfig/iptables

echo -e '\n[3.5.3.2.6 Ensure iptables is enabled and running]'
systemctl is-enabled iptables
systemctl status iptables | grep -E " Active: active \((running|exited)\) "

echo -e '\n[3.5.3.3.1 Ensure ip6tables loopback traffic is configured]'
ip6tables -L INPUT -v -n
ip6tables -L OUTPUT -v -n

echo -e '\n[3.5.3.3.2 Ensure ip6tables outbound and established connections are configured]'
ip6tables -L -v -n

echo -e '\n[3.5.3.3.3 Ensure ip6tables firewall rules exist for all open ports]'
ss -6tuln
ip6tables -L INPUT -v -n

echo -e '\n[3.5.3.3.4 Ensure ip6tables default deny firewall policy]'
ip6tables -L

echo -e '\n[3.5.3.3.5 Ensure ip6tables rules are saved]'
cat /etc/sysconfig/ip6tables

echo -e '\n[3.5.3.3.6 Ensure ip6tables is enabled and running]'
systemctl is-enabled ip6tables
systemctl status ip6tables | grep -E " Active: active \((running|exited)\) "

echo -e '\n[4.1.1.1 Ensure auditd is installed](L2)'
rpm -q audit audit-libs

echo -e '\n[4.1.1.2 Ensure auditd service is enabled and running](L2)'
systemctl is-enabled auditd
systemctl status auditd | grep 'Active: active (running)'

echo -e '\n[4.1.1.3 Ensure auditing for processes that start prior to auditd is enabled](L2)'
grep "^\s*linux" /boot/grub2/grub.cfg | grep -v "audit=1"
# IF check passes return PASSED
efidir=$(find /boot/efi/EFI/* -type d -not -name 'BOOT')
gbdir=$(find /boot -maxdepth 1 -type d -name 'grub*')
if [ -f "$efidir"/grub.cfg ]; then
	grep "^\s*linux" "$efidir"/grub.cfg | grep -Evq "audit=1\b" && echo "FAILED" || echo "PASSED"
elif [ -f "$gbdir"/grub.cfg ]; then
	grep "^\s*linux" "$gbdir"/grub.cfg | grep -Evq "audit=1\b" && echo "FAILED" || echo "PASSED"
else
	echo "FAILED"
fi

echo -e '\n[4.1.2.1 Ensure audit log storage size is configured](L2)'
grep max_log_file /etc/audit/auditd.conf

echo -e '\n[4.1.2.2 Ensure audit logs are not automatically deleted](L2)'
grep max_log_file_action /etc/audit/auditd.conf

echo -e '\n[4.1.2.3 Ensure system is disabled when audit logs are full](L2)'
grep space_left_action /etc/audit/auditd.conf
grep action_mail_acct /etc/audit/auditd.conf
grep admin_space_left_action /etc/audit/auditd.conf

echo -e '\n[4.1.2.4 Ensure audit_backlog_limit is sufficient](L2)'
grep "^\s*linux" /boot/grub2/grub.cfg | grep -v "audit_backlog_limit="
grep "audit_backlog_limit=" /boot/grub2/grub.cfg

echo -e '\n[4.1.3 Ensure events that modify date and time information are collected](L2)'
grep time-change /etc/audit/rules.d/*.rules
auditctl -l | grep time-change

echo -e '\n[4.1.4 Ensure events that modify user/group information are collected](L2)'
grep identity /etc/audit/rules.d/*.rules
auditctl -l | grep identity

echo -e '\n[4.1.5 Ensure events that modify the system network environment are collected](L2)'
grep system-locale /etc/audit/rules.d/*.rules
auditctl -l | grep system-locale

echo -e '\n[4.1.6 Ensure events that modify the system Mandatory Access Controls are collected](L2)'
grep MAC-policy /etc/audit/rules.d/*.rules
auditctl -l | grep MAC-policy

echo -e '\n[4.1.7 Ensure login and logout events are collected](L2)'
grep logins /etc/audit/rules.d/*.rules
auditctl -l | grep logins

echo -e '\n[4.1.8 Ensure session initiation information is collected](L2)'
grep -E '(session|logins)' /etc/audit/rules.d/*.rules
auditctl -l | grep -E '(session|logins)'

echo -e '\n[4.1.9 Ensure discretionary access control permission modification events are collected](L2)'
grep perm_mod /etc/audit/rules.d/*.rules
auditctl -l | grep perm_mod

echo -e '\n[4.1.10 Ensure unsuccessful unauthorized file access attempts are collected](L2)'
grep access /etc/audit/rules.d/*.rules
auditctl -l | grep access

echo -e '\n[4.1.11 Ensure use of privileged commands is collected ](L2)'
find / -xdev \( -perm -4000 -o -perm -2000 \) -type f | awk '{print "-a always,exit -F path=" $1 " -F perm=x -F auid>='"$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)"' -F auid!=4294967295 -k privileged" }'

echo -e '\n[4.1.12 Ensure successful file system mounts are collected](L2)'
grep mounts /etc/audit/rules.d/*.rules
auditctl -l | grep mounts

echo -e '\n[4.1.13 Ensure file deletion events by users are collected](L2)'
grep delete /etc/audit/rules.d/*.rules
auditctl -l | grep delete

echo -e '\n[4.1.14 Ensure changes to system administration scope (sudoers) is collected](L2)'
grep scope /etc/audit/rules.d/*.rules
auditctl -l | grep scope

echo -e '\n[4.1.15 Ensure system administrator command executions (sudo) are collected ](L2)'
grep -E "^\s*-w\s+$(grep -r logfile /etc/sudoers* | sed -e 's/.*logfile=//;s/,? .*//')\s+-p\s+wa\s+-k\s+actions" /etc/audit/rules.d/*.rules
auditctl -l | grep actions

echo -e '\n[4.1.16 Ensure kernel module loading and unloading is collected](L2)'
grep modules /etc/audit/rules.d/*.rules
auditctl -l | grep modules

echo -e '\n[4.1.17 Ensure the audit configuration is immutable](L2)'
grep "^\s*[^#]" /etc/audit/rules.d/*.rules | tail -1

echo -e '\n[4.2.1.1 Ensure rsyslog is installed]'
rpm -q rsyslog

echo -e '\n[4.2.1.2 Ensure rsyslog Service is enabled and running]'
systemctl is-enabled rsyslog
systemctl status rsyslog | grep 'active (running) '

echo -e '\n[4.2.1.3 Ensure rsyslog default file permissions configured]'
grep ^\$FileCreateMode /etc/rsyslog.conf /etc/rsyslog.d/*.conf

echo -e '\n[4.2.1.4 Ensure logging is configured]'
ls -l /var/log/

echo -e '\n[4.2.1.5 Ensure rsyslog is configured to send logs to a remote log host]'
echo -e '\n not required to check for MSF, unless server functions as syslog'
grep "^*.*[^I][^I]*@" /etc/rsyslog.conf /etc/rsyslog.d/*.conf
grep -E '^\s*([^#]+\s+)?action\(([^#]+\s+)?\btarget=\"?[^#"]+\"?\b' /etc/rsyslog.conf /etc/rsyslog.d/*.conf
grep -E '^[^#]\s*\S+\.\*\s+@' /etc/rsyslog.conf /etc/rsyslog.d/*.conf

echo -e '\n[4.2.1.6 Ensure remote rsyslog messages are only accepted on designated log hosts]'
echo -e '\n not required to check for MSF, unless server functions as syslog'
grep '$ModLoad imtcp' /etc/rsyslog.conf /etc/rsyslog.d/*.conf
grep '$InputTCPServerRun' /etc/rsyslog.conf /etc/rsyslog.d/*.conf

echo -e '\n[4.2.2.1 Ensure journald is configured to send logs to rsyslog]'
grep -E ^\s*ForwardToSyslog /etc/systemd/journald.conf

echo -e '\n[4.2.2.2 Ensure journald is configured to compress large log files]'
grep -E ^\s*Compress /etc/systemd/journald.conf

echo -e '\n[4.2.2.3 Ensure journald is configured to write logfiles to persistent disk]'
grep -E ^\s*Storage /etc/systemd/journald.conf

echo -e '\n[4.2.3 Ensure permissions on all logfiles are configured]'
find /var/log -type f -perm /g+wx,o+rwx -exec ls -l {} \;

echo -e '\n[4.2.4 Ensure logrotate is configured] - additional checks may be required'
grep -Ev "^#|^$" /etc/logrotate.conf
echo ""
echo "ls /etc/logrotate.d/* :"
ls /etc/logrotate.d/
echo ""
grep -Ev "^#|^$" /etc/logrotate.d/* | grep "rotate "

echo -e '\nIf cron and at are not installed, section 5.1 can be skipped'
echo -e '\n[5.1.1 Ensure cron daemon is enabled and running ]'
systemctl is-enabled crond
systemctl status crond | grep 'Active: active (running)'

echo -e '\n[5.1.2 Ensure permissions on /etc/crontab are configured]'
stat /etc/crontab

echo -e '\n[5.1.3 Ensure permissions on /etc/cron.hourly are configured]'
stat /etc/cron.hourly/

echo -e '\n[5.1.4 Ensure permissions on /etc/cron.daily are configured]'
stat /etc/cron.daily/

echo -e '\n[5.1.5 Ensure permissions on /etc/cron.weekly are configured]'
stat /etc/cron.weekly

echo -e '\n[5.1.6 Ensure permissions on /etc/cron.monthly are configured]'
stat /etc/cron.monthly/

echo -e '\n[5.1.7 Ensure permissions on /etc/cron.d are configured]'
stat /etc/cron.d

echo -e '\n[5.1.8 Ensure cron is restricted to authorized users]'
stat /etc/cron.deny
stat /etc/cron.allow

echo -e '\n[5.1.9 Ensure at is restricted to authorized users]'
stat /etc/at.deny
stat /etc/at.allow

echo -e '\n[5.2.1 Ensure sudo is installed]'
rpm -q sudo

echo -e '\n[5.2.2 Ensure sudo commands use pty]'
grep -Ei '^\s*Defaults\s+([^#]+(,s*|\s+))?use_pty\b' /etc/sudoers /etc/sudoers.d/*

echo -e '\n[5.2.3 Ensure sudo log file exists]'
grep -Ei '^\s*Defaults\s+([^#;]+,\s*)?logfile\s*=\s*(")?[^#;]+(")?' /etc/sudoers /etc/sudoers.d/*

echo -e '\n[5.3.1 Ensure permissions on /etc/ssh/sshd_config are configured]'
stat /etc/ssh/sshd_config

echo -e '\n[5.3.2 Ensure permissions on SSH private host key files are configured]'
find /etc/ssh -xdev -type f -name 'ssh_host_*_key' -exec stat {} \;

echo -e '\n[5.3.3 Ensure permissions on SSH public host key files are configured]'
find /etc/ssh -xdev -type f -name 'ssh_host_*_key.pub' -exec stat {} \;

echo -e '\n[5.3.4 Ensure SSH access is limited]'
sshd -T | grep -E '^\s*(allow|deny)(users|groups)\s+\S+'
grep -Pi '^\h*(allow|deny)(users|groups)\h+\H+(\h+.*)?$' /etc/ssh/sshd_config

echo -e '\n[5.3.5 Ensure SSH LogLevel is appropriate]'
sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) /etc/hosts | awk '{print $1}')" | grep loglevel
grep -i 'loglevel' /etc/ssh/sshd_config | grep -Evi '(VERBOSE|INFO)'

echo -e '\n[5.3.6 Ensure SSH X11 forwarding is disabled]'
sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) /etc/hosts | awk '{print $1}')" | grep -i x11forwarding
grep -Ei '^\s*x11forwarding\s+yes' /etc/ssh/sshd_config

echo -e '\n[5.3.7 Ensure SSH MaxAuthTries is set to 4 or less]'
sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) /etc/hosts | awk '{print $1}')" | grep maxauthtries
grep -Ei '^\s*maxauthtries\s+([5-9]|[1-9][0-9]+)' /etc/ssh/sshd_config

echo -e '\n[5.3.8 Ensure SSH IgnoreRhosts is enabled]'
sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) /etc/hosts | awk '{print $1}')" | grep ignorerhosts
grep -Ei '^\s*ignorerhosts\s+no\b' /etc/ssh/sshd_config

echo -e '\n[5.3.9 Ensure SSH HostbasedAuthentication is disabled]'
sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) /etc/hosts | awk '{print $1}')" | grep hostbasedauthentication
grep -Ei '^\s*HostbasedAuthentication\s+yes' /etc/ssh/sshd_config

echo -e '\n[5.3.10 Ensure SSH root login is disabled]'
sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) /etc/hosts | awk '{print $1}')" | grep permitrootlogin
grep -Ei '^\s*PermitRootLogin\s+yes' /etc/ssh/sshd_config

echo -e '\n[5.3.11 Ensure SSH PermitEmptyPasswords is disabled]'
sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) /etc/hosts | awk '{print $1}')" | grep permitemptypasswords
grep -Ei '^\s*PermitEmptyPasswords\s+yes' /etc/ssh/sshd_config

echo -e '\n[5.3.12 Ensure SSH PermitUserEnvironment is disabled]'
sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) /etc/hosts | awk '{print $1}')" | grep permituserenvironment
grep -Ei '^\s*PermitUserEnvironment\s+yes' /etc/ssh/sshd_config

echo -e '\n[5.3.13 Ensure only strong Ciphers are used]'
sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) /etc/hosts | awk '{print $1}')" | grep ciphers
grep -Ei '^\s*macs\s+([^#]+,)?(hmac-md5|hmac-md5-96|hmac-ripemd160|hmacsha1|hmac-sha1-96|umac-64@openssh\.com|hmac-md5-etm@openssh\.com|hmac-md5-96-etm@openssh\.com|hmac-ripemd160-etm@openssh\.com|hmac-sha1-etm@openssh\.com|hmac-sha1-96-etm@openssh\.com|umac-64-etm@openssh\.com|umac-128-etm@openssh\.com)\b' /etc/ssh/sshd_config

echo -e '\n[5.3.14 Ensure only strong MAC algorithms are used]'
sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) /etc/hosts | awk '{print $1}')" | grep -i "MACs"
grep -Ei '^\s*macs\s+([^#]+,)?(hmac-md5|hmac-md5-96|hmac-ripemd160|hmacsha1|hmac-sha1-96|umac-64@openssh\.com|hmac-md5-etm@openssh\.com|hmac-md5-96-etm@openssh\.com|hmac-ripemd160-etm@openssh\.com|hmac-sha1-etm@openssh\.com|hmac-sha1-96-etm@openssh\.com|umac-64-etm@openssh\.com|umac-128-etm@openssh\.com)\b' /etc/ssh/sshd_config

echo -e '\n[5.3.15 Ensure only strong Key Exchange algorithms are used]'
sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) /etc/hosts | awk '{print $1}')" | grep kexalgorithms
grep -Ei '^\s*kexalgorithms\s+([^#]+,)?(diffie-hellman-group1-sha1|diffiehellman-group14-sha1|diffie-hellman-group-exchange-sha1)\b' /etc/ssh/sshd_config

echo -e '\n[5.3.16 Ensure SSH Idle Timeout Interval is configured]'
sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) /etc/hosts | awk '{print $1}')" | grep clientaliveinterval
sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) /etc/hosts | awk '{print $1}')" | grep clientalivecountmax
grep -Ei '^\s*ClientAliveInterval\s+(0|9[0-9][1-9]|[1-9][0-9][0-9][0-9]+|1[6-9]m|[2-9][0-9]m|[1-9][0-9][0-9]+m)\b' /etc/ssh/sshd_config
grep -Ei '^\s*ClientAliveCountMax\s+([1-9]|[1-9][0-9]+)\b' /etc/ssh/sshd_config

echo -e '\n[5.3.17 Ensure SSH LoginGraceTime is set to one minute or less]'
sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) /etc/hosts | awk '{print $1}')" | grep logingracetime
grep -Ei '^\s*LoginGraceTime\s+(0|6[1-9]|[7-9][0-9]|[1-9][0-9][0-9]+|[^1]m)' /etc/ssh/sshd_config

echo -e '\n[5.3.18 Ensure SSH warning banner is configured]'
sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) /etc/hosts | awk '{print $1}')" | grep banner

echo -e '\n[5.3.19 Ensure SSH PAM is enabled]'
sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) /etc/hosts | awk '{print $1}')" | grep -i usepam
grep -Ei '^\s*UsePAM\s+no' /etc/ssh/sshd_config

echo -e '\n[5.3.20 Ensure SSH AllowTcpForwarding is disabled](L2)'
sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) /etc/hosts | awk '{print $1}')" | grep -i allowtcpforwarding
grep -Ei '^\s*UsePAM\s+no' /etc/ssh/sshd_config

echo -e '\n[5.3.21 Ensure SSH MaxStartups is configured]'
sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) /etc/hosts | awk '{print $1}')" | grep -i maxstartups
grep -Ei '^\s*maxstartups\s+(((1[1-9]|[1-9][0-9][0-9]+):([0-9]+):([0-9]+))|(([0-9]+):(3[1-9]|[4-9][0-9]|[1-9][0-9][0-9]+):([0-9]+))|(([0-9]+):([0-9]+):(6[1-9]|[7-9][0-9]|[1-9][0-9][0-9]+)))' /etc/ssh/sshd_config

echo -e '\n[5.3.22 Ensure SSH MaxSessions is limited]'
sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) /etc/hosts | awk '{print $1}')" | grep -i maxsessions
grep -Ei '^\s*MaxSessions\s+(1[1-9]|[2-9][0-9]|[1-9][0-9][0-9]+)' /etc/ssh/sshd_config

echo -e '\n[5.4.1 Ensure password creation requirements are configured]'
grep '^\s*minlen\s*' /etc/security/pwquality.conf
grep '^\s*minclass\s*' /etc/security/pwquality.conf
grep -E '^\s*[duol]credit\s*' /etc/security/pwquality.conf
grep -P '^\s*password\s+(?:requisite|required)\s+pam_pwquality\.so\s+(?:\S+\s+)*(?!\2)(retry=[1-3]|try_first_pass)\s+(?:\S+\s+)*(?!\1)(retry=[1-3]|try_first_pass)\s*(?:\s+\S+\s*)*(?:\s+#.*)?$' /etc/pam.d/password-auth
grep -P '^\s*password\s+(?:requisite|required)\s+pam_pwquality\.so\s+(?:\S+\s+)*(?!\2)(retry=[1-3]|try_first_pass)\s+(?:\S+\s+)*(?!\1)(retry=[1-3]|try_first_pass)\s*(?:\s+\S+\s*)*(?:\s+#.*)?$' /etc/pam.d/system-auth

echo -e '\n[5.4.2 Ensure lockout for failed password attempts is configured]'
grep -E '^\s*auth\s+\S+\s+pam_(faillock|unix)\.so' /etc/pam.d/system-auth /etc/pam.d/password-auth
grep -E '^\s*account\s+required\s+pam_faillock.so\s*' /etc/pam.d/systemauth /etc/pam.d/password-auth
grep -E '^\s*auth\s+\S+\s+pam_(tally2|unix)\.so' /etc/pam.d/system-auth /etc/pam.d/password-auth
grep -E '^\s*account\s+required\s+pam_tally2.so\s*' /etc/pam.d/system-auth /etc/pam.d/password-auth

echo -e '\n[5.4.3 Ensure password hashing algorithm is SHA-512]'
grep -P '^\h*password\h+(sufficient|requisite|required)\h+pam_unix\.so\h+([^#\n\r]+)?sha512(\h+.*)?$' /etc/pam.d/system-auth /etc/pam.d/password-auth

echo -e '\n[5.4.4 Ensure password reuse is limited]'
grep -P '^\s*password\s+(requisite|required)\s+pam_pwhistory\.so\s+([^#]+\s+)*remember=([5-9]|[1-9][0-9]+)\b' /etc/pam.d/system-auth /etc/pam.d/password-auth

echo -e '\n[5.5.1.1 Ensure password expiration is 365 days or less]'
grep ^\s*PASS_MAX_DAYS /etc/login.defs
grep -E '^[^:]+:[^!*]' /etc/shadow | cut -d: -f1,5

echo -e '\n[5.5.1.2 Ensure minimum days between password changes is configured]'
grep ^\s*PASS_MIN_DAYS /etc/login.defs
grep -E ^[^:]+:[^\!*] /etc/shadow | cut -d: -f1,4

echo -e '\n[5.5.1.3 Ensure password expiration warning days is 7 or more]'
grep ^\s*PASS_WARN_AGE /etc/login.defs
grep -E ^[^:]+:[^\!*] /etc/shadow | cut -d: -f1,6

echo -e '\n[5.5.1.4 Ensure inactive password lock is 30 days or less]'
echo -e '\n not required to check for MSF, Govtech recommned to perform monthly acct review'
useradd -D | grep INACTIVE
grep -E ^[^:]+:[^\!*] /etc/shadow | cut -d: -f1,7

echo -e '\n[5.5.1.5 Ensure all users last password change date is in the past]'
for usr in $(cut -d: -f1 /etc/shadow); do [[ $(chage --list $usr | grep '^Last password change' | cut -d: -f2) > $(date) ]] && echo "$usr :$(chage --list $usr | grep '^Last password change' | cut -d: -f2)"; done

echo -e '\n[5.5.2 Ensure system accounts are secured]'
awk -F: '($1!="root" && $1!="sync" && $1!="shutdown" && $1!="halt" && $1!~/^\+/ && $3<'"$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)"' && $7!="'"$(which nologin)"'" && $7!="/bin/false") {print}' /etc/passwd
awk -F: '($1!="root" && $1!~/^\+/ && $3<'"$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)"') {print $1}' /etc/passwd | xargs -I '{}' passwd -S '{}' | awk '($2!="L" && $2!="LK") {print $1}'

echo -e '\n[5.5.3 Ensure default group for the root account is GID 0]'
grep "^root:" /etc/passwd | cut -f4 -d:

echo -e '\n[5.5.4 Ensure default user shell timeout is configured]'
for f in /etc/bashrc /etc/profile /etc/profile.d/*.sh ; do grep -Eq '(^|^[^#]*;)\s*(readonly|export(\s+[^$#;]+\s*)*)?\s*TMOUT=(900|[1-8][0-9][0-9]|[1-9][0-9]|[1-9])\b' $f && grep -Eq '(^|^[^#]*;)\s*readonly\s+TMOUT\b' $f && grep -Eq '(^|^[^#]*;)\s*export\s+([^$#;]+\s+)*TMOUT\b' $f && echo "TMOUT correctly configured in file: $f"; done
grep -P '^\s*([^$#;]+\s+)*TMOUT=(9[0-9][1-9]|0+|[1-9]\d{3,})\b\s*(\S+\s*)*(\s+#.*)?$' /etc/profile /etc/profile.d/*.sh /etc/bashrc

echo -e '\n[5.5.5 Ensure default user umask is configured]'
passing=""
grep -Eiq '^\s*UMASK\s+(0[0-7][2-7]7|[0-7][2-7]7)\b' /etc/login.defs && grep -Eqi '^\s*USERGROUPS_ENAB\s*"?no"?\b' /etc/login.defs && grep -Eq '^\s*session\s+(optional|requisite|required)\s+pam_umask\.so\b' /etc/pam.d/common-session && passing=true
grep -REiq '^\s*UMASK\s+\s*(0[0-7][2-7]7|[0-7][2-7]7|u=(r?|w?|x?)(r?|w?|x?)(r?|w?|x?),g=(r?x?|x?r?),o=)\b' /etc/profile* /etc/bashrc* && passing=true
[ "$passing" = true ] && echo "Default user umask is set"
grep -RPi '(^|^[^#]*)\s*umask\s+([0-7][0-7][01][0-7]\b|[0-7][0-7][0-7][0-6]\b|[0-7][01][0-7]\b|[0-7][0-7][0-6]\b|(u=[rwx]{0,3},)?(g=[rwx]{0,3},)?o=[rwx]+\b|(u=[rwx]{1,3},)?g=[^rx]{1,3}(,o=[rwx]{0,3})?\b)' /etc/login.defs /etc/profile* /etc/bashrc*

echo -e '\n[5.6 Ensure root login is restricted to system console]'
echo -e '\n not required to check for MSF, root will be logout if no physical console (i.e. VM, cloud)'
cat /etc/securetty

echo -e '\n[5.7 Ensure access to the su command is restricted]'
grep -E '^\s*auth\s+required\s+pam_wheel\.so\s+(\S+\s+)*use_uid\s+(\S+\s+)*group=\S+\s*(\S+\s*)*(\s+#.*)?$' /etc/pam.d/su
cat /etc/group

echo -e '\n[6.1.1 Audit system file permissions](L2)'
echo -e '\n not required to check for MSF, impossible to verify all installed packages'
rpm -Va --nomtime --nosize --nomd5 --nolinkto | grep -vw c

echo -e '\n[6.1.2 Ensure permissions on /etc/passwd are configured]'
stat /etc/passwd

echo -e '\n[6.1.3 Ensure permissions on /etc/passwd- are configured]'
stat /etc/passwd-

echo -e '\n[6.1.4 Ensure permissions on /etc/shadow are configured]'
stat /etc/shadow

echo -e '\n[6.1.5 Ensure permissions on /etc/shadow- are configured]'
stat /etc/shadow-

echo -e '\n[6.1.6 Ensure permissions on /etc/gshadow- are configured]'
stat /etc/gshadow-

echo -e '\n[6.1.7 Ensure permissions on /etc/gshadow are configured]'
stat /etc/gshadow

echo -e '\n[6.1.8 Ensure permissions on /etc/group are configured]'
stat /etc/group

echo -e '\n[6.1.9 Ensure permissions on /etc/group- are configured]'
stat /etc/group-

echo -e '\n[6.1.10 Ensure no world writable files exist]'
df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type f -perm -0002
 
echo -e '\n[6.1.11 Ensure no unowned files or directories exist]'
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nouser

echo -e '\n[6.1.12 Ensure no ungrouped files or directories exist]'
df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -nogroup

echo -e '\n[6.1.13 Audit SUID executables]'
df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type f -perm -4000

echo -e '\n[6.1.14 Audit SGID executables]'
df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type f -perm -2000

echo -e '\n[6.2.1 Ensure accounts in /etc/passwd use shadowed passwords]'
awk -F: '($2 != "x" ) { print $1 " is not set to shadowed passwords "}' /etc/passwd

echo -e '\n[6.2.2 Ensure /etc/shadow password fields are not empty]'
awk -F: '($2 == "" ) { print $1 " does not have a password "}' /etc/shadow

echo -e '\n[6.2.3 Ensure all groups in /etc/passwd exist in /etc/group]'
for i in $(cut -s -d: -f4 /etc/passwd | sort -u ); do
	grep -q -P "^.*?:[^:]*:$i:" /etc/group
	if [ $? -ne 0 ]; then
		echo "Group $i is referenced by /etc/passwd but does not exist in /etc/group"
	fi
done

echo -e '\n[6.2.4 Ensure shadow group is empty]'
awk -F: '($1=="shadow") {print $NF}' /etc/group
awk -F: -v GID="$(awk -F: '($1=="shadow") {print $3}' /etc/group)" '($4==GID) {print $1}' /etc/passwd

echo -e '\n[6.2.5 Ensure no duplicate user names exist]'
cut -d: -f1 /etc/passwd | sort | uniq -d | while read x ; do 
	echo "Duplicate login name ${x} in /etc/passwd"
done

echo -e '\n[6.2.6 Ensure no duplicate group names exist]'
cut -d: -f1 /etc/group | sort | uniq -d | while read -r x ; do 
	echo "Duplicate group name ${x} in /etc/group"
done

echo -e '\n[6.2.7 Ensure no duplicate UIDs exist]'
cut -f3 -d":" /etc/passwd | sort -n | uniq -c | while read -r x ; do
	[ -z "$x" ] && break
	set - $x
	if [ "$1" -gt 1 ]; then
		users=$(awk -F: '($3 == n) { print $1 }' n="$2" /etc/passwd | xargs)
		echo "Duplicate UID ($2): $users"
	fi
done

echo -e '\n[6.2.8 Ensure no duplicate GIDs exist]'
cut -d: -f3 /etc/group | sort | uniq -d | while read -r x ; do
	echo "Duplicate GID ($x) in /etc/group"
done

echo -e '\n[6.2.9 Ensure root is the only UID 0 account]'
awk -F: '($3 == 0) { print $1 }' /etc/passwd

echo -e '\n[6.2.10 Ensure root PATH Integrity]'
RPCV="$(sudo -Hiu root env | grep '^PATH' | cut -d= -f2)"
echo "$RPCV" | grep -q "::" && echo "root's path contains a empty directory (::)"
echo "$RPCV" | grep -q ":$" && echo "root's path contains a trailing (:)"
for x in $(echo "$RPCV" | tr ":" " "); do
	if [ -d "$x" ]; then
		ls -ldH "$x" | awk '$9 == "." {print "PATH contains current working directory (.)"}
		$3 != "root" {print $9, "is not owned by root"}
		substr($1,6,1) != "-" {print $9, "is group writable"}
		substr($1,9,1) != "-" {print $9, "is world writable"}'
	else
		echo "$x is not a directory"
	fi
done

echo -e '\n[6.2.11 Ensure all users home directories exist]'
awk -F: '($1!~/(halt|sync|shutdown|nfsnobody)/ && $7!~/^(\/usr)?\/sbin\/nologin(\/)?$/ && $7!~/(\/usr)?\/bin\/false(\/)?$/) {print $1 " " $6 }' /etc/passwd | while read -r user dir; do
	if [ ! -d "$dir" ]; then
		echo "User: \"$user\" home directory: \"$dir\" does not exist."
	fi
done

echo -e '\n[6.2.12 Ensure users own their home directories]'
awk -F: '($1!~/(halt|sync|shutdown|nfsnobody)/ && $7!~/^(\/usr)?\/sbin\/nologin(\/)?$/ && $7!~/(\/usr)?\/bin\/false(\/)?$/) { print $1 " " $6 }' /etc/passwd | while read -r user dir; do
   if [ ! -d "$dir" ]; then
      echo "User: \"$user\" home directory: \"$dir\" does not exist."
   else
      owner=$(stat -L -c "%U" "$dir")
      if [ "$owner" != "$user" ]; then
         echo "User: \"$user\" home directory: \"$dir\" is owned by \"$owner\""
      fi
   fi
done

echo -e '\n[6.2.13 Ensure users home directories permissions are 750 or more restrictive]'
awk -F: '($1!~/(halt|sync|shutdown)/ && $7!~/^(\/usr)?\/sbin\/nologin(\/)?$/ && $7!~/(\/usr)?\/bin\/false(\/)?$/) {print $1 " " $6}' /etc/passwd | while read -r user dir; do
	if [ ! -d "$dir" ]; then
		echo "User: \"$user\" home directory: \"$dir\" doesn't exist"
	else
		dirperm=$(stat -L -c "%A" "$dir")
		if [ "$(echo "$dirperm" | cut -c6)" != "-" ] || [ "$(echo "$dirperm" | cut -c8)" != "-" ] || [ "$(echo "$dirperm" | cut -c9)" != "-" ] || [ "$(echo "$dirperm" | cut -c10)" != "-" ]; then
			echo "User: \"$user\" home directory: \"$dir\" has permissions: \"$(stat -L -c "%a" "$dir")\""
		fi
	fi
done

echo -e '\n[6.2.14 Ensure users dot files are not group or world writable]'
awk -F: '($1!~/(halt|sync|shutdown)/ && $7!~/^(\/usr)?\/sbin\/nologin(\/)?$/ && $7!~/(\/usr)?\/bin\/false(\/)?$/) { print $1 " " $6 }' /etc/passwd | while read -r user dir; do
	if [ -d "$dir" ]; then
		for file in "$dir"/.*; do
			if [ ! -h "$file" ] && [ -f "$file" ]; then
				fileperm=$(stat -L -c "%A" "$file")
				if [ "$(echo "$fileperm" | cut -c6)" != "-" ] || [ "$(echo "$fileperm" | cut -c9)" != "-" ]; then
					echo "User: \"$user\" file: \"$file\" has permissions: \"$fileperm\""
				fi
			fi
		done
	fi
done

echo -e '\n[6.2.15 Ensure no users have .forward files]'
awk -F: '($1!~/(root|halt|sync|shutdown)/ && $7!~/^(\/usr)?\/sbin\/nologin(\/)?$/ && $7!~/(\/usr)?\/bin\/false(\/)?$/) {print $1 " " $6 }' /etc/passwd | while read -r user dir; do
	if [ -d "$dir" ]; then
		file="$dir/.forward"
		if [ ! -h "$file" ] && [ -f "$file" ]; then
			echo "User: \"$user\" file: \"$file\" exists"
		fi
	fi
done

echo -e '\n[6.2.16 Ensure no users have .netrc files]'
awk -F: '($1!~/(halt|sync|shutdown|nfsnobody)/ && $7!~/^(\/usr)?\/sbin\/nologin(\/)?$/ && $7!~/(\/usr)?\/bin\/false(\/)?$/) { print $1 " " $6 }' /etc/passwd | while read -r user dir; do
	if [ -d "$dir" ]; then
		file="$dir/.netrc"
		if [ ! -h "$file" ] && [ -f "$file" ]; then
			if stat -L -c "%A" "$file" | cut -c4-10 | grep -Eq '[^-]+'; then
				echo "FAILED: User: \"$user\" file: \"$file\" exists with permissions: \"$(stat -L -c "%a" "$file")\", remove file or excessive permissions"
			else
				echo "WARNING: User: \"$user\" file: \"$file\" exists with permissions: \"$(stat -L -c "%a" "$file")\", remove file unless required"
			fi
		fi
	fi
done

echo -e '\n[6.2.17 Ensure no users have .rhosts files]'
awk -F: '($1!~/(root|halt|sync|shutdown)/ && $7!~/^(\/usr)?\/sbin\/nologin(\/)?$/ && $7!~/(\/usr)?\/bin\/false(\/)?$/) { print $1 " " $6 }' /etc/passwd | while read -r user dir; do
	if [ -d "$dir" ]; then
		file="$dir/.rhosts"
		if [ ! -h "$file" ] && [ -f "$file" ]; then
			echo "User: \"$user\" file: \"$file\" exists"
		fi
	fi
done


#Additional items to check
echo -e '\n[===Additional Items===]'
echo -e '\n[1.1.1.2 Ensure mounting of freevxfs filesystems is disabled]'
modprobe -n -v freevxfs
lsmod | grep freevxfs

echo -e '\n[1.1.1.3 Ensure mounting of jffs2 filesystems is disabled]'
modprobe -n -v jffs2
lsmod | grep jffs2

echo -e '\n[1.1.1.4 Ensure mounting of hfs filesystems is disabled]'
modprobe -n -v hfs
lsmod | grep hfs

echo -e '\n[1.1.1.5 Ensure mounting of hfsplus filesystems is disabled]'
modprobe -n -v hfsplus
lsmod | grep hfsplus

echo -e '\n[1.1.1.8 Ensure mounting of vfat filesystems is disabled - N/A for UEFI Systems] (L2)'
modprobe -n -v vfat
lsmod | grep vfat

echo -e '\n[1.1.6-17 Filesystem Configuration]'
df -h
grep -i /var/tmp /etc/fstab
grep -i /var/log /etc/fstab
grep -i /var/log/audit /etc/fstab
grep -i /home /etc/fstab
grep -i /dev/shm /etc/fstab

echo -e '\n[2.1.1 Ensure chargen services are not enabled]'
echo -ne "chargen-dgram=";systemctl is-enabled chargen-dgram
echo -ne "chargen-stream=";systemctl is-enabled chargen-stream

echo -e '\n[2.1.2 Ensure daytime services are not enabled]'
echo -ne "daytime-dgram=";systemctl is-enabled daytime-dgram
echo -ne "daytime-stream=";systemctl is-enabled daytime-stream

echo -e '\n[2.1.3 Ensure discard services are not enabled]'
echo -ne "discard-dgram=";systemctl is-enabled discard-dgram
echo -ne "discard-stream=";systemctl is-enabled discard-stream

echo -e '\n[2.1.4 Ensure echo services are not enabled]'
echo -ne "echo-dgram=";systemctl is-enabled echo-dgram
echo -ne "echo-stream=";systemctl is-enabled echo-stream

echo -e '\n[2.1.5 Ensure time services are not enabled]'
echo -ne "time-dgram=";systemctl is-enabled time-dgram
echo -ne "time-stream=";systemctl is-enabled time-stream

echo -e '\n[2.1.6 Ensure tftp server is not enabled]'
systemctl is-enabled tftp

echo -e '\n[2.1.7 Ensure xinetd server is not enabled]'
systemctl is-enabled xinetd

echo -e '\n[1.6.1.1 Ensure SELinux is not disabled in bootloader configuration]'
grep "^\s*selinux" /boot/grub2/grub.cfg
grep "^\s*enforcing" /boot/grub2/grub.cfg

echo -e '\n[1.6.1.6 Ensure no unconfined daemons exist] (L2)'
ps -eZ | egrep "initrc" | egrep -vw "tr|ps|egrep|bash|awk" | tr ':' ' ' | awk '{ print $NF }'

echo -e '\n[1.8 Ensure updates, patches, and additional security software are installed]'
yum check-update --security

echo -e '\n[2.1 Inetd Services]'
chkconfig --list
systemctl list-unit-files | grep -i enabled

echo -e '\n[3.3.2 Ensure IPv6 redirects are not accepted]'
sysctl net.ipv6.conf.all.accept_redirects
sysctl net.ipv6.conf.default.accept_redirects
grep "net\.ipv6\.conf\.all\.accept_redirect" /etc/sysctl.conf /etc/sysctl.d/*
grep "net\.ipv6\.conf\.default\.accept_redirect" /etc/sysctl.conf /etc/sysctl.d/*

echo -e '\n[3.3.3 Ensure IPv6 is disabled]'
grep 'ipv6.disable' /etc/default/grub
echo -ne "/sys/module/ipv6/parameters/disable=";cat /sys/module/ipv6/parameters/disable

echo -e '\n[3.4.1 Ensure TCP Wrappers is installed]'
rpm -q tcp_wrappers

echo -e '\n[3.4.2 Ensure /etc/hosts.allow is configured]'
cat /etc/hosts.allow | grep -v ^#

echo -e '\n[3.4.3 Ensure /etc/hosts.deny is configured]'
cat /etc/hosts.deny | grep -v ^#

echo -e '\n[3.4.4 Ensure permissions on /etc/hosts.allow are configured]'
stat /etc/hosts.allow

echo -e '\n[3.4.5 Ensure permissions on /etc/hosts.deny are 644]'
stat /etc/hosts.deny

echo -e '\n[3.5.1 Ensure DCCP is disabled]'
modprobe -n -v dccp
lsmod | grep dccp

echo -e '\n[3.5.2 Ensure SCTP is disabled]'
modprobe -n -v sctp
lsmod | grep sctp

echo -e '\n[3.5.3 Ensure RDS is disabled]'
modprobe -n -v rds
lsmod | grep rds

echo -e '\n[3.5.4 Ensure TIPC is disabled]'
modprobe -n -v tipc
lsmod | grep tipc

echo -e '\n[4.2.2.1 Ensure syslog-ng service is enabled]'
systemctl is-enabled syslog-ng

echo -e '\n[4.2.2.3 Ensure syslog-ng default file permissions configured]'
grep ^options /etc/syslog-ng/syslog-ng.conf

echo -e '\n[4.2.2.5 Ensure remote syslog-ng messages are only accepted on designated log hosts]'
grep ^source /etc/syslog-ng/syslog-ng.conf
grep ^destination /etc/syslog-ng/syslog-ng.conf
grep ^log /etc/syslog-ng/syslog-ng.conf

echo -e '\n[5.2.2 Ensure SSH Protocol is set to 2]'
grep "^Protocol" /etc/ssh/sshd_config

echo -e '\n[6.2.2 Ensure no legacy "+" entries exist in /etc/passwd]'
grep '^\+:' /etc/passwd

echo -e '\n[6.2.3 Ensure no legacy "+" entries exist in /etc/shadow]'
grep '^\+:' /etc/shadow

echo -e '\n[6.2.4 Ensure no legacy "+" entries exist in /etc/group]'
grep '^\+:' /etc/group

echo -e '\n[6.2.13 Ensure users .netrc Files are not group or world accessible]'
cat /etc/passwd | egrep -v '^(root|halt|sync|shutdown)' | awk -F: '($7 != "/sbin/nologin" && $7 != "/bin/false") { print $1 " " $6 }' | while read user dir; do
  if [ ! -d "$dir" ]; then
    echo "The home directory ($dir) of user $user does not exist."
  else
    for file in $dir/.netrc; do
      if [ ! -h "$file" -a -f "$file" ]; then
        fileperm=`ls -ld $file | cut -f1 -d" "`
        if [ `echo $fileperm | cut -c5`  != "-" ]; then
          echo "Group Read set on $file"
        fi
        if [ `echo $fileperm | cut -c6`  != "-" ]; then
          echo "Group Write set on $file"
        fi
        if [ `echo $fileperm | cut -c7`  != "-" ]; then
          echo "Group Execute set on $file"
        fi
        if [ `echo $fileperm | cut -c8`  != "-" ]; then
          echo "Other Read set on $file"
        fi
        if [ `echo $fileperm | cut -c9`  != "-" ]; then
          echo "Other Write set on $file"
        fi
        if [ `echo $fileperm | cut -c10`  != "-" ]; then
          echo "Other Execute set on $file"
        fi
      fi
    done
  fi
done

echo -e '\n[6.2.15 Ensure all groups in /etc/passwd exist in /etc/group]'
for i in $(cut -s -d: -f4 /etc/passwd | sort -u ); do
  grep -q -P "^.*?:[^:]*:$i:" /etc/group
  if [ $? -ne 0 ]; then
    echo "Group $i is referenced by /etc/passwd but does not exist in /etc/group"
  fi
done

echo -e '\n[5.2.14 Ensure SSH access is limited]'
grep "^AllowUsers" /etc/ssh/sshd_config
grep "^AllowGroups" /etc/ssh/sshd_config
grep "^DenyUsers" /etc/ssh/sshd_config
grep "^DenyGroups" /etc/ssh/sshd_config

echo -e '\n[5.4.4 Ensure default user umask is 027 or more restrictive]'
echo -e '\n not required to check for MSF, might break the system'
grep "umask" /etc/bashrc
grep "umask" /etc/profile /etc/profile.d/*.sh

echo -e '\n[5.4.5 Ensure default user shell timeout is 900 seconds or less] (L2)'
grep "^TMOUT" /etc/bashrc
grep "^TMOUT" /etc/profile


#Additional Items for RHEL8
echo -e '\n[===Additional Items for RHEL8===]'

echo -e '\n[1.1 Ensure system-wide crypto policy is not legacy]'
grep -E -i '^\s*LEGACY\s*(\s+#.*)?$' /etc/crypto-policies/config

echo -e '\n[1.11 Ensure system-wide crypto policy is FUTURE or FIPS] (L2)'
grep -E -i '^\s*(FUTURE|FIPS)\s*(\s+#.*)?$' /etc/crypto-policies/config

echo -e '\n[5.2.20 Ensure system-wide crypto policy is not over-ridden]'
grep -i '^\s*CRYPTO_POLICY=' /etc/sysconfig/sshd

echo -e '\n[5.3.1 Create custom authselect profile] and'
echo -e '\n[5.3.2 Select authselect profile]'
authselect current

echo -e '\n[5.3.3 Ensure authselect includes with-faillock]'
grep pam_faillock.so /etc/authselect/password-auth /etc/authselect/system-auth

echo "===COMPLETED===="