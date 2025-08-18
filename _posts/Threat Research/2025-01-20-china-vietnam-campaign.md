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

When we opened the [.bash_history](https://github.com/ctrlaltint3l/intelligence/blob/main/VietnameseCampaign/Artefacts/.bash_history) file on this host, we knew we were in for fun:

[![1](/assets/images/china/bash_history.png)](/assets/images/china/bash_history.png){: .full}


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

The 62 registered beacons that followed this were all beaconing from various Cloudflare AS 13335 IP addresses. Why is this happening? We can look at the file `/CS/server/CatServer.Properties`