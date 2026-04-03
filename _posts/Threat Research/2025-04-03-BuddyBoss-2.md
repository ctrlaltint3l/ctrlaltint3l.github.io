---
title: "The BuddyBoss Attack: Full Incident Analysis"
classes: wide
header:
  teaser: /assets/images/wordpress/logo2.png
ribbon: black
description: "Reconstructing the complete kill-chain of the BuddyBoss Attack"
categories:
  - Threat Research
tags:
  - Threat Research
toc: true
---

# Overview

In [Part 1](https://ctrlaltintel.com/research/BuddyBoss-1) of this research, we analysed a recovered Claude Code session log that captured a French-speaking threat actor directing Claude through the final stage of a supply chain attack: bypassing Cloudflare, uploading backdoored BuddyBoss plugins to the production licensing server, and exploiting victim WordPress sites in real time.

That blog focused on **how Claude made the supply chain injection possible**. This blog focuses on **everything else**: how the threat actor (assisted by Claude) obtained initial access, weaponised GitHub Actions to steal CI/CD secrets, laterally moved through BuddyBoss's infrastructure, escalated to root on an AWS server, and ultimately pushed backdoored updates to hundreds of customer sites.

All findings in this analysis are derived from the threat actor's own C2 server, which was left as an open directory. We recovered exfiltration logs, decoded payloads, the Claude Code session transcript, PHP backdoor templates, C2 server components, and the full loot directory containing data from 246+ victim WordPress sites.

> There are gaps in our visibility. The C2 logs capture everything **after** the threat actor had already credential access to the BuddyBoss GitHub organisation. How that initial access was obtained is not completely visible to us. Although we have suspicions that we will highlight later. 

**Kill Chain Summary - 17th March**

| Phase | Timeframe (UTC) | Activity |
|-------|-----------------|----------|
| **Initial Access** | Unknown (pre-16:20) | GitHub organisation access obtained via unknown method. Malicious workflow committed to `master` under the identity of a legitimate BuddyBoss developer |
| **CI/CD Exfiltration** | 16:24 - 16:28 | GitHub Actions workflows fire, exfiltrating SSH keys, database credentials, and the Caseproof Mothership API key to the C2 server |
| **Lateral Movement (Hetzner)** | 16:36 - 17:01 | Stolen SSH key used to access BuddyBoss's Hetzner deployment server within 10 minutes |
| **Lateral Movement (AWS)** | 17:26 - 17:38 | SSH credentials stolen from CI/CD used to access AWS server. |
| **Additional Credential Theft** | 17:46 - 18:21 | Production `.env` files exfiltrated. GitHub org-level PAT, FTP credentials, and automation tokens stolen |
| **Supply Chain Injection** | 18:54 - 19:16 | Using the stolen `appcenter_key`, backdoored BuddyBoss Platform v2.20.3 and Theme v2.19.2 deployed to the production Mothership CDN via Cloudflare bypass |
| **Victim Exploitation** | 19:18 onwards | 246+ WordPress sites call back. Automated scanning, credential harvesting, and Stripe API key theft |

**Total time from first CI/CD exfiltration to first victim callback: 2 hours 54 minutes.**

Although the Claude Code session transcript was not complete, and we only observed the latter end of the attack (from **Supply Chain Injection**), based on speed, standardised scripts & C2 telemetry, we likely believe Claude Code was also responsible for the the CI/CD exfiltration, lateral movement and credential theft. 

> The threat actor had a server-side C2 listener that captured all victim telemetry, allowing us to ascertain the near complete kill-chain

[![1](/assets/images/buddyboss/10.png){: .align-center .img-border}](/assets/images/buddyboss/10.png)
<p class="figure-caption">CI/CD secret exfiltration</p>

# CI/CD Pipeline Compromise

## The Malicious Workflow

The threat actor pushed a malicious GitHub Actions workflow file (`platform-compat.yml`) to the `master` branch of at least two private BuddyBoss repositories: `buddyboss/buddyboss-platform-pro` and `buddyboss/csr-tool`. A third repository, `buddyboss/api-build`, is also implicated based on endpoint naming.

We know this because the C2 server logged the inbound exfiltration callbacks. Each callback contained GitHub Actions runner environment variables that can only exist inside a running workflow. The `ghs_` prefixed tokens (GitHub Actions installation tokens) are generated exclusively by GitHub's runner infrastructure and cannot be manually created.

The workflow was named **"Platform Compatibility Check"**, a deliberately innocuous name designed to blend in with legitimate CI/CD activity.

[![1](/assets/images/buddyboss/8.png){: .align-center .img-border}](/assets/images/buddyboss/8.png)
<p class="figure-caption">CI/CD secret exfiltration</p>

**What Was Exfiltrated**

Three repositories called back to distinct C2 endpoints within 3 minutes of each other:

| Time (UTC) | Source IP | C2 Endpoint | Repository | Key Data Stolen |
|------------|-----------|-------------|------------|-----------------|
| 16:24:35 | 20.168.118.82 | `/gh_secrets` | `buddyboss-platform-pro` | GitHub token, Claude Code OAuth token, full runner environment |
| 16:26:46 | 145.132.102.248 | `/csr_secrets` | `buddyboss/csr-tool` | Ed25519 SSH private key, SSH credentials for Hetzner server, GitHub token |
| 16:27:02 | 13.83.166.228 | `/api_secrets` | Unknown | `appcenter_key`, database credentials, Redis credentials, SSH key |

Each repository had a **different C2 endpoint** and exfiltrated **different secrets**. 

The `User-Agent: curl/8.5.0` header on all three callbacks is consistent with Ubuntu 24 (the default GitHub-hosted runner image), confirming these ran on GitHub's own infrastructure rather than self-hosted runners.

## The Push Identity

The exfiltrated environment variables from the `buddyboss-platform-pro` callback reveal who triggered the workflow:

| Variable | Value |
|----------|-------|
| `GITHUB_EVENT_NAME` | `push` |
| `GITHUB_RUN_NUMBER` | `1` |
| `GITHUB_TRIGGERING_ACTOR` | `KartikSuthar` |
| `GITHUB_REF` | `refs/heads/master` |
| `GITHUB_REF_PROTECTED` | `true` |
| `GITHUB_SHA` | `45efbfa2f4f0b196b19bcfc7c46ad5f5a330010b` |

A few things stand out. `GITHUB_RUN_NUMBER=1` means this was the **first time this workflow ever ran**. It was newly created, not a modification of an existing workflow. The push went directly to `master`, a protected branch, and was attributed to **KartikSuthar**, a real BuddyBoss developer who had published release v2.14.0 in October 2025, implementing the exact Caseproof licensing system that the threat actor would later exploit...

We do not believe KartikSuthar was the threat actor. The attacker spoke French. However, the push was attributed to KartikSuthar's identity. How that identity was compromised is discussed in the [Unanswered Questions](#unanswered-questions) section below.

## Why This Was Hard to Detect

The malicious workflow was designed to avoid raising alarms:

- **Innocuous naming**: "Platform Compatibility Check" blends with legitimate CI/CD workflows
- **GitHub masks secrets**: Any value stored as a GitHub secret is automatically masked with `***` in workflow run logs. Even if someone reviewed the logs, the `curl` commands would show redacted values
- **Direct push to master**: The `GITHUB_EVENT_NAME=push` confirms this was not a pull request -> maybe no code review
- **Immediate execution**: The workflow ran on the push event itself, exfiltrating secrets before anyone could review the commit

# Lateral Movement

## Hetzner Server (95.217.100.226)

Within **10 minutes** of stealing the SSH key from CI/CD, the threat actor (likely performed by Claude) was logged into BuddyBoss's Hetzner deployment server.

At 16:36:01 UTC, six IP addresses simultaneously posted environment dumps to the C2's `/build_env` endpoint. All decoded bodies contained identical SSH session metadata:

```
SSH_CONNECTION=195.178.110.242 42900 95.217.100.226 2525
USER=bbapp-cert-services-bb
HOME=/home/bbapp-cert-services-bb
```

This proves the C2 server at `195.178.110.242` established an SSH connection to the Hetzner server at `95.217.100.226` on port `2525`, authenticating as `bbapp-cert-services-bb` using the Ed25519 private key stolen from the `csr-tool` repository secrets just minutes earlier.

The Hetzner server resolves to several BuddyBoss-related domains:

- `appcenter.hz5.developbb.dev`
- `bbapp-cert-services.hz5.developbb.dev`
- `api-build.buddyboss.com`
- `crm.hz5.developbb.dev`

The threat actor ran reconnaissance commands (`whoami`, `id`, `env`).

Between 17:18 and 17:20 UTC, we observed two waves of `wpconfig_*` probes: six sequential POST requests with descriptive endpoint names (`wpconfig_via_ssh`, `wpconfig_from_cat`, `wpconfig_base64`, `wpconfig_result`, `wpconfig_dump`, `wpconfig_raw`), all returning empty bodies. The threat actor's workflow was attempting to extract `wp-config.php` files from the Hetzner server using multiple methods. All failed. The `bbapp-cert-services-bb` user did not have read permissions to the WordPress configuration files.

**RunCloud Server**

While the `wp-config.php` extraction attempts on Hetzner failed, a separate callback from `64.236.200.112` at 17:20:25 UTC was more successful.

The `/apiuser_env` endpoint received the **full production `.env` file** from `api-build.buddyboss.com`. This contained database credentials, Redis credentials, a GitLab personal access token, a Slack webhook URL, and an `APPCENTER_AUTOMATION_API_KEY`, the same Mothership API key the threat actor would later use for the supply chain injection.

An earlier request from this IP to `/wpconfig_apiuser` had returned `uid=1004(api-build)` followed by "Permission denied" when trying to read wp-config. The RunCloud server's user isolation was working, but the application's `.env` file was readable.

**AWS Server**

At 17:26:00 UTC, a GitHub Actions runner exfiltrated SSH credentials for an AWS server: a password, a push token, the hostname `44.241.213.212`, and the username `deployment`.

Five seconds later, a 1,780-byte reconnaissance dump arrived containing a full Laravel `.env` file with database credentials, Apple App Store Connect configuration (issuer ID, key ID, team ID), and a directory listing showing `monitor.api-publish.buddyboss.com`.

The server resolves to:

- `api-publish.buddyboss.com`
- `monitor.api-publish.buddyboss.com`
- `download.api-publish.buddyboss.com`

### Root Access

At 17:38:02 UTC, **the AWS server itself** called back to the C2 with a 13,214-byte reconnaissance dump. The first line confirmed what the threat actor was after:

```
uid=0(root) gid=0(root) groups=0(root)
```

The `deployment` user had `sudo` privileges. The threat actor had root, ran comprehensive enumeration, and planted their own SSH key (`ctf-pivot`, Ed25519) in `/root/.ssh/authorized_keys` alongside four legitimate BuddyBoss keys (`app-demo`, `Aman Sangra`, `buddyboss-new-key-2022`, `Wes`).

The `ctf-pivot` key is distinct from the `github-actions-deployment` key stolen from CI/CD. The threat actor brought their own key for persistence. This is consistent with the SSH pivot chain we observed in `oldconv.txt`, where Claude later used `44.241.213.212` to bypass Cloudflare protections on compromised victim sites.

## Additional Credential Theft

At 18:21:23 UTC, the final CI/CD-related callback arrived at `/bbapp_secrets`. This exfiltrated a BuddyBoss GitHub organisation-level PAT (`ghp_*` prefix), an FTP password, and an automation deployment token.

By this point, the threat actor had:

- SSH access to BuddyBoss's Hetzner deployment server
- Root access (with persistent backdoor) on BuddyBoss's AWS publishing server
- Production `.env` files containing database credentials, API keys, and third-party service tokens
- The `appcenter_key` for the Caseproof Mothership licensing API
- A GitHub organisation-level PAT for continued access
- Apple App Store Connect credentials
- A GitLab personal access token

The entire credential theft for BuddyBoss, from first CI/CD exfiltration to the last callback, took approximately **2 hours**.

# Supply Chain Injection

With the `appcenter_key` in hand, this is where our visibility into the Claude Code began at approximately 18:54 UTC. The full analysis of this session is covered in [Part 1](link-to-part-1) of this research. Below is a summary.

The `appcenter_key` authenticated to the Caseproof Mothership at `licenses.caseproof.com`, a Laravel application hosted on Heroku and fronted by Cloudflare. This is the licensing and software distribution platform that serves plugin and theme updates to all BuddyBoss customers.

The threat actor's backdoored ZIP files were prepared from clean BuddyBoss Platform v2.13.1 packages. Exactly **one file per package** was modified:

| Package | Modified File | SHA256 | Backdoored Size |
|---------|--------------|------------|-----------------|
| Platform Plugin | `bp-loader.php` | `ddda12b545a7b817883641421cf6a213f4c5100effa40cdb55018efce11bbe42` | 19,144 bytes |
| Theme | `functions.php` | `5027a0e77eca13a5cc120d3e37262c4073452569ad341cd1558051b5a91ce144` | 8,375 bytes |

Cloudflare blocked the multipart file upload. Claude independently discovered the Heroku origin IP (`18.208.60[.]216`) by probing known Heroku IP ranges with the correct `Host` header, bypassing Cloudflare entirely. The 22MB backdoored Platform ZIP was uploaded directly to the origin server and deployed as version 2.20.3. The Theme was deployed as version 2.19.2.

Both backdoored packages were verified as live on the official Caseproof CDN. Claude then triggered update notifications to `buddyboss.com` to accelerate victim discovery.

# The Backdoors

Each backdoored file contained two components prepended to the legitimate code.

## Automatic Credential Exfiltration

Hooks into the WordPress `after_setup_theme` action at priority 1. On first execution (throttled by a WordPress transient with a 1-year TTL), the backdoor collects and exfiltrates:

- Site URL
- Database credentials: `DB_HOST`, `DB_NAME`, `DB_USER`, `DB_PASSWORD`
- WordPress secret keys: `AUTH_KEY`, `SECURE_AUTH_KEY`, `NONCE_KEY`
- Server information: IP, software, document root, hostname
- All environment variables via `getenv()`
- PHP version, active plugins list, user counts

This data is base64-encoded as JSON and POSTed to the C2 at `195.178.110[.]242:8443`. The request uses `blocking => false` to avoid impacting page load times on the victim site. `195.178.110[.]242:8443` is the same endpoint that was listening for the CI/CD and other credential theft data. 

## Interactive Backdoor

| Mode | Trigger (Platform) | Capability |
|------|-------------------|------------|
| Reverse Shell | `?bp_compat_check=[auth]&mode=diag` | TCP socket to C2 on port 4444, spawns `/bin/bash` via `proc_open` |
| Command Exec | `?bp_compat_check=[auth]&mode=exec&c=<base64>` | Arbitrary command via `shell_exec()` |
| File Read | `?bp_compat_check=[auth]&mode=read&f=<base64>` | Reads arbitrary file via `file_get_contents()` |

The parameter names were chosen to blend with legitimate BuddyBoss internals (`bp_compat_check`, `bb_theme_compat`), and the code was disguised with phpDoc: *"Platform telemetry for usage analytics."*

The threat actor later deployed version 2.20.4, adding six shell execution methods for resilience (`shell_exec`, `exec`, `system`, `passthru`, `popen`, `proc_open`), a standalone webshell at `bp-compatibility.php` for direct access bypassing WAF parameter filtering, and an `eval` mode for environments where all shell functions are disabled.

# Victim Impact

## First Callbacks

The first real victim callback arrived at **19:18:06 UTC**, approximately 2 minutes after the backdoored packages went live. WordPress sites checking for updates via `wp-cron` (or when an admin visited the dashboard) saw the new versions and installed them automatically.

**Active Exploitation**

The threat actor did not wait passively. Once callbacks began arriving, they shifted to targeted exploitation via the exec endpoint:

- Database credentials were extracted from every calling-back site
- At least one site had live Stripe payment processing keys exfiltrated
- Automated scanning (`AUTO_SCAN_RESULTS.log`) ran against approximately 30 high-value targets
- Two full `wp-config.php` files were extracted from victim sites

# The C2 Infrastructure

**How We Found This**

The entire evidence base comes from the threat actor's own C2 server. The receiver at `195.178.110[.]242:8443` was running a purpose-built Python HTTP server (`receiver.py`) that logged **every inbound HTTP request** with full metadata: server-side timestamps, sequential request IDs, HTTP method and path, full headers, raw and decoded request bodies, and source IP/port.

This server was left as an open directory. The structured logging, combined with the open directory, gave us near-complete visibility into the campaign from the moment the C2 came online.

Data was stored in a structured directory hierarchy:

```
loot/
├── by_ip/
│   ├── 20.168.118.82/          <- GitHub Actions runner
│   ├── 145.132.102.248/        <- GitHub Actions runner
│   ├── 44.241.213.212/         <- AWS server (root_recon)
│   └── ... (300+ IP directories) <- Wordpress victims
│
├── master.log                   <- Global chronological log
├── FLAG_CANDIDATES.txt          <- Auto-detected secrets/flags
└── AUTO_SCAN_RESULTS.log        <- Post-exploitation scan results
```

# Timeline

All times are **March 17, 2026 UTC**. Times are derived from server-side timestamps on the C2's HTTP request logs.

| Time | Event |
|------|-------|
| *Unknown* | GitHub identity compromised. Malicious workflow committed to `master` in 2+ repos. C2 server provisioned |
| 16:24:35 | **First exfiltration.** `/gh_secrets` from `buddyboss-platform-pro` |
| 16:26:46 | `/csr_secrets`: SSH key + Hetzner credentials from `csr-tool` |
| 16:27:02 | `/api_secrets`: `appcenter_key` + database credentials |
| 16:36:01 | **Hetzner accessed.** C2 SSHes to `95.217.100[.]226:2525` (10 min after key theft) |
| 17:18 - 17:20 | `wpconfig_*` probes fail on Hetzner (permissions denied) |
| 17:20:25 | **Production `.env` stolen** from `api-build.buddyboss.com` |
| 17:26:00 | AWS SSH credentials exfiltrated |
| 17:38:02 | **Root access on AWS.** `ctf-pivot` key planted for persistence |
| 18:21:23 | GitHub org-level PAT, FTP password, automation token stolen |
| ~18:54 |  Mothership API queried with `appcenter_key` |
| ~19:03 | Cloudflare bypassed. Backdoored Platform v2.20.3 uploaded to Heroku origin |
| ~19:15 | Backdoored Theme v2.19.2 uploaded |
| ~19:16 | Update notifications sent to `buddyboss.com` |
| 19:18:06 | **First victim callback** |
| 19:20+ | Active exploitation begins. Stripe keys stolen. |

**From first exfiltration to first victim: 2 hours 54 minutes.**

# Unanswered Questions

**How Was Initial GitHub Access Obtained?**

This is the biggest gap in our visibility. The loot data begins at the point where the malicious workflow has already been committed and is executing. We do not have the session where initial access was obtained.

The `GITHUB_ACTOR=KartikSuthar` field tells us the push was attributed to a legitimate BuddyBoss developer. But the threat actor is French-speaking and showed no definite indicators of being KartikSuthar. However, we did note something interesting.

* Within the open-directory, the French threat actor had named the packages `buddyboss-platform-2.13.1-backdoored.zip` and `buddyboss-theme-2.13.1-backdoored.zip`. They had backdoored Buddyboss Platform/Theme version `2.13.1` and renamed/ uploaded these to production as "newer" versions. 

* KartikSuthar's first release in Github was `2.14.0`, and this "Implemented a new licensing system for BuddyBoss plugins and theme". 

[![1](/assets/images/buddyboss/6.png){: .align-center .img-border}](/assets/images/buddyboss/6.png)
<p class="figure-caption">Claude's insight</p>

We considered several possibilities:

| Scenario | Supporting Evidence | Weaknesses |
|----------|-------------------|------------|
| **Stolen credentials** | Most common GitHub account compromise vector. Infostealers routinely harvest GitHub session cookies and PATs | No direct evidence in recovered data |
| **APK reverse engineering** | The threat actor's workstation contains a `Scan_APK/GITHUB/` directory with cloned BuddyBoss repositories. BuddyBoss has a mobile application that may embed API tokens | Speculative. |

> Ctrl-Alt-Intel **did identify** exposed secrets in BuddyBoss APKs that were found online - however these would not have given direct access to Github like we observed.   

**An Odd Visitor**

On March 18 at 11:24 UTC, someone from an Indian IP address (Reliance Jio, Mac/Chrome) manually browsed `http://195.178.110[.]242:8443/bbapp_secrets`, then tried `?ftp_password` and `?ftp_password=true`.

This is notable. The IP is Indian (consistent with BuddyBoss's development team), the browser is personal (Mac Chrome, not a CI/CD runner), and the specific endpoint tested (`/bbapp_secrets`) directly targets the stolen credentials. This looks like someone who knew what was stolen - likely a BuddyBoss developer discovering the C2 during incident response.

## Was the GitHub Repository Source Code Backdoored?

In the Claude Code session, Claude stated: *"The backdoored code is already on GitHub master."* However, our analysis of the publicly available BuddyBoss repository (cloned and checked via `git log -S` for all backdoor strings across all branches) found **no evidence of the backdoor ever being committed**. Version 2.14.0 of `bp-loader.php` is clean and shows a natural 2-byte increment over the clean 2.13.1 version.

This means either: the GitHub master was never actually compromised and Claude's statement was inaccurate, or the backdoor was committed and then cleaned up before we cloned the repository. Without access to the private `buddyboss-platform-pro` repository's full commit history, we cannot determine which scenario occurred.

**How Many Repositories Were Compromised?**

We can confirm two: `buddyboss/buddyboss-platform-pro` and `buddyboss/csr-tool`. These are the only callbacks that contained explicit `repo=` fields. 

Additional C2 endpoints (`/api_secrets`, `/ssh_deploy`, `/real_deploy`, `/bbapp_secrets`, `/appstore_ssh`) exfiltrated CI/CD secrets but did not include repository identifiers, just widened the scope of the intrusion.  

# Conclusion

This campaign is notable for several reasons. The entire attack, from CI/CD exfiltration to supply chain injection to victim exploitation, was completed in under 3 hours - likely all done by Claude. The threat actor moved methodically through BuddyBoss's infrastructure: stealing CI/CD secrets, laterally moving to deployment servers, gaining root access on AWS, and ultimately pushing backdoored plugin updates to hundreds of WordPress sites via the legitimate distribution CDN.

The `appcenter_key`, a single API key stored as a CI/CD secret, was the bridge between the GitHub compromise and the supply chain injection. Its theft at 16:27 UTC enabled everything that followed after 18:54 UTC.

The use of Claude as an interactive attack assistant, documented in Part 1 of this research, lowered the technical barrier for the supply chain injection phase significantly.

For defenders, the key takeaway is the speed. Ten minutes from SSH key theft to lateral movement. Twelve minutes from AWS access to root. Three hours from first exfiltration to first victim. CI/CD secrets, particularly those that grant access to software distribution infrastructure, represent a direct path from code repository compromise to supply chain attack.

The speed here, we believe, is due to Claude performing the malice quickly and efficiently. We also used Claude to assist our analysis and whilst writing this blog. This is what Claude thinks of the Supply-Chain attack it caused:

[![1](/assets/images/buddyboss/5.png){: .align-center .img-border}](/assets/images/buddyboss/5.png)
<p class="figure-caption">Claude's insight</p>

If you'd like to read more about how Claude was leveraged, please read [Claude's Supply-Chain Attack](https://ctrlaltintel.com/research/BuddyBoss-1)


# IOCs

| Type | Value | Context |
|------|-------|---------|
| IPv4 | `195.178.110[.]242` | Primary C2 server (exfiltration receiver + reverse shell listener) |
| File | `bp-loader.php` | Platform plugin backdoor |
| SHA256 | `ddda12b545a7b817883641421cf6a213f4c5100effa40cdb55018efce11bbe42` | `bp-loader.php` |
| File | `functions.php` | Theme backdoor |
| SHA256 | `5027a0e77eca13a5cc120d3e37262c4073452569ad341cd1558051b5a91ce144` | `functions.php` |
| File | `buddyboss-platform-pro.php` | Standalone backdoor with upload capability |
| GET Parameter | `bb_platform_debug` | Platform backdoor trigger |
| GET Parameter | `bb_theme_compat` | Theme backdoor trigger |
| Auth Token | `a9f2c8e1` | Shared authentication key across all backdoor variants |
| File | `bp-compatibility.php` | Standalone webshell (v2.20.4) |
| Workflow Name | `Platform Compatibility Check` | Name of the malicious GitHub Actions workflow |

The malicious PHP modules have been added to our [Github](https://github.com/ctrlaltint3l/intelligence/tree/main/BuddyBoss/Backdoor).

# MITRE ATT&CK

| Tactic | ID | Technique | Observed Activity |
|--------|----|-----------|-------------------|
| **Initial Access** | [T1195.002](https://attack.mitre.org/techniques/T1195/002/) | Supply Chain Compromise: Compromise Software Supply Chain | Malicious workflow injected into BuddyBoss CI/CD; backdoored plugins deployed via Mothership CDN |
| **Initial Access** | [T1078.004](https://attack.mitre.org/techniques/T1078/004/) | Valid Accounts: Cloud Accounts | KartikSuthar's GitHub identity used to push to protected `master` branch |
| **Execution** | [T1059.004](https://attack.mitre.org/techniques/T1059/004/) | Command and Scripting Interpreter: Unix Shell | Reverse shell via `proc_open('/bin/bash')`, command exec via `shell_exec()` |
| **Persistence** | [T1098.004](https://attack.mitre.org/techniques/T1098/004/) | Account Manipulation: SSH Authorized Keys | `ctf-pivot` Ed25519 key planted in `/root/.ssh/authorized_keys` on AWS server |
| **Persistence** | [T1505.003](https://attack.mitre.org/techniques/T1505/003/) | Server Software Component: Web Shell | PHP backdoor with exec, eval, file read/write capabilities embedded in WordPress plugin/theme |
| **Privilege Escalation** | [T1548.003](https://attack.mitre.org/techniques/T1548/003/) | Abuse Elevation Control Mechanism: Sudo | Escalated from `deployment` to `root` on AWS via `sudo` |
| **Defense Evasion** | [T1036.005](https://attack.mitre.org/techniques/T1036/005/) | Masquerading: Match Legitimate Name | Workflow named "Platform Compatibility Check"; backdoor disguised as "telemetry for usage analytics" |
| **Defense Evasion** | [T1027](https://attack.mitre.org/techniques/T1027/) | Obfuscated Files or Information | Base64 encoding of exfiltrated data and command parameters |
| **Credential Access** | [T1552.001](https://attack.mitre.org/techniques/T1552/001/) | Unsecured Credentials: Credentials in Files | CI/CD secrets, `.env` files, `wp-config.php` extraction |
| **Credential Access** | [T1552.004](https://attack.mitre.org/techniques/T1552/004/) | Unsecured Credentials: Private Keys | Ed25519 SSH key stolen from `csr-tool` CI/CD secrets |
| **Credential Access** | [T1528](https://attack.mitre.org/techniques/T1528/) | Steal Application Access Token | GitHub PAT, GitLab PAT, Caseproof `appcenter_key`, Apple App Store Connect credentials |
| **Discovery** | [T1018](https://attack.mitre.org/techniques/T1018/) | Remote System Discovery | `/deep_recon` file enumeration on Hetzner; `/root_recon` on AWS |
| **Discovery** | [T1087.001](https://attack.mitre.org/techniques/T1087/001/) | Account Discovery: Local Account | `id`, `whoami`, SSH key enumeration on all compromised hosts |
| **Lateral Movement** | [T1021.004](https://attack.mitre.org/techniques/T1021/004/) | Remote Services: SSH | C2 to Hetzner (stolen key); C2 to AWS (stolen password); SSH keys from victim sites|
| **Collection** | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System | Database credentials, WordPress keys, environment variables, Laravel `.env` files |
| **Exfiltration** | [T1041](https://attack.mitre.org/techniques/T1041/) | Exfiltration Over C2 Channel | All data exfiltrated via HTTP POST to C2 at `195.178.110[.]242:8443` |
| **Exfiltration** | [T1020](https://attack.mitre.org/techniques/T1020/) | Automated Exfiltration | Non-blocking auto-exfil on first WordPress page load after plugin activation, during Github Actions |
| **Command and Control** | [T1071.001](https://attack.mitre.org/techniques/T1071/001/) | Application Layer Protocol: Web Protocols | HTTP-based C2 for exfiltration and command execution |
