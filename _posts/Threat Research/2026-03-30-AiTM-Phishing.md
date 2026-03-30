---
title: "Inside the UPMI Phishing-as-a-Service Platform"
classes: wide
header:
  teaser: /assets/images/UPMI/logo.png
ribbon: black
description: "Analysis of a fully-featured AiTM phishing platform with a collective intelligence & licensing system"
categories:
  - Threat Research
tags:
  - Threat Research
toc: true
redirect_from:
  - /threat%20research/UPMI-phishing/
  - /threat research/UPMI-phishing/
---

# Overview

Ctrl-Alt-Intel researchers identified and analysed the full source code of an AI-developed Adversary-in-the-Middle (AiTM) phishing platform branded **"UPMI ULTIMATE"**, operated by a group calling themselves **"Team Unlimited"**. The codebase was recovered from an exposed server, the central node that all licensed client instances phone home to for licensing, intelligence sharing, and remote control.

[![1](/assets/images/UPMI/8.png){: .align-center .img-border}](/assets/images/UPMI/8.png)
<p class="figure-caption">UPMI ULTIMATE panel</p>

This was developed intended to be sold with licensed deployments - indicating Phishing-as-a-Service buisness model. The platform was complete with a remote kill and a collective intelligence system where every deployed instance feeds campaign telemetry back to the developer. Every operator's successes and failures *attempt* to improve evasion effectiveness for all operators.

The platform provides an end-to-end capablities: phishing email composition and delivery, link obfuscation, automated domain rotation, Cloudflare Turnstile CAPTCHA gates to block automated analysis, and final redirection to Evilginx reverse-proxy pages that capture credentials and **live session tokens, bypassing MFA entirely**.

We observed developers testing UPMI's platform as early as March 12, 2026. Hardcoded credentials for the operator dashboard, SMTP accounts, Azure AD applications, and the developer's Telegram bot token were all recovered from the source code.

# Attack Chain

The full attack chain is explicitly documented in the threat actor's own `knowledge-base.js`:

```js
attackChain: [
  '1. MX Sender sends email (Gmail API / O365 relay / Port 25 direct)',
  '2. Email body contains encrypted link → go.docviewportal.com/d/TOKEN',
  '3. LinkShield decrypts AES-256 token → extracts target URL + recipient',
  '4. Turnstile CAPTCHA verification (blocks all scanners)',
  '5. Redirect to Evilginx lure → webmail.tms.ac/...',
  '6. Evilginx reverse-proxies Microsoft login page',
  '7. Target enters credentials → Evilginx captures username + password + session token',
  '8. Session token = full account access (bypasses MFA)',
]
```
# Sending Infrastructure (MX Sender)

The platform supports three distinct delivery methods, with automatic failover between them. 

## Reconnaissance

Before any emails are sent, `osint-recon.js` performs passive DNS reconnaissance against each target domain, gathering:

- MX hostnames and inferred filter vendor
- DMARC policy (`none` / `quarantine` / `reject`) and enforcement percentage
- SPF mechanisms and hard/soft-fail configuration
- DKIM selector enumeration (12 common selectors tested)
- Nameserver provider (Cloudflare, Route 53, Azure DNS, etc.)
- Autodiscover CNAME presence (confirms Exchange Online)

[![1](/assets/images/UPMI/2.png){: .align-center .img-border}](/assets/images/UPMI/2.png)
<p class="figure-caption">UPMI ULTIMATE - Recon module</p>

Each domain is assigned a risk score from 0–100 combining filter difficulty, DMARC strictness, and SPF configuration. The score determines which delivery method is selected and whether full domain spoofing is viable. Domains with `p=none` and no enterprise filter can be spoofed directly; domains with `p=reject` behind Proofpoint route to O365 relay with display-name-only spoofing.

## Sending emails

**Direct MX (Port 25)**

Connects directly to the victim's mail server with full domain spoofing capability. No sending limits beyond IP reputation. The primary sender domain observed was `pablotechnostore[.]com`.

**Office 365 SMTP Relay**

Uses `smtp.office365.com:587` with O365 accounts. The framework allowed for Display-name spoofing only, since O365 enforces FROM address matching. This method achieves the highest inbox rate for O365-to-O365 delivery. 

**Microsoft Graph API**

Native Microsoft API sending that bypasses SMTP-layer security controls entirely. The source code contained hardcoded Azure AD credentials:

```
Tenant ID:     01e9a5b6-58de-44a7-8d3a-04a0a85ea86b
Client ID:     dc6a461f-e84a-4991-a28e-8719e1da2e19
Sender:        johnny[@]professionalinsurancesolutions[.]com
```

**DMARC Auto-Detection**

Before sending, the system scans each recipient domain's DMARC policy. Domains with no DMARC or `p=none` get full domain spoofing, where the email is sent as something like `hr@targetdomain.com`. Domains with `p=reject` trigger a fallback to display-name-only spoofing. Major free email providers (Gmail, Outlook, Yahoo, ProtonMail, iCloud) are hardcoded as protected.

**DKIM Signing**

RSA-2048 DKIM private keys were maintained for six sender domains: `bowhead-transport[.]com`, `workplaceoutreach[.]online`, `vvearcon[.]com`, `cybernt[.]us`, `trns[.]live`, and `tms[.]ac`. Additional keys exist for `ventrisecure[.]com`.

**IP Warmup**

A dedicated warmup engine (`warmup.js`) manages sending volume from fresh IPs on a 30-day schedule, enforcing daily send limits and minimum delays between sends.

| Day | Daily Limit | Delay Between Sends |
|-----|-------------|---------------------|
| 1–3 | 5–10 | 60–120 seconds |
| 4–7 | 20–30 | 30–45 seconds |
| 8–14 | 50–75 | 10–15 seconds |
| 15–21 | 100–200 | 5–8 seconds |
| 22–30 | 300–500 | 3–4 seconds |
| 30+ | 1,000+ | 2 seconds |

State is persisted to `warmup-state.json` with per-day send counts. A fresh IP that attempts bulk sending before warming will be rate-limited or blocklisted before reaching any significant volume.


# The Xverginia Dashboard

Operators purchasing access to UPMI receive a web dashboard branded **"Xverginia - Evilginx Session Manager"**. The login page for version 4.1 lists `@andrew_z12` as the contact for license renewal and support.

[![1](/assets/images/UPMI/XverginiaLogin.png){: .align-center .img-border}](/assets/images/UPMI/XverginiaLogin.png)
<p class="figure-caption">Xverginia 4.1 dashboard login page</p>

The dashboard provides visibility into visitors, active sessions, and real-time notifications when session tokens are successfully stolen. Configuration is focused on two areas: Telegram channel and bot token for notifications, and Evilginx management including enabling/disabling phishing lures and changing phishing URLs.

[![1](/assets/images/UPMI/LureMenu.png){: .align-center .img-border}](/assets/images/UPMI/LureMenu.png)
<p class="figure-caption">Xverginia 4.1 dashboard lure configuration</p>

**Dashboard Licensing**

The dashboard has its own licensing system, separate from the mailer, using port 4444 and a license key format of `DASH:<iv_hex>:<auth_tag_hex>:<encrypted_payload_hex>`. It supports offline activation via a local key file, indicating the developers designed for modularity across different phishing configurations.

## Live Deployments

The Login Panel exposed the string "Login — Xverginia" within the HTTP response body. We can use the Censys query `web.endpoints.http.body:"Login — Xverginia` to identify 6 Xverginia deployments on 29/03/2026:

[![1](/assets/images/UPMI/9.png){: .align-center .img-border}](/assets/images/UPMI/9.png)
<p class="figure-caption">New Xverginia version login page, on port 2030</p>

```
143.198.27[.]52:2030
147.182.195[.]233:2030
104.194.152[.]178:2030
157.250.207[.]92:2030
212.52.6[.]239:2030
205.198.88[.]186:2030
```

[![1](/assets/images/UPMI/NewVersion.png){: .align-center .img-border}](/assets/images/UPMI/NewVersion.png)
<p class="figure-caption">New Xverginia version login page, on port 2030</p>

# LinkShield

The UPMI platform has multiple features, including **MX Sender**, advertised as a "Intelligent Email Security Assessment Platform" used to send the phishing emails to recipient mailboxes. 

Within the emails themselves are the phishing links - which is managed purely by "LinkShield", advertised as "Advanced link management with CAPTCHA protection, click tracking, smart redirects, and real-time analytics. All in one powerful platform".

[![1](/assets/images/UPMI/4.png){: .align-center .img-border}](/assets/images/UPMI/4.png)
<p class="figure-caption">LinkShield</p>

From the website, it lists the below features:

[![1](/assets/images/UPMI/10.png){: .align-center .img-border}](/assets/images/UPMI/10.png)
<p class="figure-caption">LinkShield Features</p>

Every phishing link is encrypted with AES-256-GCM using a shared secret between the sender and the LinkShield decryption server. The encrypted payload contains the destination URL, a timestamp, the recipient email, and a random nonce. No automated scanner can determine the destination without the decryption key. The shared encryption secret recovered from the source: `qVLPQpK8d6xseWkQRw0S2u/mNUrTT/XRZUh4qCfoeCw=`

On the LinkShield panel, we observed how an operator would generate URLs that would be used in campaigns: 

[![1](/assets/images/UPMI/7.png){: .align-center .img-border}](/assets/images/UPMI/7.png)
<p class="figure-caption">LinkShield Link Creation</p>

Additionally, LinkShield offered the capability to generate "GOOGLE PROTECTED URLs" that would stage the phishing link via an initial trusted google.com domain: 

[![1](/assets/images/UPMI/3.png){: .align-center .img-border}](/assets/images/UPMI/3.png)
<p class="figure-caption">LinkShield Google Redirection</p>

## Live Deployments

Using the Censys query, `host.services.endpoints.http.html_title:"LinkShield - Professional Link Management"`, we can identify 1 deployment of LinkShield on the IP address `104.131.106[.]42`

[![1](/assets/images/UPMI/12.png){: .align-center .img-border}](/assets/images/UPMI/12.png)
<p class="figure-caption">LinkShield Link Creation</p>

# Defence Evasion / Anti-Analysis 

**Scanner Detection**

The tracking server (`tracker.js`) maintains extensive IP range databases to classify visitors. Over 100 Microsoft Safe Links / EOP IP prefixes, Google Safe Browsing ranges, Proofpoint, Mimecast, and Barracuda ranges are all catalogued. When a scanner IP hits the tracking pixel or click URL, it is classified separately from human visitors, allowing operators to distinguish real opens from automated scanning. Over 30 regex patterns match known crawler user-agents and sandboxes.

**Cloudflare Worker Proxy**

Tracking pixels and click redirects are routed through a Cloudflare Worker. The email source only shows a `workers.dev` URL (trusted by most filters), the real tracker VPS IP is never exposed in email headers, and Cloudflare's infrastructure adds credibility to the tracking URLs.

**Reply-Chain Injection**

The platform generates fake email conversation threads prepended to the phishing message. Five pre-built thread templates ("Document Review", "Following up", "Quick question", "Project update", "Shared file") fabricate a history of prior messages between the sender and recipient, with realistic timestamps set 1–3 days prior during business hours.

The code is explicit about why this works:

```javascript
// Reply Chain Injection Engine
// Generates fake previous email threads that make the email look like
// an ongoing conversation. Microsoft's ML gives massive trust boost
// to reply chains — they indicate established relationships.
```

The phishing link is embedded naturally as part of the final message in the fake thread rather than appearing as a standalone call-to-action. The subject line is set to `RE: [template subject]`.

**Content Randomization**

The platform randomizes HTML elements (invisible spans, random CSS classes, unique IDs per email), subjects (variable dates, numbers, department names), and text content (synonym replacement, sentence reordering). Both `text/plain` and `text/html` MIME parts are included, alongside Exchange-clean headers with proper `Message-ID`, `List-Unsubscribe`, and `Thread-Index` values. For bulk sends, the lead queue is shuffled so consecutive emails go to different MX servers, preventing any single mail server from seeing a burst of traffic.

**Filter-Specific Header Manipulation**

Before constructing each email, `fingerprint.js` identifies the target's mail filter from the MX hostname and selects a tailored header set.

For *Microsoft EOP* targets, the sender injects forged Exchange internal headers:

```
X-MS-Exchange-Organization-SCL: -1
X-MS-Exchange-Organization-AuthSource: internal
X-Mailer: Outlook 16.0
```

An SCL value of `-1` signals to Exchange Online Protection that the message has already been scanned and trusted by an internal system.

For *Google Workspace* targets, the opposite strategy applies, all `X-MS-*` headers are stripped entirely.

For *Proofpoint* targets, tracked images are removed and URL count is minimised, reducing surface area for Proofpoint's URL detonation engine.

**Automated Domain Rotation**

Sending domains are managed through a pool defined in `sender-domains.txt`, with one entry per line:

`name|email|helo|dkim_domain|dkim_selector|dkim_key_path`

The sender cycles through the pool in round-robin order - each email increments an index counter, so consecutive emails rotate across all domains in the pool. The DKIM private key for each domain is loaded automatically at startup from `dkim-keys/<domain>/private.pem`.

`health-monitor.js` runs on a 30-minute interval, checking every sending domain and IP against 15 blacklists sources. If a listing is detected, a Telegram alert fires immediately instructing the operator to swap the domain out. The operator then removes the burned entry from `sender-domains.txt` and adds a replacement:

[![1](/assets/images/UPMI/DomainRotated.png){: .align-center .img-border}](/assets/images/UPMI/DomainRotated.png)
<p class="figure-caption">Domain rotation and standby domain count Telegram notification</p>

# License and Remote Control

## Architecture

The developer sells this as a licensed product. License keys are bound to a SHA-256 hash of the client machine's CPU model, core count, hostname, username, platform, architecture, total memory, and MAC addresses. The license format is `MXLIC:<iv_hex>:<auth_tag_hex>:<encrypted_payload_hex>`, with AES-256-GCM encryption and HMAC-SHA256 signing.

Every startup contacts the license server at `104.131.106[.]42:9999` for verification. Core logic modules (knowledge-base, campaign-intelligence, adaptive-throttle) are AES-256-GCM encrypted and can only be decrypted with a valid license key at runtime.

**Telegram Bot Control**

The developer controls the entire operation from a single Telegram bot (`Mxlicense_control_bot`). From here the developer can generate new licenses, kill or revoke licenses instantly, view all active machines and their IPs, view activity logs, view campaign intelligence across all deployed instances, and trigger a nuclear kill-all option.

**License Server API**

The HTTP API on port 9999 exposes endpoints for license verification (`POST /api/license/verify`), admin license management (`GET /api/admin/licenses`), activity logging (`GET /api/admin/activity`), instant revocation (`POST /api/admin/kill`), and a web dashboard. The developer maintains full visibility into every client's operations.

**Encrypted Module Loading**

Core logic modules (`knowledge-base`, `campaign-intelligence`, `adaptive-throttle`) are distributed as AES-256-GCM encrypted `.enc` files. The plaintext `.js` source is not present in production deployments.

At runtime, `secure-loader.js` derives a decryption key using `scryptSync(masterSecret, 'mx-module-enc-salt', 32)`, decrypts the module into a temporary file under `/tmp/.mx-[hash]/`, imports it as an ES6 module, and **immediately deletes the temporary file**. The decrypted source exists only in memory for the lifetime of the process.

This means a filesystem snapshot of a running operator instance reveals no readable campaign logic - only encrypted blobs that are useless without the master secret bound to a valid license.

# Collective Intelligence

This is arguably the most interesting component of the platform. Every deployed MX Sender instance participates in a shared intelligence network. Before each campaign, the instance pulls global intelligence from the master server (`/api/intel/pull`). After each campaign, it pushes results back (`/api/intel/push`).

The data collected per target domain includes mail filter type (Proofpoint, Mimecast, Barracuda, Google, Microsoft, cPanel, etc.), DMARC/SPF/DKIM status, MX hostname and response times, delivery rates, open rates, click rates, throttling events, greylisting behaviour, and risk scores. Over time, this creates a feedback loop where the platform gets progressively better at evading each target's defences.

**Pre-loaded Knowledge Base**

The developer has pre-loaded `knowledge-base.js` with extensive intelligence on mail security vendors, rating each on a difficulty scale of 1-10. Proofpoint scores a 9, with notes that clean business emails bypass ML scoring and that DKIM from real domains get reputation boosts. GoDaddy scores a 3, with notes that it has almost no content filtering and no URL scanning.

The system automatically selects the optimal delivery method per target domain based on this intelligence. O365 targets get the O365 relay (same-ecosystem trust). Proofpoint targets get the O365 relay for Microsoft reputation. cPanel and GoDaddy targets get Port 25 direct delivery to save relay quota for harder targets.

# Phishing Templates

Seven templates were included in the source code, each designed for specific social engineering scenarios. These ranged from SharePoint/OneDrive document sharing notifications, to corporate IT password expiration notices, to security alert notifications about unusual logins, to enterprise voicemail notifications.

One template (`voicemail-image.html`) renders the entire email body as a dynamically generated image using the Node.js `canvas` library, bypassing text content scanning entirely. Another template (`clean-business.html`) is a plain corporate follow-up with no urgency or branding, designed specifically to bypass ML content classifiers.

All templates support dynamic placeholders for recipient name, email, domain, sender name, landing URL, current date/time, and random numbers. The subject lines are randomised with variable elements to prevent pattern-based detection.

## HTML Attachments

Two HTML attachment variants were recovered (`e32afa656bf7-SharedDocument.html`, `4ed20f25ac8c-DocumentViewer.html`). Both render a blurred document preview in the browser, fake line elements and a metadata table visible beneath a blur filter, overlaid with a lock badge and the message *"This document is protected. Verify your identity to access the contents."*

The redirect URL is not present in plaintext. It is obfuscated via a character code shift followed by base64 encoding. The destination is decoded and executed in the browser at click time, making static extraction from the HTML file insufficient.

```javascript
var _d14f4a10f2d6492a="iPZ8kPU>TAvj=sj:V:i_^;kOAlON{TuV~j[AT;RtluttlEE";
function _d(s,k){return atob(s.split("").map(function(c){
    return String.fromCharCode(c.charCodeAt(0)-k)}).join(""))}
function go(){ ... window.location.href=_d(_d14f4a10f2d6492a,8) }
```

A 1.2-second loading spinner reading *"Connecting to authentication portal..."* plays before the redirect fires.

## PDF Attachments

`pdf-generator.js` produces password-protected PDFs across four templates: voicemail notification, invoice, document review, and security alert. Passwords are randomly selected from a wordlist (e.g. `Review1234`, `Access5678`) and distributed in the email body. Document metadata is spoofed:

```
Author:  Notification Service
Creator: Microsoft Office
```

Permissions are set to block copying and modification, restricting recipients to read-only and print access.

# Leads

Several lead files were recovered from the source code, including `Leads-20k.txt` containing approximately 20,000 email addresses. Processed lead data in JSON format within the `dashboard-data/leads/` directory included `@wellsfargo.com` targets.

The `knowledge-base.js` confirmed successful inbox delivery against several potential test domains including `shreekrishnarubber[.]com` (Bluehost), `crewchiefpb[.]com` (cPanel), `basamat[.]org`, and `gatsbydominicana[.]com`.

# Evilginx Phishlets

| Phishlet | VPS | Target |
|----------|-----|--------|
| `msoutlookonline` | `tms[.]ac` / `45.61.136.[1]90` | Microsoft 365 login |
| `cpanel-webmail` | `cybernt[.]us` / `64.95.13[.]174` | cPanel webmail login |
| `roundcube` | `cybernt[.]us` / `64.95.13[.]174` | Roundcube webmail login |
| `office-working` | `sso.ventraqcloud[.]com` / `104.131.106[.]42` | Microsoft 365 login |

# AI-Assisted Development

Despite its capabilities, analysis of the source code strongly suggests this platform was developed with heavy assistance from a Large Language Model (LLM). 

**Sanitised Framing**

The most telling indicator is how the platform describes itself. Nowhere in the source code does the developer call this what it is. The startup banner displayed to operators reads:

```
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║          UPMI ULTIMATE — MX SENDER v7.0                      ║
║       Intelligent Email Security Assessment Platform         ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
```

The `package.json` description is `"UPMI Ultimate — Intelligent email security assessment platform"`. The PDF report generator produces documents titled "Campaign Security Assessment Report" with a footer stating *"This report was generated as part of an authorized security assessment. All activities were conducted with proper authorization."* The dashboard UI describes the intelligence engine as a tool for "security assessments" and the report generator as something to "hand to the client to close the deal."

This sanitised language is consistent with how someone would need to frame prompts to an LLM in order to get it to generate this code. Modern LLMs refuse to write code explicitly described as phishing tooling, but will readily produce "email security assessment platforms" or "red team tools" with identical functionality. The framing persists throughout the codebase because it was baked into the prompts that generated it.

**Structural Fingerprints**

Across **16,284 lines** of JavaScript spread over 38 source files, the code exhibits a remarkably consistent set of patterns that are hallmarks of LLM-generated output.

```javascript
// ═════════════════════════════════════════════════════════════════════════════
//  MAIL FILTER PROFILES — How each security vendor works internally
// ═════════════════════════════════════════════════════════════════════════════
```

```javascript
// ─── Synonym Banks ───────────────────────────────────────────────────────────
```

```javascript
// ─── Scan single domain's MX records ────────────────────────────────────────
```

**Emoji in source code strings** appears **99 times** across the codebase, used heavily in `console.log` output, Telegram messages, and UI elements. The license bot alone uses over 40 distinct emoji characters in its output strings (`💀`, `✅`, `🆕`, `🔑`, `💻`, `🌐`, `📊`, `🧠`, `⚡`, etc.). 

## What This Means

None of this diminishes the platform's operational capability. The attack chain works. The Evilginx integration captures session tokens. The collective intelligence system aggregates campaign data. AI-assisted development lowered the barrier to building a fully-featured PhaaS platform, allowing a developer who may not have been capable of building this from scratch to produce a commercially viable product.

# Conclusion

This marks another step in Phishing-as-a-Service platforms. What makes UPMI notable is the AI-assisted development, which included collective intelligence gathering across licensed operators, where every campaign improves evasion effectiveness for the entire network. 

The exposed master server gave us full visibility into the developer's operation, including their licensing model, intelligence sharing infrastructure, operator dashboard, and the credentials tying it all together. We hope sharing this analysis helps defenders detect and disrupt campaigns leveraging this platform.

# IOCs

| Type | Value | Context |
|------|-------|---------|
| IP Address | `143.198.27[.]52` | XVerginia deployment |
| IP Address | `147.182.195[.]233` | XVerginia deployment |
| IP Address | `104.194.152[.]178` | XVerginia deployment |
| IP Address | `157.250.207[.]92` | XVerginia deployment |
| IP Address | `212.52.6[.]239` | XVerginia deployment |
| IP Address | `205.198.88[.]186` | XVerginia deployment | 
| IP Address | `104.131.106[.]42` | Master server: license server, LinkShield, intelligence API |
| IP Address | `45.61.136[.]190` | Evilginx VPS #1 (`tms.ac`) |
| IP Address | `64.95.13[.]174` | Evilginx VPS #2 (`cybernt.us`) |
| IP Address | `193.111.125[.]137` | Primary sending server (Kamatera) |
| IP Address | `103.101.202[.]72` | Secondary sending server (Kamatera) |
| Domain | `tms[.]ac` | Evilginx phishing domain |
| Domain | `cybernt[.]us` | Evilginx phishing domain (standby) |
| Domain | `docviewportal[.]com` | LinkShield encrypted URL decryption |
| Domain | `go.docviewportal[.]com` | Primary LinkShield endpoint |
| Domain | `webmail.tms[.]ac` | Primary Evilginx lure URL |
| Domain | `pablotechnostore[.]com` | Primary sender domain |
| Domain | `bowhead-transport[.]com` | Sender domain (DKIM-signed) |
| Domain | `workplaceoutreach[.]online` | Sender domain (DKIM-signed) |
| Domain | `vvearcon[.]com` | Sender domain (DKIM-signed) |
| Domain | `trns[.]live` | Sender domain (DKIM-signed) |
| Domain | `professionalinsurancesolutions[.]com` | Graph API sender domain |
| Domain | `ventrisecure[.]com` | Sender domain (DKIM keys present) |
| Domain | `ventracloud[.]com` | Evilginx phishing domain |
| Domain | `brevantic[.]com` | Evilginx phishing domain |
| Bot Username | `Mxlicense_control_bot` | License management bot |
| Bot Username | `UPMi035bot` | Tracker alert bot |
| URL Pattern | `go.docviewportal[.]com/d/<base64url_token>` | Encrypted phishing link |
| URL Pattern | `webmail.tms[.]ac/djMfuXoi` | Default Evilginx lure URL |

# MITRE ATT&CK

| Tactic | ID | Technique | Observed Activity |
|--------|----|-----------|-------------------|
| **Resource Development** | [T1583.001](https://attack.mitre.org/techniques/T1583/001/) | Acquire Infrastructure: Domains | Multiple phishing and sender domains (`tms.ac`, `cybernt.us`, `docviewportal.com`, etc.) |
| **Resource Development** | [T1583.003](https://attack.mitre.org/techniques/T1583/003/) | Acquire Infrastructure: Virtual Private Server | Kamatera VPS for sending, DigitalOcean droplet for master server |
| **Resource Development** | [T1583.006](https://attack.mitre.org/techniques/T1583/006/) | Acquire Infrastructure: Web Services | Cloudflare Workers for tracking proxy, Azure AD apps for Graph API sending |
| **Resource Development** | [T1585.002](https://attack.mitre.org/techniques/T1585/002/) | Establish Accounts: Email Accounts | Multiple sender accounts across O365 and custom domains |
| **Resource Development** | [T1608.005](https://attack.mitre.org/techniques/T1608/005/) | Stage Capabilities: Link Target | LinkShield decryption server + Evilginx reverse-proxy infrastructure |
| **Resource Development** | [T1588.002](https://attack.mitre.org/techniques/T1588/002/) | Obtain Capabilities: Tool | Evilginx reverse-proxy framework for credential and session token harvesting |
| **Reconnaissance** | [T1596.002](https://attack.mitre.org/techniques/T1596/002/) | Search Open Technical Databases: DNS/Passive DNS | Automated DMARC/SPF/MX scanning per target domain before sending |
| **Credential Access** | [T1557.001](https://attack.mitre.org/techniques/T1557/001/) | Adversary-in-the-Middle | Evilginx reverse-proxy intercepts credentials and live session tokens (MFA bypass) |
| **Credential Access** | [T1539](https://attack.mitre.org/techniques/T1539/) | Steal Web Session Cookie | Evilginx captures live session tokens providing full account access |
| **Defense Evasion** | [T1027](https://attack.mitre.org/techniques/T1027/) | Obfuscated Files or Information | AES-256-GCM encrypted core modules, encrypted URL tokens |
| **Command and Control** | [T1071.001](https://attack.mitre.org/techniques/T1071/001/) | Application Layer Protocol: Web Protocols | HTTPS for licensing, intelligence sync, and LinkShield |
| **Command and Control** | [T1102](https://attack.mitre.org/techniques/T1102/) | Web Service | Telegram for license management, campaign alerts, and remote kill switch |
