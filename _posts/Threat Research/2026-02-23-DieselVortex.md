---
title: "Diesel Vortex: Exploring connections to Russian LLCs"
classes: wide
header:
  teaser: /assets/images/cargo/logo.png
ribbon: black
description: "OSINT analysis of entities potentially linked to the 'Global Profit' PHaaS platform"
categories:
  - Threat Research
tags:
  - Threat Research
toc: true

---

# Overview

In February 2026, *Ctrl-Alt-Intel* and *Have I Been Squatted* identified a financially motivated threat actor we've tracked as **Diesel Vortex**. The group operate a phishing-as-a-service platform branded *Global Profit* or *MC Profit Always* and harvested more than 1,500 unique credentials belonging to Western logistics, trucking, and transportation companies.

*Have I Been Squatted* retrieved and analysed source code from the *Global Profit* phishing platform, which provided visibility into both infrastructure and operations. Telegram webhook logs embedded within the platform exposed months of internal coordination between operators. 

Linguistic analysis of those logs indicates Armenian-speaking actors targeting companies in the logistics sector. Conversations reference impersonation of freight brokers, use of voice phishing, and deployment of remote management tools to access internal systems. The objective was consistent with cargo diversion and goods theft.

During infrastructure analysis, *Ctrl-Alt-Intel* identified a domain registration that linked the phishing panel to a Russian-registered email address. That same email appears linked to corporate records of potentially linked logistics and warehousing LLCs that reported over **14.3 billion rubles** (**$180+ million USD**) in annual revenue within 2024.

[![1](/assets/images/cargo/20.png){: .align-center .img-border}](/assets/images/cargo/20.png)
<p class="figure-caption">Main Correlation Graph</p>

> This research is based solely on open-source intelligence (OSINT) and analysis of materials obtained during technical investigation. References to individuals and Russian-registered limited liability companies (LLCs) are provided for research context only, based on publicly available records and observed technical artifacts. Any linkages described are hypotheses derived from correlational indicators and should not be interpreted as findings of guilt, intent, or legal liability.

# Phishing in Yerevan

Within the recovered source code, developers logged all Telegram webhook calls to a file named `apidata-full.txt`. The logs correspond to a prior campaign deployment and span from 22 November 2024 through 25 April 2025.  

Four Telegram chats were captured:


| **TG Chat ID** | **# of messages** | **# of members** | **Primary Language**    | **First Message (UTC)** | **Last Message (UTC)** |
|----------------|-------------------|------------------|-------------------------|-------------------------|------------------------|
| -1002326535196 | 1255              | 8                | Armenian (Latin Script) | 2024-11-22 16:19:23     | 2025-04-11 20:28:21    |
| -1002159174580 | 134               | 6                | Armenian                | 2025-01-10 16:44:57     | 2025-04-25 19:09:35    |
| -1002335202080 | 50                | 3          | Russian                 | 2024-12-06 14:20:30     | 2024-12-23 16:41:03    |
| -1002495358035 | 5                 | 2          | Russian                 | 2025-01-09 23:13:28     | 2025-01-09 23:15:32    |

The dominant chat, containing 1,255 messages, was conducted in Armenian using Latin script, with occasional Russian messages. Operators discussed:

* Credential harvesting results
* MCs - Motor Carrier (companies that transport goods/cargo)
* SMS / Call spoofing services
* Remote, Monitoring & Management (RMM) tools

Although 14 unique Telegram user IDs registered to the platform, the majority of the messages were sent by 4 users:


| **User ID** | **username** | **# of messages** |
|--------------|----------|----------------------------|
| 7779899846 | gts100 | 465 |
| 5270565142 | TA1 | 411 |
| 5318416774 | TGMC100 | 247 |
| 2077544656 | TA2 | 245 |
| 7517405011 | antonioprimoderivera | 29 |
| 1087968824 | GroupAnonymousBot | 21 |
| 6570551667 | sapip_188 | 7 |
| 5321390016 | GTPOCO_2 | 6 |
| 389288453 | Mc100Mc | 4 |
| 5712841521 | gts10 | 3 |
| ... | ... | ... | 

## Translated conversations using an LLM 

Most messages were written in Armenian using Latin script. Where possible, we translated them to better understand campaign context. Seeing how the speak to each other, on the day to day, in their private Telegram chat provides a lot of insight. For some reason, some accounts only had their Telegram ID and not username. I've named these `TA1` and `TA2`. The other usernames were found within the logs.

[![1](/assets/images/cargo/17.png){: .align-center .img-border}](/assets/images/cargo/17.png)
<p class="figure-caption">Translated Chat Excerpt</p>

2 members of **Diesel Vortex** on the *Global Profit Platform* had a conversation with one asking "do we have an MC with 250k cargo?". Here they are referring to a compromised Motor Carrier with 250k worth of cargo. Although the currency is not stated - we presume they are discussing USD as they are targeting US companies. 

Please see [Have I Been Squatted's analysis](https://haveibeensquatted.com/blog/diesel-vortex-inside-the-russian-cybercrime-group-targeting-us-eu-freight#language-geography-and-operational-patterns) for further details.

# The Infrastructure Pivot

Within the phishing panel source code, the file `njhTghagTGgYT\template\footer.php` contained a reference to the domain `yasomawork[.]space`. The domain was embedded within the login panel of the phishing-kit.

[![1](/assets/images/cargo/1.png){: .align-center .img-border}](/assets/images/cargo/1.png)
<p class="figure-caption"> Source Code Excerpt</p>

Historical DNS records show `yasomawork[.]space` resolving to `45.130.41[.]81` on 14 February 2025. The domain itself was registered three days earlier, on 11 February 2025 at 16:51:57 GMT.

RDAP data shows the domain was registered through the Russian provider *BEGET-RU*. The associated IP address was also hosted on infrastructure allocated to Beget.

[![2](/assets/images/cargo/2.png){: .align-center .img-border}](/assets/images/cargo/2.png)
<p class="figure-caption"><a href="https://client.rdap.org/?type=domain&object=yasomawork.space&follow-referral=1">RDAP Record</a></p>

Unlike anonymized registrations commonly used in phishing operations, this domain contained registrant details including:

* A full name
* A phone number
* An email address

# From Infra to Identity

The registrant email address exposed in the RDAP record was reused across multiple services and corporate filings. We used the platform [osint.industries](https://www.osint.industries/) to pivot on the email and phone number to find profiles under the names:

[![3](/assets/images/cargo/21.png){: .align-center .img-border}](/assets/images/cargo/21.png)
<p class="figure-caption">Screenshot from osint.industries platform</p>

* Yura Ivlev
* Yuri Ivlev 
* Yuri Ivlev Konstantinovich
* Юрий Ивлев Константинович

We will use the name **Yuri** or **Yuri Ivlev** for the remainder of this analysis. 

Publicly accessible social media accounts contain photos dating from 2014 through 2023. The same email address was used to register the domain `unx-defence[.]ru` on 8 December 2021, also via *Beget*.

[![3](/assets/images/cargo/3.jpg){: .align-center .img-border}](/assets/images/cargo/3.jpg)
<p class="figure-caption">Yuri's Facebook Photo (2014)</p>

[![4](/assets/images/cargo/4.jpg){: .align-center .img-border}](/assets/images/cargo/4.jpg)
<p class="figure-caption">Yuri's Whatsapp Photo (2023)</p>

Corporate registry records show the identity linked to the email `y.ivlev@gmail.com` associated with several Russian LLCs operating in wholesale trade, transportation and warehousing.

From `2014` to `2025`, **Yuri** was a founder or co-founder of the 5 registered entities:


| **Registration Date**| **LLC Name**  | **Translation** | **ИНН/Tax ID** | **Email**                | **Sector**   | **Ownership at incorporation** |
|------------------------|---------------|----------------|------------|----------------------|---------------------|-----------|
| 25th Sep 2014 (closed) | КОРОНА ХОСТЕЛ | KORONA HOSTEL  | [7715446004](https://www.tbank.ru/business/contractor/legal/5147746142638/) | N/A                  | Hotel/Accommodation  | 100%      |
| 30 Sept 2021          | ЮНИКС ГРУПП   | UNIX GROUP LLC | [7713484999](https://www.tbank.ru/business/contractor/legal/1217700463529/) | buh[@]unx-defence[.]ru   | Wholesale trade     | 100%      |
| 15th Jun 2023          | ВПМ           | VPM            | [9726047206](https://www.tbank.ru/business/contractor/legal/1237700412443/) | y.ivlev[@]gmail[.]com    | Wholesale trade     | 100%      |
| 13th July 2023         | ТЕРМИНАЛ ИКС  | Terminal X     | [9726049122](https://www.tbank.ru/business/contractor/legal/1237700473581/) | nkazarinov[@]yandex[.]ru | Warehousing/Storage | 67%       |
| 10th Oct 2025          | ПСМ           | PSM            | [5044145482](https://www.tbank.ru/business/contractor/legal/1255000093116/) | y.ivlev[@]gmail[.]com    | Wholesale trade     | 100%      |

## UNIX GROUP LLC 

*UNIX GROUP LLC* was registered on 30 September 2021. On 8 December 2021, the domain `unx-defence[.]ru` was registered using the same email address identified in the phishing panel RDAP record. In June 2022, **Yuri Ivlev** assumed ownership of the company.

Corporate filings show *UNIX Group LLC* registered more than 30 OKVED classifications. The primary classification is:

* 46.90 — Non-specialized wholesale trade

However, additional classifications include:

* 49.20.9 — Transportation of other cargo
* 52.10 — Warehousing and storage activities
* 52.29 — Other auxiliary activities related to transportation

These codes directly align with logistics, freight handling, and storage operations.

[![6](/assets/images/cargo/9.png){: .align-center .img-border}](/assets/images/cargo/9.png)
<p class="figure-caption"><a href="https://www.tbank.ru/business/contractor/legal/1217700463529/okved/">UNIX Group LLC OKVED code</a></p>

The domain `unx-group[.]ru` is the publicly accessible website for the entity *UNIX GROUP LLC*:

[![7](/assets/images/cargo/4.png){: .align-center .img-border}](/assets/images/cargo/4.png)
<p class="figure-caption"><a href="https://unx-group.ru/">UNIX Group website</a></p>

"UNIX Group, a trading and manufacturing company, is a direct partner of leading Chinese factories and offers a wide range of high-quality industrial and consumer raw materials". We can see they also have "Our own logistics service for international transportation" and are in "Close cooperation with leading factories in Russia and China".

[![8](/assets/images/cargo/5.png){: .align-center .img-border}](/assets/images/cargo/5.png)
<p class="figure-caption"><a href="https://unx-group.ru/">UNIX Group website</a></p>

This appears to be a legitimate registered business that comes along with a product catalog:

[![9](/assets/images/cargo/6.png){: .align-center .img-border}](/assets/images/cargo/6.png)
<p class="figure-caption"><a href="https://unx-group.ru/">UNIX Group website</a></p>

On 23 March 2022, *UNIX GROUP LLC* was issued an [official trade certificate](https://swis.trade.kg/Doc/171c9c78-4b33-47d9-af94-74dbcec88700) through a Kyrgyz government export and import documentation system. The certificate is publicly accessible and registers the company in connection with cross-border trade activity. Notably, the certificate lists the name **Olga Olegovna Ivleva**, who previously appeared in ownership records associated with the company.

[![10](/assets/images/cargo/7.png){: .align-center .img-border}](/assets/images/cargo/7.png)
<p class="figure-caption"><a href="https://swis.trade.kg/Doc/171c9c78-4b33-47d9-af94-74dbcec88700">Kyrgyz trade certificate</a></p>

### Rapid Growth

Using 1 Ruble = 0.013 USD: 

| **Year** | **Revenue (USD)** | **Net Profit (USD)** |
| -------- | ----------------- | -------------------- |
| 2021     | $604,700          | $2,000               |
| 2022     | $54,420,000       | $9,670,000           |
| 2023     | $95,180,000       | $16,270,000          |
| 2024     | $154,890,000      | $10,910,000          |

[T-Bank - ООО "ЮНИКС ГРУПП" (UNIX GROUP LLC)](https://www.tbank.ru/business/contractor/legal/1217700463529/)   

Between 2021 and 2024, *UNIX Group LLC* scaled from sub-million revenue to more than $150 million annually. Net profit margins in 2023 exceeded 17 percent.

We have no evidence to prove these funds have originated from cargo theft, nor is *Ctrl-Alt-Intel* suggesting this. At minimum, the overlap establishes that the registrant of phishing infrastructure operates or has operated companies in the same sector targeted by **Diesel Vortex**.

[![11](/assets/images/cargo/14.png){: .align-center .img-border}](/assets/images/cargo/14.png)
<p class="figure-caption">Correlation Graph #1</p>

## Terminal X and Shared Ownership

TERMINAL X LLC was registered on 13 July 2023.

Ownership at formation:

* **Yuri Ivlev** - 67% 
* **Nikita Kazarinov** - 33%

[![12](/assets/images/cargo/8.png){: .align-center .img-border}](/assets/images/cargo/8.png)
<p class="figure-caption">Split ownership of Terminal X</p>

The company lists the following OKVED classifications:

* 52.10 — Warehousing and storage activities
* 52.10.9 — Storage and warehousing of other cargo
* 52.29 — Other auxiliary transportation activities
* 82.99 — Other business support services

The classifications again align with freight handling and cargo operations.

Financial filings for Terminal X show limited revenue and small annual losses between 2023 and 2025. However, the structural importance of Terminal X lies not in revenue, but in shared ownership.

On 20 February 2026, just days prior to publication of this report, **Nikita Kazarinov** assumed full ownership of Terminal X. **Yuri Ivlev** no longer retained shares.

*Terminal X* serves as the bridge between **Yuri Ivlev** and **Nikita Kazarinov** within the corporate network.

# Shuttle Logistic and the "Terminal" Network

Nikita Kazarinov previously founded or owned several logistics-related entities, including:

* FILIKA GROUP
* TERMINAL PLUS
* TERMINAL BROKER
* TERMINAL X

Both *Terminal Plus* and *Terminal Broker* are associated with the domain `shuttle-logistic[.]ru`, operating under the brand "Shuttle Logistics Solutions":

[![14](/assets/images/cargo/10.png){: .align-center .img-border}](/assets/images/cargo/10.png)
<p class="figure-caption"><a href="https://shuttle-logistic.ru/company_details/">Shuttle Logistics website</a></p>

Unlike *UNIX Group LLC*, the Shuttle Logistics website prominently displays staff identities and executive leadership. **Nikita Kazarinov** is publicly presented as CEO.

[![15](/assets/images/cargo/11.png){: .align-center .img-border}](/assets/images/cargo/11.png)
<p class="figure-caption"><a href="https://shuttle-logistic.ru/company_details/">Nikita Kazarinov</a></p>

Industry media coverage from Russian logistics publications references Kazarinov in connection with freight and transportation operations.

[![15](/assets/images/cargo/12.png){: .align-center .img-border}](/assets/images/cargo/12.png)
<p class="figure-caption"><a href="https://logirus.ru/news/transport/fury_asstra_popali_v_perestrelku_na_ukraino-rossiyskoy_granitse.html?sphrase_id=11323822">Snippet of logirus.ru article</a></p>

[![15](/assets/images/cargo/13.png){: .align-center .img-border}](/assets/images/cargo/13.png)
<p class="figure-caption"><a href="https://logirus.ru/articles/week_results/indiyskiy_kryuk-_parallelnyy_import_i_konteynery_-na_stope.html?sphrase_id=11323822">Screenshot from logirus.ru website</a></p>

See below for the full list of registered entities with corresponding email addresses. 


| **Registration Date**  | **LLC Name**    | **Translation** | **ИНН/Tax ID** | **Email**                | **Sector**           | **Ownership at incorporation** |
|------------------------|-----------------|-----------------|----------------|--------------------------|----------------------|---------------|
| 22nd May 2014 (closed) | ФИЛИКА ГРУПП    | FILIKA GROUP    | [7715432611](https://www.tbank.ru/business/contractor/legal/1147746571499/)     | N/A                      | Cargo transportation | 33%           |
| 22nd Sept 2016          | ТЕРМИНАЛ ПЛЮС   | Terminal Plus   | [7728349199](https://www.tbank.ru/business/contractor/legal/1167746892488/)     | kiseleva_n1971[@]mail.ru   | Transportation       | 100%          |
| 26th Aug 2021           | ТЕРМИНАЛ БРОКЕР | Terminal Broker | [7726481674](https://www.tbank.ru/business/contractor/legal/1217700400741/)     | info[@]shuttle-logistic[.]ru | Transportation       | 100%          |
| 13th July 2023         | ТЕРМИНАЛ ИКС    | *Terminal X*      | [9726049122](https://www.tbank.ru/business/contractor/legal/1237700473581/)     | nkazarinov[@]yandex[.]ru     | Warehousing/storage  | 67%           |

# Address Clustering in Moscow

Five of the six identified LLCs are registered at the same address:

117105, Moscow, Novodanilovskaya Embankment, Building 4A

[![15](/assets/images/cargo/18.png){: .align-center .img-border}](/assets/images/cargo/18.png)
<p class="figure-caption">Correlation Graph #2</p>

In October 2025, a newly registered LLC diverged from this pattern, listing an address in the Esipovo Industrial Park in Solnechnogorsk.

The concentration of logistics-oriented entities at a single Moscow address reinforces the structural connectivity within the network.

# Sector Convergence 

The Telegram logs recovered from the phishing platform showed Armenian operators targeting:

* Freight brokers
* Trucker drivers
* logistics firm

The objective discussed was theft of cargo and/or funds. 

The Russian LLCs associated with **Yuri Ivlev** and **Nikita Kazarinov** list OKVED classifications covering:

* Wholesale trade
* Transportation of cargo
* Warehousing and storage 
* Auxiliary transportation services

Public websites for these companies advertise:

* International freight handling 
* Warehousing capacity
* Cross-border trade coordination

The sector alignment is direct. This report does not assert that the corporate revenue is being derived from phishing or diversion activity. 

However, the same email identified used to register phishing infrastructure appears in corporate filings for logistics companies operating in the same vertical targeted by **Diesel Vortex**. 

## What we can establish

Based on the technical artifacts and public records, the following claims can be made:

1. **Diesel Vortex** operated a phishing platform targeting logistics-sector companies.
2. Telegram logs show Armenian-speaking operators discussing credential harvesting and cargo-related activity. 
3. The phishing panel contained a domain registered with identifiable personal information.
4. That email identifier appears in Russian corporate filings for multiple logistics-oriented LLCs.
5. Several of these companies share sector classifications and a common Moscow address.
6. A co-owned entity between **Yuri Ivlev** and **Nikita Kazarinov** transferred ownership shortly before publication.

Each data point is independently verifiable through infrastructure records and public corporate registries.

# Conclusion

The investigation into **Diesel Vortex** began with a phishing platform targeting Western logistics companies. Source code recovered by *Have I Been Squatted* exposed not only credential harvesting mechanisms, but operational Telegram logs that revealed Armenian-language coordination tied to freight impersonation, mailbox compromise, and post-access activity consistent with cargo diversion.

The [technical analysis](https://haveibeensquatted.com/blog/diesel-vortex-inside-the-russian-cybercrime-group-targeting-us-eu-freight) published by *Have I Been Squatted* details the inner workings of the **Global Profit** and **MC Profit Always** platform, including Telegram architecture, phishing templates, and victim telemetry, and lots of IOCs. That research establishes the operational capability of **Diesel Vortex**.

A domain embedded within the phishing panel created an infrastructure pivot. The registration record exposed an email identifier. That same identifier appears in the corporate filings of multiple Russian LLCs operating in wholesale trade, warehousing, and transportation. Several of these entities report substantial revenue and share both sector classifications, executive-leadership history and registration addresses.

It is possible that the domain registration reflects negligence, unrelated administrative overlap, or another explanation not visible through open-source analysis. At present, the evidence supports correlation, not attribution.
