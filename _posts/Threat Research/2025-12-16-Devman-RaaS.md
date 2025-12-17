---
title: "How not to run a RaaS Operation"
classes: wide
header:
  teaser: /assets/images/devman/logo.jpg
ribbon: black
description: "Lessons in OPSEC from a sloppy RaaS"
categories:
  - Threat Research
tags:
  - Threat Research
toc: true
---

# OPSEC

Operational Security is something most cybercriminals have not mastered. In fact, a lot of cybercriminals have incredibly sloppy OPSEC. Whether this is from carelessly leaving open-directories exposed, re-using cybercrime handles on clearweb forums, being infected with infostealers, revealing your identity to researchers you “trust”, or just letting them inside your RaaS operation comms platform.

In the cybersecurity community, some threat actors are known for embarrassingly bad OPSEC. Reputations like these come from repeated failures that lead to sensitive information being leaked. Most threat actors hide or ignore these mistakes, but some joke and wear their failures as badges - as if getting burned repeatedly is a personality trait, not a security problem.

[![1](/assets/images/devman/4.png)](/assets/images/devman/4.png){: .full}

# Devman

Devman (also seen operating publicly as [@Inifintyink](https://x.com/Inifintyink) on X) is a Russian-speaking ransomware actor who is attempting to graduate from affiliate work into running his own Ransomware-as-a-Service brand. According to Analyst1’s reporting, he first appeared around mid-April 2025 as an affiliate working primarily with Qilin and DragonForce, before pivoting in July toward running a “Devman” variant built from modified DragonForce code and then formalising that into a public-facing RaaS platform by late September 2025.

On September 22nd 2025, Devman advertised to "become our affiliate this week". Unfortunately, for him and his affiliates, in our blog we have analysed communications extracted from his private Rocket.Chat servers spanning from the 23rd September to 19th October, and separately, the 19th November to 3rd of December. We want to thank the authors of [te.mpe.st](https://te.mpe.st/blog/20251030-devman.html) for publicly sharing the communications from September to October. We were both unaware and shocked that Devman had another Rocket.Chat breach, just a month following his first. 

## Not a great start

On April 7th, Security Researcher Rakesh Krishnan (@RakeshKrish12) shared on [X](https://x.com/RakeshKrish12/status/1909169075365835014?s=20) Devman's first onion site, titled "Welcome to Devman's Place". Cute. 

[![1](/assets/images/devman/9.png)](/assets/images/devman/9.png){: .full}

Interestingly, also very cutesy, Devman provided little writeups explaining how he performed his ransomware attacks:

[![1](/assets/images/devman/10.png)](/assets/images/devman/10.png){: .full}

Noteably, these victims were not associated with "Devman Ransomware" or the "Devman RaaS", but apparently from his time as a Qilin affiliate. A release date was given for "June 20th", when "Devman will release his own RAAS platform!".

On May 20th the first of Devman's mistakes were made public by Rakesh Krishnan, exposing the public IP address associated with his onion site `qljmlmp4psnn3wqskkf3alqquatymo6hntficb4rhq5n76kuogcv7zyd[.]onion`:

[![1](/assets/images/devman/19.png)](/assets/images/devman/19.png){: .full}

## Starting to crumble

On July 1st, [Any.Run](https://any.run/cybersecurity-blog/devman-ransomware-analysis/) detailed an analysis Devman's ransomware. The sample coined "DEVMAN" isn’t so much a “new” ransomware family as a DragonForce cosplay – itself a Conti descendant, with a fresh `.DEVMAN` extension and some branding slapped on top. The ransom note is literally DragonForce’s, and thanks to a builder bug the malware enthusiastically encrypts its own readme.txt. When your standout feature is sabotaging your own payment channel, it might be a bit early to start acting like a serious RaaS kingpin.

## The Second Devman Leak  (19th Nov 25 - 3rd Dec 25)

On December 6th, using what we had learnt from tracking Devman and his infrastructure, we decided to access his Rocket.Chat instance that is used for coordinating his affiliates. Our analysts extracted private communications pertaining to the RaaS operation from his server, for local analysis. We have provided translations for some of the Russian messages below, and where possible, corroborated private communications with Devman's tweets or public victims.

We were able to access this Rocket.Chat instance, hosted on `hXXps://203.91.74[.]97:3000/home`, for 4 days until registration had been locked down and pre-authorisation required. Interestingly, however, the misconfigured server is still internet facing as of 16th December 2025!

[![1](/assets/images/devman/18.png)](/assets/images/devman/18.png){: .full}

On November 19th, multiple of Devman's associates make network connections to a Hong Kong datacenter, and sign up to Devman's supposedly "ultimate secure open-source solution for team communications" Rocket.Chat instance. User's `imploy`, `jokerx`, `fablous` and `donutt` say `qq`.

[![1](/assets/images/devman/5.png)](/assets/images/devman/5.png){: .full}  

A few more people joined in the days that followed, and by November 24th, Devman sends his first message to his affiliates: 

[![1](/assets/images/devman/6.png)](/assets/images/devman/6.png){: .full}  


* devman (Nov 24th 4:19 PM)

```
пм пиши
```

Translated: “Message me in PM / DM me.”

* devman (Nov 24th 7:41 PM)  

```
привет ребята доступы снова в работе за доступами пишите в лс или мне или `jokerx` он или я будем курировать по ним, сейчас в наличии 1 норвегия и 4 америки, важно если у вас есть сетки в работе не пишите мне или джокеру сперва доделайте те сетки.
```

Translated: Hi guys, the accesses are back in work again. For accesses, write in DMs either to me or to `jokerx`; he or I will supervise them. Right now we have 1 (network) in Norway and 4 in America. Important: if you already have networks in progress, don’t write to me or Joker—finish those networks first.

```
так же есть 2 ментовских участка ... тоже в юсе
```

Translated: There are also 2 cop stations ... also in the US

```
все эти доступы должны быть сделанны в течении 2-3 дней потому что во всех есть лдап в фортике - что вам сразу чаще всего дает локал админа или домен админа
```

Translated: All these accesses need to be done within 2–3 days, because all of them have LDAP in FortiGate – which usually gives you local admin right away, or even domain admin

--- 

From these messages alone, we can ascertain some interesting information:

* `devman` - clearly in charge of coordinating work
* `jokerx` - mentioned alongside devman as someone who will "curate/supervise" accesses to victim networks
* `jokerx` appears to have some level of seniority in comparison to the affiliates

`devman` claimed that, on 24th November, they control 1 victim network in Norway and 4 in the states. Apparently, 2 of the US victims are police stations. 

Visiting Devman's most recent and updated leak site (`devmanblggk7ddrtqj3tsocnayow3bwnozab2s4yhv4shpv6ueitjzid[.]onion`), we can see one recent victim from Norway:

[![1](/assets/images/devman/11.png)](/assets/images/devman/11.png){: .full}  

Please note, the date of "December 06, 2025" is incorrect. All victims show this date since the update. 

Additionally, these messages indicate how devman and his affiliates operate - with affiliates being assigned "accesses" to networks, and having to DM `devman` or `jokerx` for new victim networks. `devman` informs affiliates to not request new networks until they have finished compromising existing networks, implying a queue or pipeline of work available to affiliates. 

Finally, we can also ascertain they are gaining initial access via FortiGate, potentially with credential access via LDAP. Noteably, this initial access methods usually facilitates access to a local admin or domain admin, and as a result devman set a required time limit of 2-3 days. 

[![1](/assets/images/devman/7.png)](/assets/images/devman/7.png){: .full}  


* devman (Dec 2nd 09:08AM)

```
италия в наличии теперь тоже
```

Translated: Italy is now also available

```
у кого нету сеток в работе пишите в лс

мне или jokerx
```

Translated: If anyone doesn't have any networks in the works, please message me in private.  Me or `jokerx` now.

On December 2nd, devman shared an Italian network available for a ransomware intrusion. Once again, devman is reminding his affiliates to contact himself or `jokerx` for access. 

[![1](/assets/images/devman/8.png)](/assets/images/devman/8.png){: .full}  

* devman (Dec 3rd 10:03AM)

```
кто амфко ставил или работает по нему в лс отпишите он каким то хуем на блоге оказался кто то из кураторов залистил?
```

Translated: Anyone who installed or works with AMFCO, please write to me in private. It somehow turned out to be a dud on the blog. Did one of the curators scroll through it?

```
по нью хорайзан айди мне в лс их напомни
```

Translated: Remind me of their new Horizon ID in PM

* devman (Dec 3rd 06:24PM)

```
НА БОЛЬНИЦУ ВО ФРАНЦИИ СТАНОВИТСЯ jokerx
```

Translated: `jokerx` is being deployed on a hospital in France.

```
завтра апдейт панели будет и локера она будет лежать многое поменяется с ней
```

Translated: Tomorrow there will be an update to the panel, and the locker will be on it; a lot will change with it.

[![1](/assets/images/devman/12.png)](/assets/images/devman/12.png){: .full}  

Three days later Devman publicly announces the "New panel", which appears to be vibe-coded. 

## Déjà vu (29th Sep 25 -> Oct 19th)

This is not the first time Devman's private RaaS communications have been compromised. With massive thanks to `Neptunian` and `Tail` for making their recent [Rocket.Chat devman leak](https://te.mpe.st/pastes/20251030-DVM-c1.txt). We also recommend reading their [blog post](https://te.mpe.st/blog/20251030-devman.html).  These chats gave further insight into how devman operates and orders his affiliates around. Additionally, we saw massive overlap in usernames across both sets of breached communications.

### Devman's associate usernames 

| Nov - Dec    | Sep - Oct |
| -------- | ------- |
| am  |  am  |
| astonmartin | barinov |
| barinov    | blackwall  |
| blackwall | devman |
| btv | donutt |
| devman | ferrari_boy  |
| donutt | imploy |
| fablous | Kong |
| ferrari_boy | mama |
| imploy | rastafireeye |
| jokerx | tottion |
| Kungfu |  |
| Medveyj.HYU228 |  |

In the most recent breached communications, we discovered the following new usernames: `astonmartin`, `btv`, `fablous`, `jokerx`, `Kungfu` & `Medveyj.HY228`. We can also learn a lot more about how devman and his affiliates operate. We will not be doing a comprehensive analysis of these communications, although we wanted to highlight a few that gave us insight. 

#### Letting down victims

On September 29th, Devman is struggling to find stolen data from the victim which he linked to be `teeuwissen.com.`. 

```
devman (Admin) 10:02 AM —
сука кто локал teeuwissen.com
[Translation] who the hell has local (access) to teeuwissen.com
я не могу их файл листинг найти
[Translation] I can’t find their file listing
они заплатить хотят за дату
[Translation] they want to pay for the data

blackwall 2:38 PM —
Whoever is having problems with the dash can ping me
devman make a private gc with the webdevs
also include me in the maldev gc
```

[![1](/assets/images/devman/16.png)](/assets/images/devman/16.png){: .full}  

On October 6th, this was breach was made public, although this organisation is no longer on the victim list - potentially as they paid... or possibly because Devman still couldn’t find the folder ;)

#### L-L-L-ocker

On October 5th, the user `blackwall` revealed their Windows Locker had been fully deployed. 

```
blackwall 12:11 PM —
windows locker fully deployed
I will remove the buid output, i did it for debugging
https://ibb.co/LVFW4YJ
devman
next is linux locker
```

We can see `blackhall` mentions the "Build Output" will be removed, and was only included for debugging. The emoji's in the output indicate again that LLMs have been used in the development of the site. 

[![1](/assets/images/devman/33.png)](/assets/images/devman/33.png){: .full}  

#### Brewing anger

On October 13th, the user `blackwall` shared a link to the screenshot of an updated locker panel:

[![1](/assets/images/devman/17.png)](/assets/images/devman/17.png){: .full}  


```
blackwall 12:50 PM —
https://i.ibb.co/931CKWQd/image.png

devman (Admin) 2:52 PM —
OK NOW FROM NOW AND ON
WHO WILL NOT USE ROCKET CHAT WILL SUFFER SEVERE PUNISHMENTS
because for fuck sake we will literally do anything rather than work in rocket
rastafireeye is now in charge of asisgning you with targets if you want to group into a team of two consult with volt
for custom c2 or infrastructure ping me or blackwall
```

Unfortunately Devman's persistence to use broken and misconfigured Rocket.Chat servers is unfortunately what has led to successive breaches. If his affiliates hadn't listened to him here, they might have escaped 

#### Micro-management

On October 15th, Devman tries to “organise” affiliates by demanding everyone list their working hours. This is, notably, the sort of administrative overhead typically seen in customer support teams - not extortion operations.

```
devman (Admin) 5:35 AM —
IMPORTANT! ВАЖНО!
[Translation] IMPORTANT! IMPORTANT!
please write in your bio your hours of work
ребята напишите с какого и по какое время работаете
[Translation] guys, write the hours you work (from what time to what time)
чтобы я знал кого куда ставить
[Translation] so I know where to assign whom
```

It is difficult to overstate how funny it is to watch a ransomware operator reinvent basic workforce management. The only thing missing is a staff rota pinned to the fridge and a reminder to “log time in Jira”.

On October 16th, Devman tweets the kind of sentence you expect from a stressed-out shift supervisor, not a RaaS owner:

[![1](/assets/images/devman/13.png)](/assets/images/devman/13.png){: .full}  

#### Embarrassing

On October 18th, Devman proclaims that he is “a machine” in response to a victim explaining that neither the link nor the email address worked. This is an interesting claim, given that we are now reading his internal communications in full.

```
devman (Admin) 5:17 AM —
Our ID is: . We also can't access our corporate email due to this attack. We tried emailing the email address on the ransom note and that didn't work nor does the chat link you—
ебать я машина нахуй
[Translation] fuck, I’m a machine

blackwall 7:46 AM —
which corp is this
if that's the case I have ideas to fix this
since many companies are not allowed to access the darkweb
we can host the /chat system on clearnet

devman (Admin) 9:44 AM —
n**ga wtf
blackwall btw we are updating LINUX adding 2 new distros
and esxi will get updated
```

In response, the user `blackwall` enthusiastically replies that they should host the `/chat` URI endpoint for their victim site to be hosted on the clearnet. Devman was cleary confused with this response.

Also on October 18th, Devman encouraged one of his closer associates, `blackwall` to attack what they suspected to be a Israeli honeypot.   

```
blackwall 1:45 PM —
no it wasn't, but the access itself is useless and very limited
the honeypot was fucking israeli

devman (Admin) 1:46 PM —
you sure?

blackwall 1:46 PM —
it's an rce on a random ass server for [REDACTED_URL]

devman (Admin) 1:47 PM —
ok lets exploit it
why not
...

blackwall 1:47 PM —
empty af, I'm looking for bigger fish
I'm mass exploiting rn
```

The willingness to “ok lets exploit it why not” against a suspected Israeli honeypot is, from an operational security perspective, less “risk appetite” and more “touching the hot stove again to make sure it’s still hot.” This kind of impulsive exploitation strongly suggests a group chasing opportunities out of frustration rather than operating with discipline or following a playbook you'd expect to see with well-known groups.

Minutes later from this exchange, Devman mentions in conversation that the group are leveraging the [Sliver C2](https://github.com/BishopFox/sliver) framework during their operations:

```
blackwall 1:50 PM —
add me in kova gc

devman (Admin) 1:50 PM —
will forward sliver access abbit later

blackwall 1:51 PM —
drop them all in kova gc
```

#### Past OPSEC Ls

Previously, Devman has exposed his leak site on the IP address `86.106.85[.]183`:

[![1](/assets/images/devman/20.jpg)](/assets/images/devman/20.jpg){: .full}   

From the above we can see source of the "DEVMAN 2.0 - Leaked Data" site. Interestingly, this IP address was also hosting a Sliver C2 server on port `31337`:

[![1](/assets/images/devman/21.jpg)](/assets/images/devman/21.jpg){: .full}   

# Conclusion

Devman would like to present a polished, professional RaaS operation that is complete with branding, a leak blog, and a growing victim list. There are clearly impacted organisations on the site, often aligning with “easy target” profiles (notably healthcare in regions with lower cybersecurity maturity). However, despite the site, victim data is still not meaningfully uploaded or accessible; at present it functions more as a claims board than leak platform.

More importantly, since the start of the “devman” brand, recurring sysadmin shortcomings and careless OPSEC have repeatedly exposed infrastructure and coordination channels. In a trust-driven RaaS ecosystem, that’s not a cosmetic issue: unstable and compromised backend systems degrade affiliate confidence and reduce the operator’s ability to control narratives, negotiations, and outcomes. Devman’s insistence on centralising activity onto insecure Rocket.Chat communications platform, coupled with repeated security failures (and a untrustworthy circle of affiliates), has provided a consistent and recoverable evidence trail that provides insight into how Devman operates.

## IOCs

| IP | ASN | Context |
|----------|-----|---------|
| 203.91.74[.]97 |  400619 | Rocket.Chat | 
| 86.106.85[.]183 | 9009 |  Sliver C2 (31337) |
| 86.106.85[.]183 | 9009 |  Leak Site |

[Devman Rocket.Chat Export](https://raw.githubusercontent.com/ctrlaltint3l/intelligence/refs/heads/main/devman/devman-announcements-rocket.chat)

## Thanks

We’d like to thank researchers `Neptunian` & `Tail` for [their incredible research](https://te.mpe.st/blog/20251030-devman.html). Additionally, we'd like to recongoise @RakeshKrish12 and @GangExposed_RU for their earlier work highlighting OPSEC failures and for sharing communications. Without their contributions, our findings might look like a stroke of luck, when in reality they reflect systemic operational security weaknesses driven by poor IT and system administration practices.



