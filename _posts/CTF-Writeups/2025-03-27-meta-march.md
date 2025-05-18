---
title: "MetaCTF: Flash CTF"
classes: wide
header:
  teaser: /assets/images/ctf-writeups/meta-march.jpg
ribbon: ForestGreen
description: "CTF writeups for two of the challenges in the MetaCTF that was hosted on the 27/03."
categories:
  - CTF Writeup
toc: true
---

Below are the writeups for two of the challenges in the MetaCTF that was hosted on the 27/03 with a 2 hour time frame.
- Full writeups of all challenges can be found at: https://metactf.com/blog/tag/flash-mar2025/

# **Challenge 1**
- **Category — OSINT**
- **Title — Ms Blue Sky**
- **Challenge description:**
- Your target registered on some social platform on March 18th, 2025, and goes by the username `allnaturalhacking`
Our intelligence tells us she encoded a flag in one of her posts using Base32, can you find it?

# **Solution**

- 1️⃣ Using sherlock to search social medias for the given handle
> └─$ sherlock allnaturalhacking

- 2️⃣ This produced the results which based on the challenge name returned a social media platform of relevance “BlueSky”:

![MetaCTF screenshot](/assets/images/ctf-writeups/meta/march/meta_march_1.webp)

- 3️⃣ Visited profile page and found the following post which appeared to contain base32:

![MetaCTF screenshot](/assets/images/ctf-writeups/meta/march/meta_march_2.webp)

- 4️⃣ Decoded using cyberchef and got the flag:

![MetaCTF screenshot](/assets/images/ctf-writeups/meta/march/meta_march_3.webp)

- 🚩 MetaCTF{4in7_@_c10ud_1n_51gh7}

# **Challenge 2**
- **Category — Crypto**
- **Title — Shifty XOR**
- **Challenge description:**
- I developed a fairly simple many to one one way function, simply shift and XOR. Can you recover the plaintext?

# **Solution**

- 1️⃣ The script given to encode the plain text was as follows:

![MetaCTF screenshot](//assets/images/ctf-writeups/meta/march/meta_march_4.webp)

- 2️⃣ Knowing this seems to be a relatively straight forward script and given the time constraints resorted to GPT to produce a reverse brute force script:

![MetaCTF screenshot](/assets/images/ctf-writeups/meta/march/meta_march_5.webp)

- 3️⃣ This produced the entire brute force output which was very unreadable so decided to redirect the output to a txt file with the following command:
> └─$python test.py > output.txt

- 4️⃣ Utilising grep we can search for our flag with the following command:
> └─$grep -a “Meta” output.txt

- 5️⃣ Final decoded message and flag:

![MetaCTF screenshot](/assets/images/ctf-writeups/meta/march/meta_march_6.webp)

- 🚩 MetaCTF{tw0_w4y_funct10n_m0r3_l1k3_i7}
- Thanks for reading, worth noting I was extremely close to getting the reverse engineering “collecting seashells” challenge had the understanding just didn’t get the exploit working in time..

![MetaCTF screenshot](/assets/images/ctf-writeups/meta/march/meta_march_7.webp)
