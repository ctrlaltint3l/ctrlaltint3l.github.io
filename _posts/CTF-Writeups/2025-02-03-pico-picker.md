---
title: "PicoCTF: Picker I/II/III/IV {Medium} {Reverse engineering & Binary exploit}"
classes: wide
header:
  teaser: /assets/images/ctf-writeups/utctf2020/logo.png
ribbon: ForestGreen
description: "Walkthrough for the Picker I/II/III/IV series that consist of three reverse engineering and one binary exploit challenge."
categories:
  - CTF Writeup
tags:
  - CTF
  - Writeup
  - Reverse Engineer
---

# Overview

This is a walkthrough for the Picker I/II/III/IV series that consist of three reverse engineering and one binary exploit challenge.

## **Picker I**

1️⃣ **Downloading the source code**
- Reviewing the source code shows the function win() which prints out the contents of ‘flag.txt’ in hex format.
![Picker screenshot](/assets/images/picker-1.webp)

- The comment in this function states that this functionality can be replicated by creating a ‘flag.txt’ file within the directory of the picker python script
  
2️⃣ **Replicating flag.txt output**
- After creating the flag.txt file locally and inputting some text I then modified the python script to call the win() function in the while true loop
  
```ruby
while(True):
try:
win()
print(‘Try entering “getRandomNumber” without the double quotes…’)

└─$ python picker-2.py
0x6a 0x61 0x62 0x62 0x61
Try entering “getRandomNumber” without the double quotes…
```

- As seen this reads the flag file and outputted the contents. Therefore, successfully replicating the service running on the challenge.
Additionally, the function source code uses — eval(user_input + ‘()’)” which makes it vulnerable to the user simply calling the win function.

3️⃣ **Taking this information I then connected to the service using:**

![Picker screenshot](/assets/images/picker-2.webp)

```ruby
Output:
0x70 0x69 0x63 0x6f 0x43 0x54 0x46 0x7b 0x34 0x5f 0x64 0x31 0x34 0x6d 0x30 0x6e 0x64 0x5f 0x31 0x6e 0x5f 0x37 0x68 0x33 0x5f 0x72 0x30 0x75 0x67 0x68 0x5f 0x36 0x65 0x30 0x34 0x34 0x34 0x30 0x64 0x7d
```
- This successfully called the win() function and read the contents of the servers flag.txt file.
  
4️⃣ **Finally the hex output needs to be converted which can simply be done by manually removing the “0x”s or the following simple python script:**
```ruby
hex_values = “0x70 0x69 0x63 0x6f 0x43 0x54 0x46 0x7b 0x34 0x5f 0x64 0x31 0x34 0x6d 0x30 0x6e 0x64 0x5f 0x31 0x6e 0x5f 0x37 0x68 0x33 0x5f 0x72 0x30 0x75 0x67 0x68 0x5f 0x36 0x65 0x30 0x34 0x34 0x34 0x30 0x64 0x7d”
print(bytes.fromhex(hex_values.replace(“0x”, “”).replace(“ “, “”)).decode())
```
🚩 This produced the final flag: **picoCTF{4_d14m0nd_1n_7h3_r0ugh_6e04440d}**

## **Picker 2**

1️⃣ **Downloading the source reveals this is a similar python script to the previous except for some sanitisation changes:**

![Picker screenshot](/assets/images/picker-3.webp)

- The new filter (user_input) function verifies the content of the users input to exclude references to win which is the function used to read the ‘flag.txt’ file. This makes it apparent that we need to bypass this new function to be able to still call win().
  
2️⃣ **Testing payloads**
- The initial payload tried was alternative formatting of the word ‘win’ such as case insensitive ‘WIN’, ‘WIn’. Both of which failed as only lowercase win() exists.
- Researching how to bypass this kind of sanitisation in python scripts I came across - https://hackmd.io/@yqroo/Censorship-series
- Although given this challenge scenario we aren’t able to reference the name of our function so instead I attempted to convert the word “win” to its decimal values. This produced the following payload:
- globals()[chr(119) + chr(105) + chr(110)]()
  
3️⃣ **Testing concatenated payload**

![Picker screenshot](/assets/images/picker-4.webp)

- Output:
```ruby
0x70 0x69 0x63 0x6f 0x43 0x54 0x46 0x7b 0x66 0x31 0x6c 0x37 0x33 0x72 0x35 0x5f 0x66 0x34 0x31 0x6c 0x5f 0x63 0x30 0x64 0x33 0x5f 0x72 0x33 0x66 0x34 0x63 0x37 0x30 0x72 0x5f 0x6d 0x31 0x67 0x68 0x37 0x5f 0x35 0x75 0x63 0x63 0x33 0x33 0x64 0x5f 0x62 0x39 0x32 0x34 0x65 0x38 0x65 0x35 0x7d
```

4️⃣ **This worked successfully and read the flag.txt file and outputted in hex formatting. Using our previous python script we can strip this and convert it to a readable string.**

🚩 Final flag: **picoCTF{f1l73r5_f41l_c0d3_r3f4c70r_m1gh7_5ucc33d_b924e8e5}**

## **Picker 3**

1️⃣ **Reviewing the new source code we can see that the previous method used would no longer work due the ‘Illegal value’ response being introduced which will pick up on the input being too long.**

2️⃣ **Within the write_variable() method a vulnerability exists in the line**

- exec(‘global ‘+var_name+’; ‘+var_name+’ = ‘+value)
- The use of global (which was used in the last challenge) allows modifications to global variables from within functions. Therefore this can be exploited to modify another function that is called in the program.
  
3️⃣ **By using the write_variable() function we can pass it the value ‘win’. Then when we call this using read_variable() it will execute the win() function and output the flag.txt data.**

![Picker screenshot](/assets/images/picker-5.webp)

```ruby
0x70 0x69 0x63 0x6f 0x43 0x54 0x46 0x7b 0x37 0x68 0x31 0x35 0x5f 0x31 0x35 0x5f 0x77 0x68 0x34 0x37 0x5f 0x77 0x33 0x5f 0x67 0x33 0x37 0x5f 0x77 0x31 0x37 0x68 0x5f 0x75 0x35 0x33 0x72 0x35 0x5f 0x31 0x6e 0x5f 0x63 0x68 0x34 0x72 0x67 0x33 0x5f 0x32 0x32 0x36 0x64 0x64 0x32 0x38 0x35 0x7d
```
4️⃣ **Using our previous python script we can strip this and convert it to a readable string.**

🚩 Flag: **picoCTF{7h15_15_wh47_w3_g37_w17h_u53r5_1n_ch4rg3_226dd285}**
- Note: Alternatively using ctrl+f in cyber chef and simply replacing ‘0x’ with ‘’ may be a faster method for converting the hex output.

## **Picker IV**

1️⃣ **The final challenge of this series was a different category (binary exploitation). I started by reviewing the source code of the binary file.**
- Opening up the source code we once again see the win() function present
  
![Picker screenshot](/assets/images/picker-6.webp)

- This implies we will once again need to get the program to execute this function in order to read the flag.txt file contained on the server.
- The program asks for a hex value to be inputted for the program to jump to.
  
2️⃣ Binary file analysis
- Based on this I opened the file in binary ninja to try and find the location of the win function.
  
![Picker screenshot](/assets/images/picker-7.webp)

- The win function was stored at ‘0040129e’
  
3️⃣ Attempting input
- As instructed by the program the input should exclude ‘0x’ therefore we pass it ‘40129e’
  
![Picker screenshot](/assets/images/picker8.webp)

- This shows the input caused the program to successfully call the win function and attempt to read the file. Although this was our local binary so therefore failed.
  
4️⃣ Passing input logic
- The final part was to take our working input and pass it to the server that contained the flag.txt file.
  
![Picker screenshot](/assets/images/picker-9.webp)

- This read the file and outputted the final flag of this challenge series
- 🚩 Flag: **picoCTF{n3v3r_jump_t0_u53r_5uppl13d_4ddr35535_01672a61}**

# Thanks for reading!
