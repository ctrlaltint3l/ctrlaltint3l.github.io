---
title: "ErrTraffic Under the Hood: A look at the source code"
classes: wide
header:
  teaser: /assets/images/err/logo.png
ribbon: black
description: "Investigating vulnerabilities in the ErrTraffic panel"
categories:
  - Threat Research
tags:
  - Threat Research
toc: true
---

# ErrTraffic

Inspired by Censys' blog [ErrTraffic: Inside a GlitchFix Attack Panel](https://censys.com/blog/errtraffic-inside-glitchfix-attack-panel), we wanted to take a poke at the source-code but we had no idea how censys gained it. From Censys' blog we can see the panel advertised for sell by user `LenAI` on a cybercrime forum. 

ErrTraffic is a multi-platform (Windows, MacOS, Android, Linux) Traffic Distribution System (TDS) that allows threat actors to easily deploy ClickFix-style lures hosting malware via externally hosted JavaScript on threat actor owned or compromised websites sites. 

We always approach threat research with an attacker mindset. In this blog, we'll walk through these discoveries and explain our process of poking around, analysing the source code, deploying locally, identifying vulnerabilities, and developing simple POCs to pwn ErrTraffic. 

## Vulnerabilities Overview

Our analysis of ErrTraffic uncovered several recurring design flaws that could to full panel compromise, under certain conditions:

- Authenticated file upload paths that allow arbitrary code execution
- An exposed `install.php` endpoint that enables panel reinstallation and authentication bypass
- Database-controlled file paths that can be abused for local file disclosure via path traversal

In the sections below, we walk through how each issue was identified and provide POC videos from our deployments!

# Source Acquisition

In order to start testing versions of ErrTraffic, we'd need to get our hands on the source code to deploy locally. We saw Censys' had the source, and it was being advertised on cybercrime forums, so it must be out there! There are few ways we could approach getting our hands on this. 

* OSINT
* Scanning

Scanning ended up being successful as threat actors are predictable creatures. 

## Scanning

To scan ErrTraffic webservers for exposed panels, we first have to find the ErrTraffic web-servers.

Censys provided a query to identify ErrTraffic servers:

```
web.endpoints.http.headers: (key: "Set-Cookie" and value: "errtraffic_session=")
```

Additionally, when you visit an ErrTraffic site, a HTTP request is made to `/admin/styles.css`. We can leverage the hash of the `styles.css` page hunt for additional panels on URLScan:

[![1](/assets/images/err/1.png)](/assets/images/err/1.png){: .full}  

Once we have a list of URLs, we can use `ffuf` with a word list that checks common filenames like `panel.zip`, `панель.zip`, `errtraffic.7z`, and many other variations.

Using a quick one-liner we can loop through each "target" and run a `ffuf` command:

```bash
while read -r url; do ffuf -u "http://$url/FUZZ" -w /path/to/wordlist.txt -fc 401,403; done < targets.txt
``` 
After letting this run we got 1 hit!

[![1](/assets/images/err/2.png)](/assets/images/err/2.png){: .full}  

# Source Code Analysis (v2)

After extracting the panel archive, we find two files in the root of the panel directory: `install.php` and `index.php`. The below source-code tree reflects that shown on the Censys article.  

```
.
├── panel
│  ├── admin
│  │  ├── auth.php
│  │  ├── delete_file.php
│  │  ├── index.php
│  │  ├── login.php
│  │  ├── logout.php
│  │  ├── partials
│  │  │  ├── analytics.php
│  │  │  ├── files.php
│  │  │  ├── script.php
│  │  │  └── settings.php
│  │  ├── set_active_file.php
│  │  ├── styles.css
│  │  ├── update_file.php
│  │  ├── update_js.php
│  │  ├── update_password.php
│  │  ├── update_script.php
│  │  ├── update_settings.php
│  │  └── upload_file.php
│  ├── api
│  │  ├── css.js
│  │  ├── css.js.php
│  │  ├── download.php
│  │  ├── generate-download-token.php
│  │  ├── icons
│  │  │  ├── brave.ico
│  │  │  ├── chrome.ico
│  │  │  ├── firefox.ico
│  │  │  ├── opera.ico
│  │  │  └── vivaldi.ico
│  │  └── log.php
│  ├── config
│  │  └── config.php
│  ├── index.php
│  ├── install.php
│  └── uploads
│      ├── android
│      ├── mac
│      └── windows
```

## install.php (v2)

[![1](/assets/images/err/3.png)](/assets/images/err/3.png){: .full}  


ErrTraffic has a few "configuration" items, the hostname & credentials for the database and panel that are stored within the file `/panel/config/config.php` which are supplied by the user in the set up process via `/install.php`.

Specifically the user will fill out a form submitting the database hostname, database name, database credentials and "admin" account for the panel, via a POST request to `/install.php`. We can see the MySQL PDO driver is used to connect to the MySQL server. The panel credentials are stored in the database.

```php
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $dbHost = trim($_POST['db_host'] ?? 'localhost');
    $dbName = trim($_POST['db_name'] ?? '');
    $dbUser = trim($_POST['db_user'] ?? '');                    // Threat actor submitting configuration manually on /install.php
    $dbPass = (string)($_POST['db_pass'] ?? '');
    $panelUrl = trim($_POST['panel_base_url'] ?? '');
    $adminUser = trim($_POST['admin_user'] ?? 'admin');
    $adminPass = (string)($_POST['admin_pass'] ?? '');

    if ($dbName === '' || $dbUser === '' || $adminUser === '' || $adminPass === '') {
        $errors[] = 'Заполните все обязательные поля.';
    }

    if (!$errors) {
        try {
            $dsn = 'mysql:host=' . $dbHost . ';dbname=' . $dbName . ';charset=utf8mb4';       // Testing database credentials
            $pdo = new PDO($dsn, $dbUser, $dbPass, [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES => false,
            ]);

 
//[...REDACTED...]

// Пишем config.php (генерируем APP_KEY до создания админа, чтобы использовать его при хешировании пароля)
$appKey = bin2hex(random_bytes(32));
$configPhp = <<<'PHP'
<?php
// ErrTraffic v2 - базовая конфигурация (создан install.php)                 

const ERRTRAFFIC_DB_HOST = '%DB_HOST%';
const ERRTRAFFIC_DB_NAME = '%DB_NAME%';
const ERRTRAFFIC_DB_USER = '%DB_USER%';
const ERRTRAFFIC_DB_PASS = '%DB_PASS%';

const ERRTRAFFIC_APP_KEY = '%APP_KEY%';

//[...REDACTED...]
PHP;

$configPhp = str_replace(                                   // Fills out config values into $configPhp that will be written to disk
  ['%DB_HOST%', '%DB_NAME%', '%DB_USER%', '%DB_PASS%', '%APP_KEY%'], 
  [addslashes($dbHost), addslashes($dbName), addslashes($dbUser), addslashes($dbPass), $appKey],   
  $configPhp
);

file_put_contents(__DIR__ . '/config/config.php', $configPhp); // New configuration written to disk. 
//[...REDACTED...]
```

This is not an unusual way to setup or configure a webapp to install, but as the `/install.php` isn't deleted and threat actors are simple creatures who will forget to delete this. Sadly, in the latest version this is password protected:


[![1](/assets/images/err/6.png)](/assets/images/err/6.png){: .full}  


## upload_file.php (v2)

As part of a ClickFix TDS, you'd expect some capability to upload or stage malware/payloads that can be hosted on sites with the ErrTraffic lure. Thankfully, in the v2 source, there are no restrictions on files that can be uploaded. 

The name of the malware is always chosen randomly and set in the `$storedName` variable, keeping the original file extension. 

```php
//[...REDACTED...]
$origName = $_FILES['file']['name'];
$size = (int)$_FILES['file']['size'];
$ext = pathinfo($origName, PATHINFO_EXTENSION);
$storedName = time() . '_' . bin2hex(random_bytes(4)) . ($ext ? '.' . $ext : '');                      // File name of malware stored on disk (NOT ORIGINAL FILE NAME)

$targetDir = ERRTRAFFIC_UPLOAD_DIR . '/' . $os;                                                        
if (!is_dir($targetDir)) {                                                                             // Create relevant OS directory, if not already present
    mkdir($targetDir, 0775, true);
}
$targetPath = $targetDir . '/' . $storedName;

if (!move_uploaded_file($_FILES['file']['tmp_name'], $targetPath)) {                                   // Upload file 
    $_SESSION['et_flash_files'] = ['type' => 'error', 'msg' => 'Не удалось сохранить файл'];
    header('Location: /admin/index.php?tab=files');
    exit;
}

$hashMd5 = md5_file($targetPath) ?: null;

// Проверка дубликата по md5: если уже есть такой же файл для этой ОС, не создаём новую запись
if ($hashMd5 !== null) {
    $dupStmt = $pdo->prepare('SELECT COUNT(*) FROM et_files WHERE os = :os AND hash_md5 = :m');     // Get hash
    $dupStmt->execute([':os' => $os, ':m' => $hashMd5]);
    if ((int)$dupStmt->fetchColumn() > 0) {
        // Удаляем только что загруженный физический файл, чтобы не захламлять диск
        @unlink($targetPath);
        $_SESSION['et_flash_files'] = ['type' => 'error', 'msg' => 'Такой файл уже загружен для этой ОС (совпадает md5)'];
        header('Location: /admin/index.php?tab=files');
        exit;
    }
}

$stmt = $pdo->prepare('INSERT INTO et_files (os, filename, original_name, size, hash_md5) VALUES (:os, :f, :o, :s, :m)');  // Insert uploaded file information to DB
$stmt->execute([
    ':os' => $os,
    ':f'  => $storedName,
    ':o'  => $origName,
    ':s'  => $size,
    ':m'  => $hashMd5,
]);
```

# Authenticated file upload to RCE

## Version 2

As shown above, ErrTraffic v2 performs no server-side validation on uploaded files, allowing direct upload of executable PHP payloads.

<center>
<video width="1080" height="720" controls="controls">
<source src="/assets/images/err/4.mp4" type="video/mp4">
</video>
</center>

Notably, we also analysed source code of newer versions of ErrTraffic. These versions had additional restrictions that made it more fiddly to bypass. Later, we will discuss techniques to bypass the new "restrictions", allowing RCE regardless of the version.

## ErrTraffic V2.1

The developer(s) put in the work to harden new uploads… then apparently decided that was enough effort for one release. The file replacement endpoint (`update_file.php`) received zero love - no re-validation, no extension checks, nothing. Good job! Enter `update_file.php` - the endpoint that lets an authenticated admin replace an already-uploaded payload with a completely different file including a `PHP` file while keeping the same database record.

```php
// Get original extension from the user controlled filename
$origName = $_FILES['file']['name'];
$ext = pathinfo($origName, PATHINFO_EXTENSION);

// Generate new storage name using that unverified extension
$stored = time() . '_' . bin2hex(random_bytes(4)) . ($ext ? '.' . $ext : '');

$targetPath = ERRTRAFFIC_UPLOAD_DIR . '/' . $os . '/' . $stored;

//  The file is moved to the web-accessible directory 
// without checking if $ext is 'php', 'phtml', or 'exe'.
if (move_uploaded_file($_FILES['file']['tmp_name'], $targetPath)) {
    // File is now live on the server
    $upd = $pdo->prepare('UPDATE et_files SET filename = :f WHERE id = :id');
    $upd->execute([':f' => $stored, ':id' => $id]);
}
```

<center>
<video width="1080" height="720" controls="controls">
<source src="/assets/images/err/7.mp4" type="video/mp4">
</video>
</center>

# Rogue database

When `install.php` is left exposed, an attacker can reinitialize the panel with a database they control. This effectively resets authentication and hands full administrative access, and this file is not deleted by default on earlier versions.

We set up a ErrTraffic server that has the domain `sadrussianserver.xyz` and a rogue MySQL database on the domain `mysecretdatabase.com`. These were controlled and owned by us. 

> When using a rogue database, original data used will not be visible after authentication. Regardless, this same access could allow RCE or path traversal. 

## Broken Access Control

After quite a bit of testing, we managed to set up a remote MySQL server and test our hijacking theory on our deploy ErrTraffic panel: 

1. Create a MySQL server and set credentials up for a database
2. Fill in your hostname, database name, database credentials & panel credentials to `install.php`
3. Authenticate

<center>
<video width="1080" height="720" controls="controls">
<source src="/assets/images/err/6.mp4" type="video/mp4">
</video>
</center>

## Path Traversal

Earlier we abused the file upload capability to upload a webshell and gain RCE. When you upload "malware" to ErrTraffic, these file names paths and hashes are reflected within the MySQL database - although the files reside on disk of the web-server - not on the database. 

The MySQL database contains the filename that PHP uses to read the "malware" that is downloaded for the ClickFix lure, and we can control the MySQL database. These file references are stored within the `et_files` table. We can reference the below snippet from `upload_file.php`:

```php
$stmt = $pdo->prepare('INSERT INTO et_files (os, filename, original_name, size, hash_md5) VALUES (:os, :f, :o, :s, :m)');
$stmt->execute([
    ':os' => $os,
    ':f'  => $storedName,
    ':o'  => $origName,
    ':s'  => $size,
    ':m'  => $hashMd5,
]);   // Insert uploaded file information to DB
```

This is possible because `$file['filename']` from the database is not validated and with control of the database we control which files are downloaded 

```php
$filePath = ERRTRAFFIC_UPLOAD_DIR . '/' . $os . '/' . $file['filename'];
if (!is_file($filePath)) {
    http_response_code(404);
    exit('File missing');
}
``` 

In the below video we demonstrate uploading "malware" to the ErrTraffic website that we have hijacked with our rogue DB. We will use our direct access to MySQL to edit the internal file path, embedding a path traversal payload to read `/etc/passwd`:

<center>
<video width="1080" height="720" controls="controls">
<source src="/assets/images/err/5.mp4" type="video/mp4">
</video>
</center>

For example, if authenticated (potentially via the rogue database), you could fill out MySQL database with the files being path-traversal payloads in order to dump source code:

[![1](/assets/images/err/5.png)](/assets/images/err/5.png){: .full}  


## update_js.php, A little bit of chaos 

We examined the update JavaScript functionality. While no critical vulnerabilities were found, we identified features not accessible via the UI, such as the ability to update the malicious JavaScript injected into compromised sites. This is interesting because, if you took over a live panel, you could trigger alert boxes to warn visitors though we don't recommend this, as it requires unauthorized access.

```php
$jsSource = (string)$_POST['js_source'];
$scriptPath = __DIR__ . '/../api/css.js';

file_put_contents($scriptPath, $jsSource);
```

# Aeternum C2 BotNet Loader

On the updated ErrTraffic panel, the one we named v2.1, there was an advertisements for "Aeternum C2 BotNet Loader":

[![1](/assets/images/err/7.png)](/assets/images/err/7.png){: .full}  

This is a command-and-control (C2) panel that reportedly uses blockchain smart contracts as its command database.

[![1](/assets/images/err/8.png)](/assets/images/err/8.png){: .full}  

At the bottom of the page is contact details for `LenAI`, the same cybercriminal selling ErrTraffic. 

[![1](/assets/images/err/9.png)](/assets/images/err/9.png){: .full}  



# Conclusion

ErrTraffic’s recurring flaws feel less like oversights and more the result of AI-assisted development. Additionally, the username of the developer, `LenAI`, may also suggest this was developed using the assistance of an LLM. 

Although in the "v2" version there was no restrictions or hardening, making it trivial to gain authenticated RCE, we observed in newer versions the actor had attempted to, implying the developer was aware of issues. However, due to the obvious logic gaps, attempts to fix certain vulnerabilities were futile. 

For defenders, this is useful context. Tooling like ErrTraffic may lower the barrier to entry for attackers, but it also introduces systemic weaknesses. As AI-assisted crimeware becomes more common, these predictable failures are likely to become an increasingly common. 
