# Between 0&1

*We managed to infiltrate UnDuplicitous Corp and obtained this image (something like that, original description lost)*  

------

We are given a `dump`. Running `file` on it does not give any useful output, only `data`

But if we are to run `strings` on it, we will see messages such as `Windows could not start due to an error while booting from a RAMDISK.`, which suggest that it is a **memory dump**.

Running a quick `imageinfo` on it:

```bash
volatility -f dump imageinfo

INFO    : volatility.debug    : Determining profile based on KDBG search...
          Suggested Profile(s) : WinXPSP2x86, WinXPSP3x86 (Instantiated with WinXPSP2x86)
                     AS Layer1 : IA32PagedMemoryPae (Kernel AS)
                     AS Layer2 : FileAddressSpace (/mnt/d/Desktop/Cybersecurity/Competitions/CDDC 2020/dump)
                      PAE type : PAE
                           DTB : 0x31c000L
                          KDBG : 0x80545ce0L
          Number of Processors : 1
     Image Type (Service Pack) : 3
                KPCR for CPU 0 : 0xffdff000L
             KUSER_SHARED_DATA : 0xffdf0000L
           Image date and time : 2020-06-27 18:52:08 UTC+0000
     Image local date and time : 2020-06-28 02:52:08 +0800
```

Looks like it is a Windows xp dump (`WinXPSP2x86`)

Let's run some basic enumeration commands and... 

```bash
volatility -f dump --profile=WinXPSP2x86 consoles
Volatility Foundation Volatility Framework 2.6
**************************************************
ConsoleProcess: csrss.exe Pid: 528
Console: 0x4f23b0 CommandHistorySize: 50
HistoryBufferCount: 2 HistoryBufferMax: 4
OriginalTitle: %SystemRoot%\system32\cmd.exe
Title: mdd - 0.00% complete
AttachedProcess: mdd.exe Pid: 3500 Handle: 0x7b4
AttachedProcess: cmd.exe Pid: 3220 Handle: 0x7d4
----
CommandHistory: 0x4fd380 Application: mdd.exe Flags: Allocated
CommandCount: 0 LastAdded: -1 LastDisplayed: -1
FirstCommand: 0 CommandCountMax: 50
ProcessHandle: 0x7b4
----
CommandHistory: 0x4f4d88 Application: cmd.exe Flags: Allocated, Reset
CommandCount: 2 LastAdded: 1 LastDisplayed: 1
FirstCommand: 0 CommandCountMax: 50
ProcessHandle: 0x7d4
Cmd #0 at 0x13232d8: cd \
Cmd #1 at 0x1323340: mdd.exe -o dump
----
Screen 0x4f2ab0 X:80 Y:300
Dump:
Microsoft Windows XP [Version 5.1.2600]
(C) Copyright 1985-2001 Microsoft Corp.

C:\Documents and Settings\User>cd \

C:\>mdd.exe -o dump
 -> mdd
 -> ManTech Physical Memory Dump Utility
    Copyright (C) 2008 ManTech Security & Mission Assurance

 -> This program comes with ABSOLUTELY NO WARRANTY; for details use option `-w'
    This is free software, and you are welcome to redistribute it
    under certain conditions; use option `-c' for details.

 -> Dumping 255.42 MB of physical memory to file 'dump'.
**************************************************
ConsoleProcess: csrss.exe Pid: 528
Console: 0x13233d8 CommandHistorySize: 50
HistoryBufferCount: 1 HistoryBufferMax: 4
OriginalTitle: C:\Documents and Settings\User\Desktop\svchost.exe
Title: C:\Documents and Settings\User\Desktop\svchost.exe
AttachedProcess: svchost.exe Pid: 3464 Handle: 0x428
----
CommandHistory: 0x132f840 Application: svchost.exe Flags: Allocated
CommandCount: 0 LastAdded: -1 LastDisplayed: -1
FirstCommand: 0 CommandCountMax: 50
ProcessHandle: 0x428
----
Screen 0x1323b00 X:80 Y:300
Dump:
01000011010001000100010001000011001100100011000001111011010001010111011000110001
01100100011001010110111001100011011001010101111101001000001100010110010001100100
01100101011011100101111101000010011001010111010001110111011001010110010101101110
0101111100110000001001100011000101111101
```

Hmmm interesting, there is a huge chunk of binary in the command history. 

Decoding it reveals the flag:

```
CDDC20{Ev1dence_H1dden_Between_0&1}
```

