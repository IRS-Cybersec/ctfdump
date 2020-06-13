# Big Brother Secrets

## 350 Points - Forensics (Memory Forensics)

Greetings once again Agent
Snail Speed Corp seems to be purchasing a file that we suspect contains highly sensitive information concerning national security. One of our agents, posing as a potential client, has managed to infiltrate their Headquarters and did a quick memory dump of one of their computers responsible for the purchase. They seem to have received the file through a secure channel. Analyse it and see what you can find.

Best of luck, agent

We are given a memory dump, and imageinfo using volatility reveals the following:

```
          Suggested Profile(s) : Win7SP1x64, Win7SP0x64, Win2008R2SP0x64, Win2008R2SP1x64_23418, Win2008R2SP1x64, Win7SP1x64_23418
                     AS Layer1 : WindowsAMD64PagedMemory (Kernel AS)
                     AS Layer2 : FileAddressSpace (/mnt/d/Desktop/Cybersecurity/Cybersec Self-Made Stuff/Sieberrsec CTF 2020/Windows 7 iso/TKAI-PC-20200611-142233.raw)
                      PAE type : No PAE
                           DTB : 0x187000L
                          KDBG : 0xf800028570a0L
          Number of Processors : 1
     Image Type (Service Pack) : 1
                KPCR for CPU 0 : 0xfffff80002858d00L
             KUSER_SHARED_DATA : 0xfffff78000000000L
           Image date and time : 2020-06-11 14:22:36 UTC+0000
     Image local date and time : 2020-06-11 22:22:36 +0800
```

Doing some basic enumeration by looking at the processes running:

```bash
Offset(V)          Name                    PID   PPID   Thds     Hnds   Sess  Wow64 Start                          Exit                          
------------------ -------------------- ------ ------ ------ -------- ------ ------ ------------------------------ ------------------------------
0xfffffa8001e03040 System                    4      0     84      603 ------      0 2020-06-12 17:24:04 UTC+0000                                 
0xfffffa80030127f0 smss.exe                268      4      2       29 ------      0 2020-06-12 17:24:04 UTC+0000                                 
0xfffffa80030e5560 csrss.exe               340    332      9      460      0      0 2020-06-12 17:24:15 UTC+0000                                 
0xfffffa8001e0a060 wininit.exe             388    332      3       74      0      0 2020-06-12 17:24:16 UTC+0000                                 
0xfffffa80039719e0 csrss.exe               400    380      9      484      1      0 2020-06-12 17:24:16 UTC+0000                                 
0xfffffa80039d53e0 services.exe            456    388      8      211      0      0 2020-06-12 17:24:18 UTC+0000                                 
0xfffffa80039fe450 lsass.exe               472    388      7      740      0      0 2020-06-12 17:24:18 UTC+0000                                 
0xfffffa8003905910 lsm.exe                 480    388     10      153      0      0 2020-06-12 17:24:18 UTC+0000                                 
0xfffffa80039e6b30 winlogon.exe            488    380      5      119      1      0 2020-06-12 17:24:18 UTC+0000                                 
0xfffffa8003ac7060 svchost.exe             616    456      9      355      0      0 2020-06-12 17:24:23 UTC+0000                                 
0xfffffa8003b041c0 VBoxService.ex          680    456     13      126      0      0 2020-06-12 17:24:23 UTC+0000                                 
0xfffffa8003af4890 svchost.exe             748    456      8      287      0      0 2020-06-12 17:24:23 UTC+0000                                 
0xfffffa8003b55950 svchost.exe             840    456     23      597      0      0 2020-06-12 17:24:23 UTC+0000                                 
0xfffffa8003b5db30 svchost.exe             884    456     28      533      0      0 2020-06-12 17:24:23 UTC+0000                                 
0xfffffa8003b7f060 svchost.exe             908    456     36     1051      0      0 2020-06-12 17:24:23 UTC+0000                                 
0xfffffa8003c60b30 TrustedInstall          308    456      6      297      0      0 2020-06-12 17:24:25 UTC+0000                                 
0xfffffa8003c77b30 svchost.exe             548    456     16      443      0      0 2020-06-12 17:24:25 UTC+0000                                 
0xfffffa80032ce890 svchost.exe            1076    456     15      460      0      0 2020-06-12 17:24:27 UTC+0000                                 
0xfffffa8001e4eb30 spoolsv.exe            1188    456     13      282      0      0 2020-06-12 17:24:28 UTC+0000                                 
0xfffffa80032f8570 svchost.exe            1216    456     18      306      0      0 2020-06-12 17:24:28 UTC+0000                                 
0xfffffa8003caf530 svchost.exe            1316    456     23      312      0      0 2020-06-12 17:24:29 UTC+0000                                 
0xfffffa80048349e0 taskhost.exe           1948    456      8      185      1      0 2020-06-12 17:24:53 UTC+0000                                 
0xfffffa8004858b30 dwm.exe                2000    884      3       73      1      0 2020-06-12 17:24:53 UTC+0000                                 
0xfffffa800485ab30 explorer.exe           2024   1992     30      907      1      0 2020-06-12 17:24:53 UTC+0000                                 
0xfffffa800487e9b0 taskeng.exe            1388    908      5       87      0      0 2020-06-12 17:24:53 UTC+0000                                 
0xfffffa8004882b30 GoogleUpdate.e         1040   1388      4      116      0      1 2020-06-12 17:24:54 UTC+0000                                 
0xfffffa800405d1f0 GoogleCrashHan          552   1040      4       80      0      1 2020-06-12 17:24:55 UTC+0000                                 
0xfffffa80048d1060 GoogleCrashHan         1768   1040      4       74      0      0 2020-06-12 17:24:55 UTC+0000                                 
0xfffffa8004515b30 VBoxTray.exe           1096   2024     14      144      1      0 2020-06-12 17:24:57 UTC+0000                                 
0xfffffa800493cb30 SearchIndexer.         2140    456     11      591      0      0 2020-06-12 17:25:02 UTC+0000                                 
0xfffffa8004a21060 wmpnetwk.exe           2252    456     13      441      0      0 2020-06-12 17:25:02 UTC+0000                                 
0xfffffa8004a97200 svchost.exe            2552    456      7      347      0      0 2020-06-12 17:25:03 UTC+0000                                 
0xfffffa8004af34f0 chrome.exe             2732   2024     32      789      1      0 2020-06-12 17:25:05 UTC+0000                                 
0xfffffa8004aff140 chrome.exe             2744   2732      9       87      1      0 2020-06-12 17:25:05 UTC+0000                                 
0xfffffa8004bdd320 chrome.exe             2908   2732     14      333      1      0 2020-06-12 17:25:07 UTC+0000                                 
0xfffffa8002fd4b30 chrome.exe             1928   2732      9      208      1      0 2020-06-12 17:25:11 UTC+0000                                 
0xfffffa8004a0cb30 chrome.exe              600   2732     13      179      1      0 2020-06-12 17:26:26 UTC+0000                                 
0xfffffa80047a5630 chrome.exe             3664   2732     17      369      1      0 2020-06-12 17:26:29 UTC+0000                                 
0xfffffa8001f838d0 chrome.exe             3100   2732     11      179      1      0 2020-06-12 17:26:45 UTC+0000                                 
0xfffffa800477b690 sppsvc.exe             3596    456      4      144      0      0 2020-06-12 17:26:50 UTC+0000                                 
0xfffffa8002018060 svchost.exe            3560    456     15      344      0      0 2020-06-12 17:26:54 UTC+0000                                 
0xfffffa8002178b30 mscorsvw.exe            688    456      6       77      0      0 2020-06-12 17:28:12 UTC+0000                                 
0xfffffa8002f8fb30 WMIADAP.exe            3344    908      4       80      0      0 2020-06-12 17:28:18 UTC+0000                                 
0xfffffa8002f99060 mscorsvw.exe           3024    456      6       84      0      1 2020-06-12 17:29:32 UTC+0000                                 
0xfffffa8002e3e2d0 software_repor         2648   2732      9      182      1      0 2020-06-12 17:30:45 UTC+0000                                 
0xfffffa8001fe5060 software_repor         3220   2648      7       76      1      0 2020-06-12 17:30:45 UTC+0000                                 
0xfffffa8001f70250 software_repor         3984   2648      3       99      1      0 2020-06-12 17:30:48 UTC+0000                                 
0xfffffa80038f5490 Discord.exe            3740   4068     31      535      1      1 2020-06-12 17:31:04 UTC+0000                                 
0xfffffa8002fd15f0 Discord.exe            1908   3740     15      342      1      1 2020-06-12 17:31:06 UTC+0000                                 
0xfffffa80040bf5f0 Discord.exe            3732   3740      8      221      1      1 2020-06-12 17:31:13 UTC+0000                                 
0xfffffa8002716630 Discord.exe             288   3740      7      122      1      1 2020-06-12 17:31:34 UTC+0000                                 
0xfffffa8001fe4710 Discord.exe            1916   3740     40      665      1      1 2020-06-12 17:31:35 UTC+0000                                 
0xfffffa800264f7d0 Discord.exe            2440   3740     13      207      1      1 2020-06-12 17:31:41 UTC+0000                                 
0xfffffa8003c00b30 audiodg.exe            3440    840      6      134      0      0 2020-06-12 17:31:44 UTC+0000                                 
0xfffffa8001f77060 WmiPrvSE.exe           3864    616      8      148      0      0 2020-06-12 17:31:54 UTC+0000                                 
0xfffffa80029ffa90 chrome.exe             3412   2732     12      158      1      0 2020-06-12 17:32:01 UTC+0000                                 
0xfffffa8001f4a350 software_repor         2180   2648      2       94      1      0 2020-06-12 17:33:05 UTC+0000                                 
0xfffffa8003c18060 DumpIt.exe             3524   2024      5       45      1      1 2020-06-12 17:33:25 UTC+0000                                 
0xfffffa8002f4a480 conhost.exe            3852    400      2       52      1      0 2020-06-12 17:33:25 UTC+0000                                 

```

Apart from the normal windows services, we use `Discord` and `Google Chrome` running. The challenge description states that we should be looking for a **file**, but if we run filescan and look through it, we will not find any interesting files.

Let's dump discord's process memory and run strings on it to see if we can find anything interesting. Perhaps start by grepping for links:

```
https://cdn.discordapp.com/attachments/720636480405504041/721017557804515438/Invoice_11-6-20.encrypted.pdf
```

If you grep for links, you will see this interesting link above. As you might know, files in discord are normally sent as a link to their server where it can be downloaded from.

However, as the name suggests, when we try to open the PDF file, it is encrypted with a password.

So where can we get the password? There is only 1 place left to look :open_mouth:, Google Chrome!

If you dump Google Chrome's memory and run strings on it, you might be able to see some text mentioning the PDF and a password, but the password seems to be nowhere!? The next method we can use to analyse the process memory dump is to use **GIMP**! 

(*This part is admittedly very tedious and time-consuming*) After some time, you should be able to see this:

![1](D:\Desktop\Cybersecurity\Cybersec Github Repos\ctfdump\IRSInternalCTF\Big Brother Secrets\1.png)

Keying in the password to decrypt the PDF, we will still get a **blank pdf**. Oh no! Running binwalk, exiftool etc. on the PDF reveals nothing. But when we take a look at the objects of the PDF using `peepdf`, we will notice a **javascript stream** with the following obfuscated javascript code: (<u>Note:</u> You will still need to decrypt the PDF first using `qpdf` with the password recovered)

```javascript
peepdf -i out.pdf
PPDF> object 2

<< /Type /Action
/S /JavaScript
/JS 5 0 R >>

PPDF> object 5

<< /Length 335
/Filter /FlateDecode >>
stream
var _0x424d = ['ealMFPepi{REEY}RW3_4_LM4SI', 'split', 'reverse', 'join', 'YEE', 'length'];
var _0x5a94 = function (_0x424dfd, _0x5a942d) {
    _0x424dfd = _0x424dfd - 0x0;
    var _0x1b1cf7 = _0x424d[_0x424dfd];
    return _0x1b1cf7;
};
var encryptedFlag = _0x5a94('0x0');
var encryptedFlagArray = encryptedFlag[_0x5a94('0x1')]('')[_0x5a94('0x2')]('')[_0x5a94('0x3')]('');
encryptedFlagArray = encryptedFlagArray[_0x5a94('0x1')](_0x5a94('0x4'));
var decoded = '';
var counter1 = 0x0;
var counter2 = 0x0;
for (let i = 0x0; i < encryptedFlag[_0x5a94('0x5')] - 0x3; i++) {
    if (i % 0x2 === 0x0) {
        decoded += encryptedFlagArray[0x0][counter1];
        counter1++;
    } else {
        decoded += encryptedFlagArray[0x1][counter2];
        counter2++;
    }
}
endstream
```

 `ealMFPepi{REEY}RW3_4_LM4SI` looks like the flag, doesn't it :smile:? Hence what we need to do is to simply de-obfuscate this javascript code and it will run the decryption algorithm! (*This is left as an exercise for the reader*)

After running the code, it gives us the flag:

```
IRS{4iMpLe_P4F_M3lWaRe}
```



### Learning Points:

- Reading more stuff on screen using GIMP :smile:
- Practise of tactics taught before xD
- Some PDF Malware analysis

