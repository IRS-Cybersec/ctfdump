# Walking down a colourful memory lane [992 Points] - 6 Solves (Cat 3)

```
We are trying to find out how did our machine get infected. What did the user do?
```

We are given a memory dump, and hence the first thing is to pull out the **good ol' volatility**

Let's first run a basic `imageinfo` to determine the profile.

```bash
volatility -f forensics-challenge-1.mem imageinfo

         Suggested Profile(s) : Win7SP1x64, Win7SP0x64, Win2008R2SP0x64, Win2008R2SP1x64_23418, Win2008R2SP1x64, Win7SP1x64_23418
                     AS Layer1 : WindowsAMD64PagedMemory (Kernel AS)
                     AS Layer2 : FileAddressSpace (/mnt/d/Desktop/Stack the Flags 2020/forensics-challenge-1.mem)
                      PAE type : No PAE
                           DTB : 0x187000L
                          KDBG : 0xf800029fb0a0L
          Number of Processors : 1
     Image Type (Service Pack) : 1
                KPCR for CPU 0 : 0xfffff800029fcd00L
             KUSER_SHARED_DATA : 0xfffff78000000000L
           Image date and time : 2020-12-03 09:12:22 UTC+0000
     Image local date and time : 2020-12-03 17:12:22 +0800
```

Alright, so the profile is `Win7SP1x64`, let's continue by running a basic `pslist` to list running processes:

```bash
volatility -f forensics-challenge-1.mem --profile=Win7SP1x64 pslist

Offset(V)          Name                    PID   PPID   Thds     Hnds   Sess  Wow64 Start                          Exit                          
------------------ -------------------- ------ ------ ------ -------- ------ ------ ------------------------------ ------------------------------
0xfffffa8018dac040 System                    4      0     86      572 ------      0 2020-12-03 08:51:24 UTC+0000                                 
0xfffffa8019355b30 smss.exe                240      4      2       29 ------      0 2020-12-03 08:51:24 UTC+0000                                 
0xfffffa8019f07950 csrss.exe               324    316      9      458      0      0 2020-12-03 08:51:25 UTC+0000                                 
0xfffffa8018db2060 wininit.exe             376    316      3       75      0      0 2020-12-03 08:51:25 UTC+0000                                 
0xfffffa8018db15d0 csrss.exe               388    368     13      611      1      0 2020-12-03 08:51:25 UTC+0000                                 
0xfffffa801a12c060 winlogon.exe            424    368      5      112      1      0 2020-12-03 08:51:25 UTC+0000                                 
0xfffffa801a12fb30 services.exe            480    376      7      207      0      0 2020-12-03 08:51:25 UTC+0000                                 
0xfffffa801a1797c0 lsass.exe               496    376      6      569      0      0 2020-12-03 08:51:25 UTC+0000                                 
0xfffffa801a17db30 lsm.exe                 504    376     10      146      0      0 2020-12-03 08:51:25 UTC+0000                                 
0xfffffa801a1c7b30 svchost.exe             612    480     10      356      0      0 2020-12-03 08:51:25 UTC+0000                                 
0xfffffa801a1aa780 vm3dservice.ex          672    480      3       45      0      0 2020-12-03 08:51:25 UTC+0000                                 
0xfffffa801a234060 svchost.exe             708    480      8      285      0      0 2020-12-03 08:51:25 UTC+0000                                 
0xfffffa801a2592a0 svchost.exe             756    480     22      515      0      0 2020-12-03 08:51:25 UTC+0000                                 
0xfffffa801a2cf5f0 svchost.exe             868    480     15      370      0      0 2020-12-03 08:51:26 UTC+0000                                 
0xfffffa801a2fab30 svchost.exe             908    480     32      948      0      0 2020-12-03 08:51:26 UTC+0000                                 
0xfffffa801a331230 svchost.exe             252    480     22      770      0      0 2020-12-03 08:51:26 UTC+0000                                 
0xfffffa801a34cb30 svchost.exe             500    480     19      478      0      0 2020-12-03 08:51:26 UTC+0000                                 
0xfffffa801a3ee4c0 spoolsv.exe            1184    480     13      261      0      0 2020-12-03 08:51:26 UTC+0000                                 
0xfffffa801a408b30 taskhost.exe           1196    480      8      154      1      0 2020-12-03 08:51:26 UTC+0000                                 
0xfffffa801a4158a0 svchost.exe            1244    480     19      313      0      0 2020-12-03 08:51:26 UTC+0000                                 
0xfffffa801a51eb30 VGAuthService.         1448    480      3       84      0      0 2020-12-03 08:51:27 UTC+0000                                 
0xfffffa801a55f630 vmtoolsd.exe           1472    480     10      270      0      0 2020-12-03 08:51:27 UTC+0000                                 
0xfffffa801a4c4630 sppsvc.exe             1672    480      5      151      0      0 2020-12-03 08:51:27 UTC+0000                                 
0xfffffa801a643b30 WmiPrvSE.exe           1852    612      9      196      0      0 2020-12-03 08:51:27 UTC+0000                                 
0xfffffa801a6695e0 dllhost.exe            1912    480     13      185      0      0 2020-12-03 08:51:27 UTC+0000                                 
0xfffffa801a6ae380 svchost.exe            2024    480      7       97      0      0 2020-12-03 08:51:28 UTC+0000                                 
0xfffffa801a6ba060 msdtc.exe              1276    480     12      145      0      0 2020-12-03 08:51:29 UTC+0000                                 
0xfffffa801917f060 WmiPrvSE.exe           2264    612      6      206      0      0 2020-12-03 08:51:47 UTC+0000                                 
0xfffffa801a54e130 dwm.exe                2444    868      5      118      1      0 2020-12-03 08:51:58 UTC+0000                                 
0xfffffa801a3dd7f0 explorer.exe           2460   2432     32      905      1      0 2020-12-03 08:51:58 UTC+0000                                 
0xfffffa801a846b30 vm3dservice.ex         2548   2460      2       53      1      0 2020-12-03 08:51:59 UTC+0000                                 
0xfffffa801a8ceb30 vmtoolsd.exe           2556   2460      8      166      1      0 2020-12-03 08:51:59 UTC+0000                                 
0xfffffa801a91a060 SearchIndexer.         2704    480     13      648      0      0 2020-12-03 08:52:05 UTC+0000                                 
0xfffffa801a9bfb30 wmpnetwk.exe           2876    480     15      226      0      0 2020-12-03 08:52:05 UTC+0000                                 
0xfffffa801a9cab30 svchost.exe            2964    480     18      246      0      0 2020-12-03 08:52:05 UTC+0000                                 
0xfffffa801a5d27c0 svchost.exe            1240    480     13      332      0      0 2020-12-03 08:53:27 UTC+0000                                 
0xfffffa801a84e060 audiodg.exe            2376    756      5      126      0      0 2020-12-03 09:08:22 UTC+0000                                 
0xfffffa80199e6a70 chrome.exe             2904   2460     33     1694      1      0 2020-12-03 09:10:20 UTC+0000                                 
0xfffffa801a1d5b30 chrome.exe              852   2904     10      170      1      0 2020-12-03 09:10:20 UTC+0000                                 
0xfffffa801998bb30 chrome.exe             1392   2904     10      274      1      0 2020-12-03 09:10:20 UTC+0000                                 
0xfffffa801a91d630 chrome.exe              692   2904     13      225      1      0 2020-12-03 09:10:20 UTC+0000                                 
0xfffffa8019989b30 chrome.exe             1628   2904      8      152      1      0 2020-12-03 09:10:21 UTC+0000                                 
0xfffffa801a84cb30 chrome.exe             1340   2904     13      280      1      0 2020-12-03 09:10:24 UTC+0000                                 
0xfffffa801acbeb30 chrome.exe             1112   2904     14      251      1      0 2020-12-03 09:10:27 UTC+0000                                 
0xfffffa801acd8b30 chrome.exe              272   2904     14      239      1      0 2020-12-03 09:10:27 UTC+0000                                 
0xfffffa801acd1060 chrome.exe             1648   2904     13      227      1      0 2020-12-03 09:10:28 UTC+0000                                 
0xfffffa801acedb30 chrome.exe             3092   2904     13      212      1      0 2020-12-03 09:10:28 UTC+0000                                 
0xfffffa801ad0eb30 chrome.exe             3160   2904     15      286      1      0 2020-12-03 09:10:29 UTC+0000                                 
0xfffffa801ad3cb30 chrome.exe             3220   2904     15      295      1      0 2020-12-03 09:10:30 UTC+0000                                 
0xfffffa801ad3ab30 chrome.exe             3240   2904     13      218      1      0 2020-12-03 09:10:30 UTC+0000                                 
0xfffffa801ad8d060 chrome.exe             3320   2904     13      218      1      0 2020-12-03 09:10:32 UTC+0000                                 
0xfffffa801ad9eb30 chrome.exe             3328   2904     13      231      1      0 2020-12-03 09:10:33 UTC+0000                                 
0xfffffa801addfb30 chrome.exe             3380   2904     13      304      1      0 2020-12-03 09:10:34 UTC+0000                                 
0xfffffa801ad9ab30 chrome.exe             3388   2904     13      283      1      0 2020-12-03 09:10:34 UTC+0000                                 
0xfffffa801ae269e0 chrome.exe             3444   2904     13      231      1      0 2020-12-03 09:10:38 UTC+0000                                 
0xfffffa801ae2e7d0 chrome.exe             3456   2904     12      196      1      0 2020-12-03 09:10:42 UTC+0000                                 
0xfffffa801ae63060 chrome.exe             3568   2904     12      222      1      0 2020-12-03 09:10:44 UTC+0000                                 
0xfffffa801ae89b30 chrome.exe             3584   2904      9      173      1      0 2020-12-03 09:10:45 UTC+0000                                 
0xfffffa801aed8060 notepad.exe            3896   2460      5      286      1      0 2020-12-03 09:10:52 UTC+0000                                 
0xfffffa801aeb5b30 chrome.exe             2492   2904     12      171      1      0 2020-12-03 09:10:58 UTC+0000                                 
0xfffffa801af22b30 chrome.exe             1348   2904     12      171      1      0 2020-12-03 09:10:59 UTC+0000                                 
0xfffffa801af63b30 chrome.exe             3232   2904     12      182      1      0 2020-12-03 09:11:00 UTC+0000                                 
0xfffffa801af9d060 chrome.exe             4192   2904     12      168      1      0 2020-12-03 09:11:02 UTC+0000                                 
0xfffffa801afaf630 chrome.exe             4268   2904     12      171      1      0 2020-12-03 09:11:04 UTC+0000                                 
0xfffffa801afa6b30 chrome.exe             4324   2904     14      180      1      0 2020-12-03 09:11:04 UTC+0000                                 
0xfffffa801afbeb30 chrome.exe             4380   2904     12      179      1      0 2020-12-03 09:11:04 UTC+0000                                 
0xfffffa801ac4d060 RamCapture64.e         4832   2460      6       70      1      0 2020-12-03 09:11:24 UTC+0000                                 
0xfffffa80199c3060 conhost.exe            4840    388      2       50      1      0 2020-12-03 09:11:24 UTC+0000                                 
0xfffffa801ae055d0 dllhost.exe            4508    612      6 57728600      1      0 2020-12-03 09:12:23 UTC+0000                                 
```

Hmmm, there doesn't seem to be anything of interest here, other than a large number of chrome processes (aka a large number of chrome tabs open) as well as notepad.exe. 

Looking back at the challenge description `We are trying to find out how did our machine get infected. What did the user do?`, maybe there is a malicious process hidden somewhere? Let's run a `psxview`!

```bash
volatility -f forensics-challenge-1.mem --profile=Win7SP1x64 psxview

Offset(P)          Name                    PID pslist psscan thrdproc pspcid csrss session deskthrd ExitTime
------------------ -------------------- ------ ------ ------ -------- ------ ----- ------- -------- --------
0x000000007ebaa780 vm3dservice.ex          672 True   True   True     True   True  True    True     
0x000000007e4ae380 svchost.exe            2024 True   True   True     True   True  True    True     
0x000000007dd22b30 chrome.exe             1348 True   True   True     True   True  True    True     
0x000000007e24e060 audiodg.exe            2376 True   True   True     True   True  True    True     
0x000000007e443b30 WmiPrvSE.exe           1852 True   True   True     True   True  True    True     
0x000000007df0eb30 chrome.exe             3160 True   True   True     True   True  True    True     
0x000000007e31a060 SearchIndexer.         2704 True   True   True     True   True  True    True     
0x000000007dc269e0 chrome.exe             3444 True   True   True     True   True  True    True     
0x000000007e246b30 vm3dservice.ex         2548 True   True   True     True   True  True    True     
0x000000007deedb30 chrome.exe             3092 True   True   True     True   True  True    True     
0x000000007df9ab30 chrome.exe             3388 True   True   True     True   True  True    True     
0x000000007df8d060 chrome.exe             3320 True   True   True     True   True  True    True     
0x000000007debeb30 chrome.exe             1112 True   True   True     True   True  True    True     
0x000000007eb2c060 winlogon.exe            424 True   True   True     True   True  True    True     
0x000000007e6158a0 svchost.exe            1244 True   True   True     True   True  True    True     
0x000000007e6c4630 sppsvc.exe             1672 True   True   True     True   True  True    True     
0x000000007f389b30 chrome.exe             1628 True   True   True     True   True  True    True     
0x000000007dda6b30 chrome.exe             4324 True   True   True     True   True  True    True     
0x000000007e3cab30 svchost.exe            2964 True   True   True     True   True  True    True     
0x000000007e31d630 chrome.exe              692 True   True   True     True   True  True    True     
0x000000007f38bb30 chrome.exe             1392 True   True   True     True   True  True    True     
0x000000007e9ee4c0 spoolsv.exe            1184 True   True   True     True   True  True    True     
0x000000007e94cb30 svchost.exe             500 True   True   True     True   True  True    True     
0x000000007e74e130 dwm.exe                2444 True   True   True     True   True  True    True     
0x000000007ebc7b30 svchost.exe             612 True   True   True     True   True  True    True     
0x000000007dcb5b30 chrome.exe             2492 True   True   True     True   True  True    True     
0x000000007ded1060 chrome.exe             1648 True   True   True     True   True  True    True     
0x000000007e2ceb30 vmtoolsd.exe           2556 True   True   True     True   True  True    True     
0x000000007e931230 svchost.exe             252 True   True   True     True   True  True    True     
0x000000007eb2fb30 services.exe            480 True   True   True     True   True  True    False    
0x000000007f3c3060 conhost.exe            4840 True   True   True     True   True  True    True     
0x000000007dc89b30 chrome.exe             3584 True   True   True     True   True  True    True     
0x000000007eb797c0 lsass.exe               496 True   True   True     True   True  True    False    
0x000000007e834060 svchost.exe             708 True   True   True     True   True  True    True     
0x000000007df9eb30 chrome.exe             3328 True   True   True     True   True  True    True     
0x000000007e7d27c0 svchost.exe            1240 True   True   True     True   True  True    True     
0x000000007fb7f060 WmiPrvSE.exe           2264 True   True   True     True   True  True    True     
0x000000007dfdfb30 chrome.exe             3380 True   True   True     True   True  True    True     
0x000000007dcd8060 notepad.exe            3896 True   True   True     True   True  True    True     
0x000000007dc2e7d0 chrome.exe             3456 True   True   True     True   True  True    True     
0x000000007ebd5b30 chrome.exe              852 True   True   True     True   True  True    True     
0x000000007e24cb30 chrome.exe             1340 True   True   True     True   True  True    True     
0x000000007e4ba060 msdtc.exe              1276 True   True   True     True   True  True    True     
0x000000007e75f630 vmtoolsd.exe           1472 True   True   True     True   True  True    True     
0x000000007e608b30 taskhost.exe           1196 True   True   True     True   True  True    True     
0x000000007e8592a0 svchost.exe             756 True   True   True     True   True  True    True     
0x000000007ded8b30 chrome.exe              272 True   True   True     True   True  True    True     
0x000000007dd63b30 chrome.exe             3232 True   True   True     True   True  True    True     
0x000000007feab060 wininit.exe             376 True   True   True     True   True  True    True     
0x000000007dd9d060 chrome.exe             4192 True   True   True     True   True  True    True     
0x000000007e9dd7f0 explorer.exe           2460 True   True   True     True   True  True    True     
0x000000007df3ab30 chrome.exe             3240 True   True   True     True   True  True    True     
0x000000007df3cb30 chrome.exe             3220 True   True   True     True   True  True    True     
0x000000007dc63060 chrome.exe             3568 True   True   True     True   True  True    True     
0x000000007e8cf5f0 svchost.exe             868 True   True   True     True   True  True    True     
0x000000007ddaf630 chrome.exe             4268 True   True   True     True   True  True    True     
0x000000007eb7db30 lsm.exe                 504 True   True   True     True   True  True    False    
0x000000007de4d060 RamCapture64.e         4832 True   True   True     True   True  True    True     
0x000000007e4695e0 dllhost.exe            1912 True   True   True     True   True  True    True     
0x000000007e71eb30 VGAuthService.         1448 True   True   True     True   True  True    True     
0x000000007f3e6a70 chrome.exe             2904 True   True   True     True   True  True    True     
0x000000007e3bfb30 wmpnetwk.exe           2876 True   True   True     True   True  True    True     
0x000000007ddbeb30 chrome.exe             4380 True   True   True     True   True  True    True     
0x000000007e8fab30 svchost.exe             908 True   True   True     True   True  True    True     
0x000000007dc055d0 dllhost.exe            4508 True   True   True     True   False True    True     
0x000000007fea5040 System                    4 True   True   True     True   False False   False    
0x000000007ed07950 csrss.exe               324 True   True   True     True   False True    True     
0x000000007feaa5d0 csrss.exe               388 True   True   True     True   False True    True     
0x000000007f955b30 smss.exe                240 True   True   True     True   False False   False    
0x000000007e2b7060 chrome.exe             3672 False  True   False    False  False False   False    2020-12-03 09:12:21 UTC+0000
0x000000007e07b060 slui.exe               4908 False  True   False    False  False False   False    2020-12-03 09:11:29 UTC+0000
```

Hmmmm nothing out of the ordinary unfortunately... the 2 processes which weren't listed in pslist were merely because they had exited.

I then decided to run various Windows Malware plugins such as `malfind`, `idrmoudles`, `svcscan` and more but to no avail... it almost seems like the malware didn't exist.

Looking back at the challenge description once more, `what did the user do?` made me wonder... maybe the user downloaded something in chrome? Let's run the `chromehistory` plugin to check it out! **Note:** I have removed the last 3 columns for this to fit into the page

```
Index  URL                                                                              Title                                                                           
------ -------------------------------------------------------------------------------- ---------------------------------------------------------------------------
    14 https://www.google.com/search?q=smart+n...j0l7.3224j0j7&sourceid=chrome&ie=UTF-8 smart nation singapore - Google Search                                                  
    13 https://www.google.com/search?q=stack+g...9i59.5761j0j7&sourceid=chrome&ie=UTF-8 stack govtech 2020 - Google Search                                                       
    12 https://www.channelnewsasia.com/                                                 CNA - Breaking news, latest Singapore, Asia and world news                               
    11 https://www.google.com/search?q=channel...j0l4.2634j0j4&sourceid=chrome&ie=UTF-8 channel news asia - Google Search                                                           
    10 https://www.straitstimes.com/                                                    The Straits Times - Breaking news, Sing...news, Asia and world news & multimedia          
     9 https://www.google.com/search?q=straits...0l3.74607j0j4&sourceid=chrome&ie=UTF-8 straits times - Google Search                                                             
     7 https://www.youtube.com/                                                         YouTube                                                                                   
     6 https://www.google.com/search?q=hobbies...j0l6.3762j0j9&sourceid=chrome&ie=UTF-8 hobbies to pick up during quarantine - Google Search                                
     5 https://www.google.com/search?q=benefit...j0l7.2693j0j4&sourceid=chrome&ie=UTF-8 benefits of exercise - Google Search                                                         
     4 https://www.reddit.com/r/cybersecurity/...now_some_good_cybersecurity_youtubers/ Anyone know some good cybersecurity youtubers : cybersecurity                           
     3 https://www.google.com/search?q=govtech...j0l2.4169j0j4&sourceid=chrome&ie=UTF-8 govtech singapore - Google Search                                                      
     2 https://www.stack.gov.sg/                                                        STACK 2020                                                                                
     1 https://www.google.com/search?q=stack+g...i457.4684j1j4&sourceid=chrome&ie=UTF-8 stack govtech 2020 - Google Search                                                        
    25 https://pastebin.com/KeqPRaaY                                                    htesttttttttttt - Pastebin.com                                                            
    27 https://www.reddit.com/r/singapore/                                              Singapore                                                                               
    26 https://www.reddit.com/r/singapore/comm...ew_govtech_software_for_smart_thermal/ COVID-19: New GovTech software for smar...mercialisation and scaling : singapore      
    22 https://www.google.com/search?q=stack+c...30l6.9304j0j9&sourceid=chrome&ie=UTF-8 stack ctf - Google Search                                                               
    21 https://www.google.com/search?q=govtech...57j0.2222j0j4&sourceid=chrome&ie=UTF-8 govtech csg - Google Search                                                           
    18 https://www.google.com/search?q=traceto...0l3j5.845j0j4&sourceid=chrome&ie=UTF-8 tracetogether token - Google Search                                                
    16 https://www.google.com/search?q=govtech...99j0.1710j0j7&sourceid=chrome&ie=UTF-8 govtech singapore - Google Search                                                 
    15 https://www.google.com/search?ei=sCPHX9...ÿÿH9ÊHCøH…ÿtH9Ç‡  Hý    èoåAë 1ÀHØHøL‰"HØHƒÀH9õ„‡                 
     8 http://www.mediafire.com/view/5wo9db2pa7gdcoc/This_is_a_png_file.png/file        This is a png file.png - MediaFire                                              
    24 http://www.mediafire.com/view/5wo9db2pa7gdcoc/                                   This is a png file.png - MediaFire                                                
    23 https://ctf.tech.gov.sg/                                                         STACK the Flags                                                               
    20 https://www.tech.gov.sg/cyber-security-group                                     Cyber Security Group (CSG)                                                      
    19 https://token.gowhere.gov.sg/                                                    Token Go Where                                                                    
    17 https://www.reddit.com/r/singapore/comm...usive_inside_singapores_govtech_rapid/ Exclusive: Inside Singaporeâ€™s GovTech Rapid Deployment Unit : singapore           
    15 https://www.google.com/search?ei=sCPHX9...huKCxq7tAhUu7XMBHSzLA8QQ4dUDCA0&uact=5 covid update - Google Search                                                       
    20 https://www.tech.gov.sg/cyber-security-group                                     Cyber Security Group (CSG)                                                          
     5 https://www.google.com/search?q=benefit...j0l7.2693j0j4&sourceid=chrome&ie=UTF-8 benefits of exercise - Google Search                                                     
     9 https://www.google.com/search?q=straits...0l3.74607j0j4&sourceid=chrome&ie=UTF-8 straits times - Google Search   
```

Hmmm... `mediafire`, now that's a file hosting website I haven't used in a long time. Maybe the user downloaded the malware from there! Let's check it out!

After visiting the site, we get a ... *png* (not to mention how small it is)?

I did not think much about the png at first since I thought we were looking for *real malware*. Hence I went back to the dump and dumped DLLs and more for several more hours with no luck :sweat:.

After a whole 18 hours, I finally decided to relook at everything I have and found the png. I then decided to run some basic steganography decoders such as LSBsteg and zsteg. When running zsteg:

```bash
 zsteg -a This\ is\ a\ png\ file\ \(2\).png
 
b8,r,lsb,xy         .. text: "gthsm0_d3B3"
b8,g,lsb,xy         .. text: "oe-g3rRG3lz"
b8,b,lsb,xy         .. text: "vcc{my3rnu}"
b8,rgb,lsb,xy       .. text: "govtech-csg{m3m0ry_R3dGr33nBlu3z}" <----!!!
b8,bgr,lsb,xy       .. text: "vogcetc-h{gsm3myr03R_rGdn33ulB}z3"
b8,rgb,lsb,xy,prime .. text: "h-csg{0rydGr"
b8,bgr,lsb,xy,prime .. text: "c-h{gsyr0rGd"
b8,r,lsb,XY         .. text: "3B3d_0mshtg"
b8,g,lsb,XY         .. text: "zl3GRr3g-eo"
b8,b,lsb,XY         .. text: "}unr3ym{ccv"
b8,rgb,lsb,XY       .. text: "3z}Blu33ndGr_R30rym3msg{h-ctecgov"
b8,bgr,lsb,XY       .. text: "}z3ulBn33rGd3R_yr0m3m{gsc-hcetvog"
b8,rgb,lsb,XY,prime .. text: "3z}m3mh-c"
b8,bgr,lsb,XY,prime .. text: "}z3m3mc-h"
```

**Bingo!** and hence the flag is:

```
govtech-csg{m3m0ry_R3dGr33nBlu3z}
```



## Post Mortem

- I shouldn't have left the png alone... Leave no stone unturned!!!
- I was actually hoping for real malware 
- What zsteg seems to be doing is that it's extracting the Least Significant Bit (LSB) from the rgb planes... I wonder why my LSB tools didn't work