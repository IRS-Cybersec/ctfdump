# Walking down a colourful memory lane
**992 Points // 6 Solves**

We are trying to find out how did our machine get infected. What did the user do?

## Solution

The file given was a memory dump, which we processed with [`volatility`](https://www.volatilityfoundation.org/). The first step was to determine the type of memory dump given:

```
$ vol.py -f forensics-challenge-1.mem imageinfo
Volatility Foundation Volatility Framework 2.6.1
INFO    : volatility.debug    : Determining profile based on KDBG search...
          Suggested Profile(s) : Win7SP1x64, Win7SP0x64, Win2008R2SP0x64, Win2008R2SP1x64_23418, Win2008R2SP1x64, Win7SP1x64_23418
                     AS Layer1 : WindowsAMD64PagedMemory (Kernel AS)
                     AS Layer2 : FileAddressSpace (forensics-challenge-1.mem)
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

We chose to use ``Win7SP1x64`` as the profile for the remainder of the challenge. Next, we listed the running processes:

```
$ vol.py -f forensics-challenge-1.mem --profile="Win7SP1x64" pstree
Volatility Foundation Volatility Framework 2.6.1
Name                                                  Pid   PPid   Thds   Hnds Time
-------------------------------------------------- ------ ------ ------ ------ ----
 0xfffffa801a3dd7f0:explorer.exe                     2460   2432     32    905 2020-12-03 08:51:58 UTC+0000
. 0xfffffa801aed8060:notepad.exe                     3896   2460      5    286 2020-12-03 09:10:52 UTC+0000
. 0xfffffa801ac4d060:RamCapture64.e                  4832   2460      6     70 2020-12-03 09:11:24 UTC+0000
. 0xfffffa80199e6a70:chrome.exe                      2904   2460     33   1694 2020-12-03 09:10:20 UTC+0000
.. 0xfffffa801ad9eb30:chrome.exe                     3328   2904     13    231 2020-12-03 09:10:33 UTC+0000
[TRUNCATED: lots of chrome.exe]
.. 0xfffffa801ad8d060:chrome.exe                     3320   2904     13    218 2020-12-03 09:10:32 UTC+0000
. 0xfffffa801a8ceb30:vmtoolsd.exe                    2556   2460      8    166 2020-12-03 08:51:59 UTC+0000
. 0xfffffa801a846b30:vm3dservice.ex                  2548   2460      2     53 2020-12-03 08:51:59 UTC+0000
[TRUNCATED: system processes]
```

`RamCapture64` was used to create the memdump, and the VM tools processes were part of VMWare, and were most likely not part of the challenge. Therefore, our focus turned to [notepad](#appendix-notepad) and Chrome.

Extracting information from Chrome in a memdump is not a built-in feature of volatility. We chose to use the [chromehistory plugin here](https://github.com/superponible/volatility-plugins) to analyze this information. To install the plugin, clone the repository and install the following (Ubuntu 20.04, Python 2 + pip already installed):

```
# apt install python2-dev
# pip2 install pycrypto distorm3
```

Then, use the plugin by running the following:

```
$ vol.py --plugins=~/volatility-plugins -f forensics-challenge-1.mem --profile="Win7SP1x64" chromehistory
...
25  https://pastebin.com/KeqPRaaY                   htesttttttttttt - Pastebin.com
...
24  http://www.mediafire.com/view/5wo9db2pa7gdcoc/  This is a png file.png - MediaFire
...
```

We chose to focus on these two records specifically. Pastebin is a service to host arbitrary text, and we highly suspected that the flag could be there. However, the contents of the paste was "htesttttttttttt" and was not very useful.

We then looked at the PNG file:

![Downloaded PNG file](downloaded.png)

We initially did not think much of this file because it was only 107 bytes long, and seemed too small to hold any information.

(to be written)

## Flag

## Appendix: Notepad

We also tried dumping the memory of `notepad`:

```
$ vol.py -f forensics-challenge-1.mem --profile="Win7SP1x64" memdump --dump-dir=. -p 3896
```

The data from this dump can be analyzed by following [this guide](https://www.andreafortuna.org/2018/03/02/volatility-tips-extract-text-typed-in-a-notepad-window-from-a-windows-memory-dump/). Assuming that the flag was in the notepad, we tried:

```
strings -e l 3896.dmp | grep govtech
strings -e l 3896.dmp | grep csg
```

But it quickly became evident that the flag was not stored here.

