# CDDC 2020: Warp Gate 4

## Recycling Bin

***Found this file in one of the Unduplicitous Corp's PCs Recycle Bin. Can you walk me through this?***

______

We are given a `1.img` file which is most likely an image of the computer's recycling bin. Let's use `testdisk` for this challenge!

1. `testdisk 1.img`
2. `[Proceed]` on Disk 1.img
3. Select `[None]`
4. Select `[Analyse]`
5. Select `[Quick Search]`
6. Press `P` to list files.

```
TestDisk 7.0, Data Recovery Utility, April 2015
Christophe GRENIER <grenier@cgsecurity.org>
http://www.cgsecurity.org
P ext4                     0   0  1     2 140 10      40960
Directory /

drwxr-xr-x  1000  1000      1024  3-Apr-2020 15:42 .
drwxr-xr-x  1000  1000      1024  3-Apr-2020 15:42 ..
drwx------  1000  1000     12288  3-Apr-2020 15:29 lost+found
-rwxr--r--  1000  1000   6882200  3-Apr-2020 15:39 CSASingaporeCyberLandscape2018.pdf
-rwxr--r--  1000  1000     51929  3-Apr-2020 15:39 Cybersecurity.png
-rwxr--r--  1000  1000     57916  3-Apr-2020 15:39 pic1.jpg
-rwxr--r--  1000  1000    151175  3-Apr-2020 15:39 security-challenge.jpg
-rwxr--r--  1000  1000   2448714  3-Apr-2020 15:39 SingaporeCybersecurityStrategy.pdf
-rwxr--r--  1000  1000     17614  3-Apr-2020 15:39 speech.docx
-rwxr--r--  1000  1000      8881  3-Apr-2020 15:39 test.xlsx
-rwxr--r--  1000  1000      8881  3-Apr-2020 15:39 test.zip

Next
Use Right to change directory, h to hide deleted files
 q to quit, : to select the current file, a to select all files
 C to copy the selected files, c to copy the current file
```

Only `test.xlsx` is highlighted in red. Use `c` to recover the file from the `img` file.

Opening the file reveals the flag.

### Flag

_______

```
CDDC20{cArv3_C4Rve_CaRV33eE}
```