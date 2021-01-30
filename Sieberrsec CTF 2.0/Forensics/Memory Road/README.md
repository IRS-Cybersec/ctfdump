# Memory Road (1 Solve) - 5 Points

```
One of our agents managed to snag a memory dump of one of SieberrHealth's computers, can you help us take a look at the Memory Dump to see if you can find anything?
```

We are given a `Memory Road.zip`, opening it reveals 2 files: `Ubuntu1804.zip` and `ram2.lime`. Upon further inspection, we will know that `Ubuntu1804.zip` is a nicely packed Volatility Profile for linux memdumps, and we can assume that **ram2.lime is the memory dump** the description was referring to.



<u>Note:</u> Ubuntu's **default volatility version (2.6) doesn't seem to work with linux memdumps**, please grab the latest version from github (2.6.1).

## Using the Profile with Volatility to analyse the Memory Dump

Analysing memory dumps in linux is a bit more tricky as one needs to obtain a custom profile (which is already provided) in order to run volatility.

*I personally prefer to import the profiles on the go rather than dump them directly into volatility's core files.*

Firstly, we will place the profile `Ubuntu1804.zip` into a directory, say `profiles` and import the directory of profiles using `--plugins=profiles`. In the command below, after importing the profiles, we will use `--info` to find the full name of the profile imported.

```bash
 python vol.py --plugins=profiles -f ram2.lime --info | grep Linux
 
Volatility Foundation Volatility Framework 2.6.1
LinuxUbuntu1804x64    - A Profile for Linux Ubuntu1804 x64
LinuxAMD64PagedMemory          - Linux-specific AMD 64-bit address space.
linux_aslr_shift           - Automatically detect the Linux ASLR shift
linux_banner               - Prints the Linux banner information
linux_yarascan             - A shell in the Linux memory image
```

So the full name of our profile is `LinuxUbuntu1804x64` and we can use this to start running some basic commands! The first command we will run is `bash_history`. There are a lot of commands, but some catch our eye in particular:

```bash
python vol.py --plugins=profiles -f ram2.lime --profile=LinuxUbuntu1804x64 linux_bash

...
2013 bash                 2021-01-08 17:29:02 UTC+0000   echo "flphISU6ckE2IiJXRk16YA=="
2013 bash                 2021-01-08 17:29:09 UTC+0000   echo "I guess this is important!"
...
```

Base64 decoding `flphISU6ckE2IiJXRk16YA==` yields 

```
~Za!%:rA6""WFMz`
```

but no flag yet, let's continue searching!

The next command we will run is `linux_find_file` to see if any important files were stored in memory. We will run it with the `-L` flag which means to list all files stored in memory. And indeed, something catches our eye:

```bash
python vol.py --plugins=profiles -f ram2.lime --profile=LinuxUbuntu1804x64 linux_find_file -L

...
3 0xffff9e796f1f88e0 /dev/shm/flag.docx
...
```

This looks like the flag file we are looking for! Next, we can extract the file:

```bash
python vol.py --plugins=profiles -f ram2.lime --profile=LinuxUbuntuFinalx64 linux_find_file -i 0xffff9e796f1f88e0 -O flag.docx
```

We then get a complete **password-protected flag.docx**. Hmmm, I wonder where the password could be? Let's try the decoded string from above!

And indeed, this yields the flag inside the docx:

```
IRS{1iNuX_m3mD5mp!}
```





## Learning Points:

- Basic Linux memory forensics using Volatility