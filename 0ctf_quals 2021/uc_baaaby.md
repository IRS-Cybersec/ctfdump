# uc_baaaby
Unicorn is good, ummh?

`nc 111.186.59.29 10087`

**Files**: Dockerfile, uc_baaaby.py:
```python
#!/usr/bin/env python
from unicorn import *
from unicorn.x86_const import *
import os
import sys
import struct
import hashlib

FLAG = 'flag{xxxx}'
CODE = 0xdeadbeef000
DATA = 0xbabecafe000
finished = False
insn_count = 0
block_count = 0


def hook_block(uc, address, size, user_data):
    global block_count
    block_count += 1
    if block_count > 1:
        print('No cheating!')
        uc.emu_stop()


def hook_code(uc, address, size, user_data):
    global insn_count, finished
    insn_count += 1
    if address == CODE + 0x2000:
        finished = True


def play():
    global finished
    uc = Uc(UC_ARCH_X86, UC_MODE_64)

    code = os.read(0, 0x2000)

    uc.mem_map(CODE, 0x3000, UC_PROT_READ | UC_PROT_EXEC)
    uc.mem_write(CODE, code)
    uc.mem_write(CODE + 0x2000, b'\xf4')

    check_data = os.urandom(50)
    uc.mem_map(DATA, 0x1000, UC_PROT_READ | UC_PROT_WRITE)
    uc.mem_write(DATA, check_data)

    uc.hook_add(UC_HOOK_CODE, hook_code)
    uc.hook_add(UC_HOOK_BLOCK, hook_block)

    try:
        uc.emu_start(CODE, CODE + 0x3000)
    except UcError as e:
        finished = False
        return False

    user_data = uc.mem_read(DATA + 0x800, 16)
    if user_data == hashlib.md5(check_data).digest():
        print('Nice.')
        return True
    else:
        print('0ops.')
        return False


if __name__ == '__main__':
    print('Welcome to uc_baaaby')
    win = play()
    if finished and win:
        print("Congratulation! You've reached the end!")
        print(f'You took {insn_count} seconds.\n')
        if insn_count < 0x233:
            print('How is this possible??? Even Bolt can\'t run this fast.')
            print('Prize for you:', FLAG)
        elif insn_count < 0x300:
            print('Come on. You can be faster.')
        else:
            print('Gege jia you.')
```
## Solving
The challenge is very simple to understand.

Unicorn Engine is used to emulate two memory spaces: an executable page (at `CODE == 0xdeadbeef000`) and a read-write page (at `DATA == 0xbabecafe000`). `CODE[:0x2000]` is filled with user-provided shellcode; `CODE[0x2000:0x3000]` is filled with the `hlt` instruction. `DATA[:50]` is filled with 50 random bytes from `os.urandom`.

The shellcode provided to the challenge must terminate without errors with the following conditions:

1. No `jmps`, `syscalls`, `calls`, etc. occured (i.e. Unicorn did not detect more than one code block)
2. `rip == CODE+0x2000`
3. The total number of assembly instructions executed was less than `0x233`.
4. `*(uint128_t*)(DATA+0x800) == md5sum(DATA[:50])`

The last two parts _seem_ very difficult, but I managed to find a [working md5 assembly implementation from google](https://www.nayuki.io/res/fast-md5-hash-implementation-in-x86-assembly/md5-fast-x8664.S) after some time. You only need a little bit of glue (and -Mintel conversion) in editing the linked implementation to get it to work for this challenge:
```python
sc = 'mov rsp, {}\n'.format(hex(DATA+0x400))
sc+= 'mov rdi, {}\n'.format(hex(DATA+0x800))
sc+= 'mov DWORD PTR [rdi], 0x67452301\n'
sc+= 'mov DWORD PTR [rdi+4], 0xEFCDAB89\n'
sc+= 'mov DWORD PTR [rdi+8], 0x98BADCFE\n'
sc+= 'mov DWORD PTR [rdi+0xc], 0x10325476\n'
sc+= 'mov rsi, {}\n'.format(hex(DATA))
sc+= 'mov BYTE PTR [rsi+50], 0x80\n'
sc+= 'mov WORD PTR [rsi+56], 0x190\n'
sc+= ... # insert unrolled code from online here
```
Once that's done, the only problem remaining is (1). Googling for ["longest assembly instruction"](https://stackoverflow.com/a/18972014) provides a similar quick answer. Although _real_ processors will not accept an infinite number of prefixes, Unicorn is okay with them:
```python
payload = asm(sc, vma=CODE).ljust(0x2000-2, b'\x67') + b'\x89\xe5' # just "mov sp, bp" but with a really long prefix
with open('payload.bin', 'wb') as f: f.write(payload)
```
I send the payload manually via `nc` here because of buffering issues with the challenge server:
```sh
$ nc 111.186.59.29 10086 < payload.bin
Welcome to uc_baaaby
Nice.
Congratulation! You've reached the end!
You took 553 seconds.

How is this possible??? Even Bolt can't run this fast.
Prize for you: flag{Hope_you_found_the_problem}
```
