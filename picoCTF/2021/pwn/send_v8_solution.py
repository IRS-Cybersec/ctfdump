#!/usr/bin/env python3
from pwn import *
try:
    PORT = int(sys.argv[1])
    exp = read(sys.argv[2])
except Exception:
    print(sys.argv[0], 'PORT', 'JS_SOURCE')
    exit()
r = remote('mercury.picoctf.net', PORT)
r.sendlineafter('5k:', str(len(exp)))
r.sendafter('!!\n', exp)
r.interactive()
