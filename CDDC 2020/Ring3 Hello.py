'''Very common exploit: AES in ECB-mode is practically equivalent to a
simple one-to-one function, executed in blocks of 16 bytes.
To decrypt the flag byte-by-byte, we
A) add enough padding to create a block with 15 known bytes + 1 unknown
B) Add a separate block with those 15 same bytes, and a guessed byte
C) Check if the block from (A) is equivalent to that of (B).
   If not equivalent, try another guess with (B).
The time-complexity of bruteforcing the flag this way is O(n); n being
the number of characters in the flag.
'''
from pwn import *
from math import ceil
from base64 import b64encode, b64decode
from string import printable
PAD = b'a'*(16-len('noor2ro'))
def run(guess):
    s = PAD + guess + b'A' * 15 + b'\x00'*4
    r = remote('hello.chall.cddc2020.nshc.sg', 12345)
    r.sendlineafter(': ', b64encode(s))
    [r.recvline() for i in range(3)]
    return chunked( b64decode(r.recv(999)) )
def chunked(s,c=16): return [s[i*c:i*c+c] for i in range(0,ceil(len(s)/c))]
#run(b'}')
init = b'}' #CDDC20{?????????????????eet_y0u_fri3nd}
while b'{' != init[0]:
    for guess in printable:
        ns = guess.encode() + init
        blocks = run(ns)
        if blocks[1] == blocks[5]:
            init = ns
            break
    else: break
    print(init)
