'''Basically:
1. run hex-rays on all binaries
2. extract relevant variables with bash script
3. run this script
'''

def solve(s1: bytes, s2: bytes, mod: int, l: int) -> bytes:
    def ck(c,i): return (i*c%mod+c+i)%73+48
    res = []
    for i in range(l):
        possible = []
        for b in range(32,127):
            if ck(b,i) == s1[i] and ck(b,s1[i]) == s2[i]:
                possible.append(b)
        if len(possible) != 1:
            print("WARNING: got multiple possibilities for index %d: %r" % (i, possible))
        res.append(possible[0])
    return bytes(res)

def pw_for(fname: bytes) -> bytes:
    with open(b"vars/%s.out.c.vars" % fname, "rb") as f:
        mod = int(f.readline())
        s1 = eval(b'b"'+f.readline()[:-1]+b'"')
        s2 = eval(b'b"'+f.readline()[:-1]+b'"')
        l = int(f.readline())
    return solve(s1,s2,mod,l+1)

from pwn import *
r = remote('challs.nusgreyhats.org', 10523)
for _ in range(3): r.recvline()
r.sendline('y')
context.log_level = 'debug'
while 1:
    fname = r.recvline().split(b': ')[-1].strip()
    r.sendline(pw_for(fname))
exit()
