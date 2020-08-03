from pwn import *
from pickle import load
with open('lcg.formatted', 'rb') as f: lcg_f = load(f)
print('done loading')
r = remote('chals.whitehacks.ctf.sg', 10002)
#r = process(['python3.8', './server.py'])
seen = {}
history = []
for i in range(4000):
    r.sendlineafter('waifu?','')
    r.recvuntil('waifu is ')
    waifu = r.recvline().strip()
    history.append(waifu)
    #if waifu in seen: print("MATCH from %r to %d" % (seen[waifu], i))
    seen[waifu] = seen.get(waifu, ()) + (i,)
log.info('Long IO finally finished')

possible_t = None
for waifu in seen:
    potential_t = set(map(lambda t: t[1], lcg_f[seen[waifu]]))
    if possible_t == None: possible_t = potential_t
    else: possible_t &= potential_t
av = possible_t.pop()

log.info("a-v pair: %r" % (av,))
with open('lcg.dump', 'rb') as f: lcg_d = load(f)
waifu_dict = {}
for i in range(4000): #assert
    waifu_dict[lcg_d[av][i]] = history[i]
log.info("numbers mapped to waifu history")

the_rest = lcg_d[av][4000:]
for i in range(250):
    r.sendlineafter('waifu?', waifu_dict[the_rest[i]])
    r.recvuntil('waifu is ')
    assert r.recvline().strip() == waifu_dict[the_rest[i]]
r.interactive()
