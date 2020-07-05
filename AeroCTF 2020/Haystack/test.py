from pwn import *
import re, subprocess
#r = remote('tasks.aeroctf.com', 44324)
r = remote('localhost', 4444)
context.log_level = 'debug' #keep this to see the flag easily
try:
    for i in range(35): #flag is printed for cycle ~30
        f = re.findall('<[0-9a-f]*>', r.recvline())
        output = subprocess.check_output(['./a.sh',f[0][1:33]])
        if output[-1] == '\n': output = output[:-1] #clearance
        r.recvuntil('Token: ')
        r.sendline(output)
except EOFError: pass
