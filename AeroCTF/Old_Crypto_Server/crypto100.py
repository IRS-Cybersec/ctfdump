from base64 import b64decode
from pwn import *
#r = remote('tasks.aeroctf.com', 44323)
r = remote('localhost', 4444)
init = '}' + '\x00'*16 + '1234567890' #pad with 1 block of null bytes, +10 fluff bytes
#start init with a closing '}' because only hexademical chars will be bruted from the flag
blockify = lambda s: [s[i*16:i*16+16] for i in range(len(s)//16)]
def test(msg):
    r.sendlineafter('> ', '3')  #ignore the other options
    r.sendlinethen('secret: ', msg) #send a payload message, throw away formatted response
    st = r.recvline()[2:-1] #get the server's reply. indexing is to remove b''
    return blockify(b64decode(st))   #decode & split the reply
    #assert blockify(v)[0] == blockify(v)[-1] #basis of whole exploit
while 1:
    for guess in range(48, 58)+range(97,103): #The flag is purely hexademical [0-9a-f]
        ns = chr(guess)+init
        try: blocks = test(ns)
        except EOFError: #the server disconnects every 3 seconds
            #r = remote('tasks.aeroctf.com', 44323)
            r = remote('localhost', 4444)
            blocks = test(ns)
        if blocks[0] == blocks[4]:
            init = ns
            break
    else: break
    print(init[:32])
print("Aero{%s}" % init[:32])
