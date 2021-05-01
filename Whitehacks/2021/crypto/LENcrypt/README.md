# LENcrypt
**Files**: `enc.zip` (`enc`), `LENcrypt.py`
```sh
$ ll enc
-rwxrwxrwx 1 a a 36578445 Feb  1 19:24 enc
$ file enc
enc: data
$ cat LENcrypt.py
```
```python
import sys
import binascii
def encrypt(infile, outfile, password):
    with open(infile, 'rb') as f:
        data = f.read()
    # LENcrypt!
    password = len(data)

    encoded = int(binascii.hexlify(data), 16) * password
    with open(outfile, 'wb') as f:
        f.write(encoded.to_bytes((encoded.bit_length() + 7) // 8, byteorder='big'))
...
```
This challenge provides an encryption algorithm (`LENcrypt.py`), along with a zip file containing encrypted data (`enc`). The goal of the challenge is to develop a decryption function for `enc`.

## Solving
The encryption algorithm is simple: Given a bytestring `s`, return `c = long_to_bytes(len(s)*bytes_to_long(s))`. To obtain s from c, you only need to calculate `long_to_bytes(bytes_to_long(c)//len(s))`. The difficult part of the challenge arises in trying to obtain the right value of `s`.

`len(s)` can actually be easily approximated by `len(c)-n`, where `n ~= math.log(len(c), 256)`. During the competition, I didn't use that efficient method, but instead attempted a(n inefficient) binary search for `len(s)`, using the length of the data returned by encryption as an oracle:
```python
import binascii
def decrypt(infile, l):
    with open(infile, 'rb') as f: enc = f.read()
    encoded = int.from_bytes(enc, 'big')
    encoded //= l
    return encoded.to_bytes((encoded.bit_length()+7)//8, 'big')
def getlen(data):
    encoded = int(binascii.hexlify(data), 16) * len(data)
    return (encoded.bit_length() + 7) // 8

with open('enc', 'rb') as f: enc_dat = f.read()
# cheap binary search for `l := len(s)`
enc_len = len(enc_dat)
l = 1
while getlen(b'\xff'*l) < len(enc_dat): l*=2
jmp = i #67108864
while jmp:
    jmp //= 2
    if getlen(b'\xff'*l) < len(enc_dat): l += jmp
    else: l -= jmp
print(l) #36578441
# With l obtained, decrypt the flag
assert getlen(b'\x01'*(l+1)) == getlen(b'\xff'*l) == len(enc_dat)
#with open('dec', 'wb') as f: f.write(decrypt('enc', l))
with open('dec', 'wb') as f: f.write(decrypt('enc', l+1))
```
The decrypted data is an image:
```sh
$ file dec
dec: PC bitmap, Windows 98/2000 and newer format, 4032 x 3024 x 24
```
## Flag
![](dec)
