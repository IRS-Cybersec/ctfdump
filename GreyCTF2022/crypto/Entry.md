# NUS Grey Cat The Flag 2022: 🍭 Entry
_Crypto, 500 points -> 50 points_  

> Entry task for crypto  
> - mechfrog88

## Analysis
There was a simple python script given that did some encryption as follows:
```python
import secrets

FLAG = b'grey{...}'

assert len(FLAG) == 40

key = secrets.token_bytes(4)

def encrypt(m):
    return bytes([x ^ y for x, y in zip(m,key)])

c = b''
for i in range(0, len(FLAG), 4):
    c += encrypt(bytes(FLAG[i : i + 4]))

print(c.hex())

# 982e47b0840b47a59c334facab3376a19a1b50ac861f43bdbc2e5bb98b3375a68d3046e8de7d03b4
```

Looking at what was given, we can tell that there was a pregenerated 4-byte key that was used to XOR the flag in chunks of 4 bytes.  

So to solve this challenge we will only need to find the key

## Solution
If we look at the provided flag string, we can see that the first 4 characters/bytes of the flag was already given, which is `grey`.

Given that, we just need to XOR it with the ciphertext to find the key used

Writing a simple python function will get it done:
```python
search = b'grey'

def find_key(payload):
    k = b''
    for i in range(len(payload)):
        k += bytes([payload[i] ^ search[i]])

    return k
```

That obtains the key for us, which is `ff5c22c9` (in hex)

After that, we just need to XOR the remaining bytes to find the flag.

### Full solve script
```python
c = '982e47b0840b47a59c334facab3376a19a1b50ac861f43bdbc2e5bb98b3375a68d3046e8de7d03b4'
c = bytes.fromhex(c)

p = b''
key = b''
search = b'grey'

def find_key(payload):
    k = b''
    for i in range(len(payload)):
        k += bytes([payload[i] ^ search[i]])

    return k

def encrypt(m, k):
    return bytes([x ^ y for x, y in zip(m,k)])

for i in range(0, len(c), 4):
    if i == 0:
        key = find_key(bytes(c[0:4]))
        print(key.hex())

    p += encrypt(bytes(c[i:i+4]), bytes(key))

print(p)
```

**Flag:** ```grey{WelcomeToTheGreyCatCryptoWorld!!!!}```

## Notes/Comments
- Relatively easy beginner challenge that many teams managed to solve, dropping the points down to the minimum of 50
- Main concept tested was on XOR for crypto, but writing some code was also necessary
