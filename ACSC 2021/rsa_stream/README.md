# RSA stream [crypto/100]

In RSA, if you encrypt an unknown plaintext with the same modulus but with different exponents, the plaintext is recoverable. See [CDDC last year](https://github.com/IRS-Cybersec/ctfdump/tree/master/CDDC/2020/Warp%20Gate%202/EncryptSvc2).

```python
from gmpy2 import next_prime
from pwn import group,xor
from Crypto.Util.number import long_to_bytes, bytes_to_long, getStrongPrime, inverse
from Crypto.Util.Padding import pad

f = open("chal.py","rb").read()
cipher = open("chal.enc","rb").read()

groups = [bytes_to_long(g) for g in group(256, f)]
blocks = [bytes_to_long(g) for g in group(256,cipher)]

e = 0x10001
e2 = next_prime(e)
n = 30004084769852356813752671105440339608383648259855991408799224369989221653141334011858388637782175392790629156827256797420595802457583565986882788667881921499468599322171673433298609987641468458633972069634856384101309327514278697390639738321868622386439249269795058985584353709739777081110979765232599757976759602245965314332404529910828253037394397471102918877473504943490285635862702543408002577628022054766664695619542702081689509713681170425764579507127909155563775027797744930354455708003402706090094588522963730499563711811899945647475596034599946875728770617584380135377604299815872040514361551864698426189453
flags = [g^b for g,b in zip(groups,blocks)]
def egcd(a, b): # idk
    if a == 0: return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)
_,x,y = egcd(e, int(e2))
print(x,y,e,int(e2))
m = pow(flags[0],x,n) * pow(flags[1],y,n)
print(long_to_bytes(m%n))
```
`ACSC{changing_e_is_too_bad_idea_1119332842ed9c60c9917165c57dbd7072b016d5b683b67aba6a648456db189c}`
