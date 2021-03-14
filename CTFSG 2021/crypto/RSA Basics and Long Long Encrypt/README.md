# RSA Basics and Long Long Encrypt

A overtly detailed writeup on RSA basics and Long Long Encrypt from CTF.SG CTF



### Some RSA basics you need to know

###### What is RSA

RSA is a public-key cryptosystem, which means each RSA key pair has a public key used for encryption (usually denoted with `n`, `e`) and a private key used for decryption (usually denoted as `n`,` d`). The idea is that the private key should be extremely difficult (practically impossible) to attain even with the public key being publicly available. In an RSA challenge, you are usually given the values of `n`, `e` and `c`. 



###### Some important RSA equations

For any (that I am aware of) RSA, the following equations are true:



![Math1](/Users/see.min./Desktop/Math1.png)



where `m` is the plaintext and `c` is the ciphertext, both in Decimal (base 10).



###### Euler's totient function

See that![Math2](/Users/see.min./Desktop/Math2.png)?

That's [Euler's totient function](https://en.wikipedia.org/wiki/Euler%27s_totient_function) and a general formula for it is, 

where![Math3](/Users/see.min./Desktop/Math3.png),

![Math4](/Users/see.min./Desktop/Math4.png)



For standard RSA, ![Math5](/Users/see.min./Desktop/Math5.png), thus![Math6](/Users/see.min./Desktop/Math6.png) .



### Long Long Encrypt

A RSA-variant challenge. 



###### Files given

The challenge has 2 files attached, `txt.enc`  and `encrypt.py` .

Since I wasn't sure about the file format `.enc` I ran `exiftool` on it.

```shell
$ exiftool txt.enc
ExifTool Version Number         : 12.03
File Name                       : txt.enc
Directory                       : .
File Size                       : 65 kB
File Modification Date/Time     : 2021:03:14 11:54:58+08:00
File Access Date/Time           : 2021:03:14 11:54:59+08:00
File Inode Change Date/Time     : 2021:03:14 11:54:58+08:00
File Permissions                : rw-r--r--
File Type                       : TXT
File Type Extension             : txt
MIME Type                       : text/plain
MIME Encoding                   : us-ascii
Newlines                        : Unix LF
Line Count                      : 3
Word Count                      : 9
```

See that `File Type: TXT` ? So it's just a simple `.txt` file,, _phewww_. I changed the file extention to `.txt` and opened it, which gave us the values of `n`, `e` and `c` . 

The other file `encrypt.py` opens to give us the following code

```python
def is_prime(n):
    # Implement some prime checking function here
    return True  # Placeholder

def bti(s):
    out = 0
    for i in s:
        out = (out * 256) + ord(i)
    return out

def encrypt():
    fp = open('params.txt', 'r')
    p = int(fp.readline())
    q = int(fp.readline())

    assert is_prime(p)
    assert is_prime(q)

    n = p**q
    e = 1000000000000000003

    assert (p-1) % e != 0

    fc = open('flag.txt', 'r')
    m = bti(fc.read())

    if (m > n):
        print("PANIC")
        return

    c = pow(m, e, n)

    print(f'n = {n}')
    print(f'e = {e}')
    print(f'c = {c}')


if __name__ == '__main__':
    encrypt()
```



###### Solving the challenge

There are 2 processes here. Firstly, `m`  is derived from the plaintext using a really convulated method through the function `bti`.  `m` is then encrypted using a method which looks extremely like RSA, since `c = pow(m, e, n)` and `n` is derived from 2 primes, `p` and `q`. 



What we have to do it to basically reverse this process, thus we start with the decryption process first. Although `n` is extremely huge ( `len(str(n)` is 33246), which usually is a headache, notice in the code that `n = p**q`. Thus  `p` and `q`  are actually relatively small and can be bruteforced.  Using SageMath,

```python
n = # can be found in txt.enc file given. Too big so am not including it here.
for k in range(1,10000): # On hindsight, should have just done range(2, 10000)
	p = n**(1/( k + 1 ))
	if p.is_integer():
    q = k + 1
		print(q)
		print(p)
    break
```

which outputs:

```shell
1709
28375637489003756813
```

 Now that we have `p = 28375637489003756813`, we can easily find $φ(n)$. In this case,
$$
φ(n) = n(1 - \frac{1}{p})
$$
Since 
$$
d · e = 1 (mod \ φ(n))
$$
and 
$$
m ≡ c^d (mod \ n)
$$
Using SageMath, as usual:

```python
# n and c values not included here as they are too large. Can be found in txt.enc file.
n =
e = 1000000000000000003
c = 
p = 28375637489003756813
phi = n*(1-(1/p)) # phi is the totient
d = inverse_mod(e, phi) # solves for d given e and phi and that d · e = 1 (mod φ(n))
m = power_mod(c, d, n) 
print(m)
```

_The output is another monstrously large number so I shall not include it here_



We then need to reverse the `bti` function, which is:

```python
def bti(s):
    out = 0
    for i in s:
        out = (out * 256) + ord(i)
    return out
```

To reverse `bti`:

```python
while (m % 256) != 0:
        r = m % 256
        print(long_to_bytes(r)) # r = ord(i) so r is the ASCII value of a single letter
        m = (m - r)/256
```

Output:

```shell
b'\n'
b'.'
b'}'
b's'
b'N'
b'a'
b'3'
b'r'
b'0'
b'p'
b'a'
b'g'
b'N'
b'1'
b's'
b'_'
b'W'
b'0'
b'l'
b'l'
b'E'
b'f'
b'_'
b'Y'
b'm'
b'{'
b'G'
b'S'
b'F'
b'T'
b'C'
...
```

_Since we directly reversed `bti`,  the output started from the last character of the plaintext_



Thus the flag is `CTFSG{mY_fEll0W_s1Ngap0r3aNs}`.



###### Complete script

With SageMath,

```python
from Crypto.Util.number import long_to_bytes

n = 121360368116861606771833968655964769506728397093212974761176901482618556577>
e = 1000000000000000003
c = 453246072138683036588870912791417875498198293457546189333353544414234374765>

for q in range(2,10000):
	p = n**(1/(q))
	if p.is_integer():
		break

phi = n*(1-(1/p))
d = inverse_mod(e, phi)
m = power_mod(c, d, n)

while (m%256) != 0:
	r = m % 256
	print(long_to_bytes(r))
	m = (m - r)/256
```



### Other stuff you may want to know

- To convert from a `string` to `int`, we can use `from Crypto.Util.number import bytes_to_long`. The specifics of this is that the `string` is converted to `hex` and then from `base 16` to `base 10`. For example, 'Crypto' is '`0x43` `0x72` ` 0x79` `0x70` `0x74` ` 0x6f`' which is the same as '`0x43727970746f`'. Converting '`0x43727970746f`' from `base 16` to `base 10`, we get the `int` '74158942745711'.
- To convert from `int` to `string`,  use `from Crypto.Util.number import long_to_bytes`. 

- Some common attacks on standard RSA include small exponent attack and wiener's attack. Other approaches include using [Factordb](http://factordb.com) and the elliptic curve factorization method (ECM).
