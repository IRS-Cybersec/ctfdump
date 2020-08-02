# RSC (3/4)

Made as self-gratification by the unsavory egomaniac that is @N00bcak.

### Problem Description

<img src="https://github.com/IRS-Cybersec/ctfdump/blob/master/Whitehacks%202020/Crypto/RSC/images/dontbelikebill.png" style="zoom: 20%;" />

Download `vals.txt` and decrypt the value of `c` given all the other parameters.

Author: lord_idiot (don't slap me for not doing **JIF** pls)

#### Contents of `vals.txt`

``````reStructuredText
n = 11221486953303479169418636958653777962386728091356875592462654735611792654962616720924881759568872511661747203368844081583564223606024702703957398828665129158363177792865136615710168537563842048353782583875449446010069016297453969147973960956159215562005875837895351452492570297884476840721412696164166045179843138435408476602958581054284009152430396325297356892528210363745353045269636158061363637600037031454774867796221323101685389216688943928402267875718382470111569241535645334550389269646665616886098195858557710728877438949506112533516698636281059854132213
e = 5
c = 5186367422103874157090916132632280469871488070367507139356845142093882635033592715570141522344578961127916716740707327801003444940780882832591040571543694610433978956607750610019346649502302981892861825108412103504559101570281780378069348779542080915902548029421012721550682007277631135919290523418366666400363413393180215601137752319079758397029847944474559557938050825239560862777837213217404830890765947951522619073240491299382567391929179295744685619035883778423271693460277199564254745454121960352229386151705327062275879238457321618893496060128827986777102
``````

where `e` is the public exponent, `c` is the encrypted ciphertext, and `n` is a [semi-prime](https://en.wikipedia.org/wiki/Semiprime) modulus.

### Thonkeng Teem

#### 1. The meme is very cool. But what does it meme?

A cursory Google search would bring you to [this page](https://crypto.stackexchange.com/questions/9106/rsa-padding-what-is-it-and-how-does-that-work), where you would see this:

``````markdown
**Padding in cryptography means adding a (mostly secret) random set of data to the cryptographic functionality.

In practice and when done correctly, cryptographic padding adds a cryptographic problem and thereby reduces attack vectors because (theoretically) it reduces the success in “guessing” intermediate or final states of the encryption and/or decryption functionality.
``````

#### 2. That's cool. But I was wondering about the *ABSENCE* of padding.

[I've got you covered.](https://crypto.stackexchange.com/questions/3608/why-is-padding-used-for-rsa-encryption-given-that-it-is-not-a-block-cipher) [Also this one.](https://crypto.stackexchange.com/questions/1448/definition-of-textbook-rsa)

``````markdown
1. RSA has a lot of **mathematical structure**, which leads to weaknesses. Using correct padding prevents those weaknesses.
2. It is **deterministic**, and thus not semantically secure. I.e., I can distinguish between the encryptions of 0 and 1 (simply by encrypting both values myself and comparing the ciphertexts).
``````

#### 3. No I don't understand explain at once or I shall slap your pancake phizog.

Basically,

1) If the RSA ciphertext has **NO PADDING**, it is <u>egregiously easy</u> to reverse it.

- You can literally just <u>reverse the encryption process</u> (or decrypt it if you were a monkey like me)

2) Because RSA is **basically math**, it is <u>shockingly simple</u> to do so.

- This will come in handy right about now.

### Progreming Tiem

Remember how I said it was dead easy to reverse the RSA?

Yeah turns out that **wasn't so apparent** to me at the time.

So instead of the correct solution, I'll show my tiny brain so you can learn some more cool stuff.

#### 1. Decrypting RSA (monkey-brain)

RSA decrypts by utilising a private exponent `d`, where <br>
![wow](https://github.com/IRS-Cybersec/ctfdump/blob/master/Whitehacks%202020/Crypto/RSC/images/RSAexponential.png)<br>
where `m` is the plain(hex) message.

Because <u>*RSA says so*</u>, `e` and `d` are related by <br>
![again](https://github.com/IRS-Cybersec/ctfdump/blob/master/Whitehacks%202020/Crypto/RSC/images/RSAinverseexponential.png)<br>
where `λ(n)` is the Carmichael totient function of `n`.

You do not need to know what the Carmichael totient function is, but [in case you're curious.](https://en.wikipedia.org/wiki/Carmichael_function)

##### So I just need to find it right? So easy OK program now.

Well, **that's what I thought.**

Except...

**The Carmichael totient function has an absolutely HORRIBLE time complexity.**

More specifically, (my code in particular) is <u>at least</u>
![big O](https://github.com/IRS-Cybersec/ctfdump/blob/master/Whitehacks%202020/Crypto/RSC/images/On2logn.png)
Which doesn't sound so bad.

Until you realise that's about **FOREVER** for an n with 100s of digits 

- For those who don't know big O, a computer can do around 9 digits' calculations every second
- Meaning you'll be here for an eternity and it **still won't be done**.
- That's not even taking into account the speed hindrance

Oh well, if you want the program so bad...

``````python
from decimal import Decimal
def egcd(a, b): #Euclidean GCD
    if a==0:
        return (b,0,1)
    else:
        g,y,x= egcd(b%a,a)
        return (g,x-(b//a)*y,y)

def modinv(a, m): #Finding Modular Inverse
    g,x,y=egcd(a,m)
    if g != 1:
        raise Exception('MMI does not exist you are SCREWED.') 
        #Luckily I didn't wait to get here.
    else:
        return x%m
    
def carmichael(n): #See Carmichael totient function.
    coprimes = [x for x in range(1, n) if gcd(x, n) == 1]
    k = 1
    while not all(((x**k)% n) == 1 for x in coprimes): 
        #Decimal not supported by pow. sad.
        k += 1 
    return k

#pretend that c,n,e are Decimals. I can't stand their grotesque size.
print("Working on carmichael")
cm=carmichael(n)
d = modinv(e,n)
print(d)
print("decrypt!")
print((c**d)%n)
``````

Anyways,

#### 2. Reverse-Encrypting RSA (big brain)

Let's bring to your attention a few details:

1. [*It is <u>egregiously easy</u> to reverse it*](https://github.com/IRS-Cybersec/ctfdump/blob/master/Whitehacks%202020/Crypto/RSC/RSC.md#3-no-i-dont-understand-explain-at-once-or-i-shall-slap-your-pancake-phizog)
   - No padding, remember?
2. [*It is <u>shockingly simple</u> to do so.*](https://github.com/IRS-Cybersec/ctfdump/blob/master/Whitehacks%202020/Crypto/RSC/RSC.md#3-no-i-dont-understand-explain-at-once-or-i-shall-slap-your-pancake-phizog)
   - Notice that `e` is 5. That's VERY small. We could do something about that

Now that we're on the same page, if
 <br>
![wow1](https://github.com/IRS-Cybersec/ctfdump/blob/master/Whitehacks%202020/Crypto/RSC/images/RSAexponential.png)<br>

Then it stands to reason that<br>
![wow2](https://github.com/IRS-Cybersec/ctfdump/blob/master/Whitehacks%202020/Crypto/RSC/images/RSAvalueofm.png)<br>
where `k` is some constant for which <br>
![wow3](https://github.com/IRS-Cybersec/ctfdump/blob/master/Whitehacks%202020/Crypto/RSC/images/RSAethroot.png) <br>
is an integer.

Hence, we just need to find `k`.

### The Code

You **could** do some modular mathemagicks (I guess?), but I opted to brute-force because I AM a <u>monkey-brain</u>.

The time complexity is MUCH better at
![wow4](https://github.com/IRS-Cybersec/ctfdump/blob/master/Whitehacks%202020/Crypto/RSC/images/On.png). <br>
Anyways,

``````python
#again, just pretend n,e,c exist.
from decimal import *
getcontext().prec = 1000
N=Decimal(n)
E=Decimal(e)
C=Decimal(c)
for k in range(1,1000): #I got lucky that k was 35.
    R=Decimal((k*N+C)**(E))
    if(R!=R.to_integral_value()):
        print("R for {}: {}".format(k,R))
        print("Integer Form of R: {}".format(R.to_integral_value()))
    else:
        print("Yay! {}".format(R.to_integral_value()))
        break
``````

Decrypting `m` (hex) we get our flag...

``````
WH2020{Pl3as3_r3memBer_to_pAD_ur_RSA_m3ssag3s!}
``````

