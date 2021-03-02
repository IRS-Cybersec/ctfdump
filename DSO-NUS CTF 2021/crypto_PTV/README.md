# Protect The Vaccine!
```A nation-supported hacker group is using their cutting edge technology to attack a company that develops vaccine. They roll their own crypto with a hope that it will be more secure. Luckily, we have got some of their crypto system information and also have found some research that is likely to break their crypto system. I heard you are a cipher breaker, could you help us to decrypt their secret and protect the vaccine from their plan?```

## Reconnaissance
We are given the 2020 paper by Amir Hamzah, Mhd. Rezal, and Mhd. Azraf, [A New LSB Attack on Special-Structured RSA Primes](https://www.mdpi.com/2073-8994/12/5/838), and an encryptor file as below:

```python
from config import a,b,m,r_p,r_q,secret
from Crypto.Util.number import bytes_to_long

p = a**m + r_p
q = b**m + r_q
N = p*q
e = 65537

M = bytes_to_long(secret)
c = pow(M, e, N)

print('N:', N)
print('e:', e)
print('r_p:', r_p)
print('r_q:', r_q)
print('c:', c)
```

The paper itself describes an attack on **primes of the special form ![](https://render.githubusercontent.com/render/math?math=$n^{m}%2Br$)**, where `n,m,r` are secret integers.

Ostensibly this is of the same form as the primes p and q in this challenge.

**At this point I heaved a protracted sigh of disappointment, deflating and slouching upon my chair as a leaky balloon prostrates upon the floor.**

**If Uncle Roger were here he would put down his leg. H A I Y A A.**

## On The Challenge Itself

It should be painfully obvious that whoever made this challenge simply wanted us to implement the attack.

The proofs and conceptual framework are thus insignificant. It is a nice paper though.

Below is a brief explanation of the attack:
1. Compute ![](https://render.githubusercontent.com/render/math?math=$i=\lceil%20r_{p}r_{q}%20\rceil$).
2. Thus compute ![](https://render.githubusercontent.com/render/math?math=$\sigma%20=%20(\lceil%20\sqrt{N}%20\rceil%20-%20i)^{2}$) and ![](https://render.githubusercontent.com/render/math?math=$\z%20\equiv%20N-(r_{p}r_{q})%20\pmod%20\sigma$).
3. Then solve the quadratic equation ![](https://render.githubusercontent.com/render/math?math=$X^{2}-zX%2B\sigma%20r_{p}r_{q}=0$).
4. So compute ![](https://render.githubusercontent.com/render/math?math=$p=\frac{x_{1}}{r_{q}}%2Br_{p}$), and ![](https://render.githubusercontent.com/render/math?math=$q=\frac{x_{1}}{r_{p}}%2Br_{q}$)
5. If you do not get integer solutions for `p` and `q`, increment `i` and go to step 2.
6. Otherwise, you have factorized `p` and `q`.

There really is no need to explain anything else. Let's claim our flag and walk away in dejection...

## The Script & The Flag
```python
from Crypto.Util.number import long_to_bytes
N=3275733051034358984052873301763419226982953208866734590577442123100212241755791923555521543209801099055699081707325573295107810120279016450478569963727745375599027892100123044479660797401966572267597729137245240398252709789403914717981992805267568330238483858915840720285089128695716116366797390222336632152162599116524881401005018469215424916742801818134711336300828503706379381178900753467864554260446708842162773345348298157467411926079756092147544497068000233007477191578333572784654318537785544709699328915760518608291118807464400785836835778315009377442766842129158923286952014836265426233094717963075689446543
e=65537
r_p=5555
r_q=2021
c=1556192154031991594732510705883546583096229743096303430901374706824505750761088363281890335979653013911714293502545423757924361475736093242401222947901355869932133190452403616496603786871994754637823336368216836022953863014593342644392369877974990401809731572974216127814977558172171864993498081681595043521251475276813852699339208084848504200274031750249400405999547189108618939914820295837292164648879085448065561197691023430722069818332742153760012768834458654303088057879612122947985115227503445210002797443447539212535515235045439442675101339926607807561016634838677881127459579466831387538801957970278441177712

# I believe all you need to do is follow the instructions...
i=ceil(sqrt(r_p*r_q))

factorized=False
while not factorized:
    sigma=(int(sqrt(N))-i)**2
    z=int(Mod(N-r_p*r_q,sigma))
    print(i)

    x=var('x')
    S = solve(x^2-z*x+sigma*r_p*r_q==0,x,solution_dict=True)

    for soln in S:
        if not soln[x].is_integer():
            print("No solution :(((")
            break
        else:
            print(f"Got Solution! {soln[x]}")
            factorized=True
    i+=1
# Turns out we got lucky. At i=3379 we receive
x1=168200524686562144694620288802920098491216735170837810125672320002939647866974222365012727452940769281308849288903115688589419797624616813460735137583543839726240553545302460214475263890124428240711467804365871217554755973866852861234743770756153485545678683848833029401921482153203747584834969282377159947080780
x2=218640963841168131005470550035379468161157139960153907690360606758392731649074205802111908622011434335143690091387592220823296028451227124397192393817824166806698902839833001318765091590325160563899341911850960055105827530299680127408632836041078255714159019688574965424438294715765508204336190307241026142672404

q=(x1/r_p)+r_q
p=(x2/r_q)+r_p
print(p*q==N)

totient=(p-1)*(q-1)
d=inverse_mod(e,totient)
print(long_to_bytes(pow(c,d,N)))
```

And thus we receive the flag: `Let's meet at Yichun on 30 Feb. On that day, say 'DSO-NUS{851f6c328f2da456cbc410184c7ada365c6d1f69199f0f4fdcb9fd43101ce9ee}' to confirm your identity.`