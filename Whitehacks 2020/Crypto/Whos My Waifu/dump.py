import math
from faker import Faker
import sympy
import Crypto.Random.random as random
import pickle as p

class LCG():
    def __init__(self, a,v, mod=131): 
        # Mod should be a prime number
        while not sympy.isprime(mod):
            mod -= 1
            if mod == 1:
                print("You done messed up good")
                raise Exception

        #a = v = 100
        #while math.gcd(a, v) != 1:
        #    a = random.randrange(mod)
        #    v = random.randrange(mod)

        self.a = a
        self.v = v
        self.mod = mod #131
        self.counter = 0

    def next_bag(self):
        self.v += self.a
        self.value = 1

    def get_next(self):
        if self.counter == 0:
            self.next_bag()
            self.counter = self.mod // 2

        self.value = (self.a * self.value + self.v) % self.mod
        self.counter -= 1
        return self.value
ls = {}
for a in range(131):
    for v in range(131):
        if math.gcd(a,v) != 1: continue
        lcg = LCG(a,v)
        ls[(a,v)] = tuple(lcg.get_next() for i in range(5000))
    with open('lcg.dump', 'wb') as f: p.dump(ls, f)
