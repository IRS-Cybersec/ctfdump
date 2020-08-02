# Whitehacks: Crypto
**Who's My Waifu**

300; 1 SOLVES

_Can you guess our waifus?_

`nc chals.whitehacks.ctf.sg 10002`

Author: prokarius

ATTACHED FILES: `server.py`

## Beginning
```bash
$ wc server.py 
 100  422 3888 server.py
```
That's really, really long! Let's shorten that into the [Appendix](#server), and focus on a few snippets here.

First off, we'll have a look at what the `main()` does.
```python
gacha, faker, solves, tries = Gacha(), Faker(), 0, 5000
while tries:
    #...
    correct = gacha.get_next_shipgirl()
    guess = input()
    if (guess == correct):
        solves += 1
        print("Wow that is correct!")
    else:
        solves = 0
        print("Sorry, that is not correct...")
    print(f"{name}'s waifu is {correct}")
    if (solves == 250): #win
    #...
```
Essentially, the python file needs the remote to correctly guess 250 waifus in succession. 

That is not easy, because
 * the list of ship girls (`self.shipgirls`) is randomised:
```python
class Gacha():
    def __init__(self):
        self.shipgirls = [ "weeb stuff" ]	# len() == 131
        random.shuffle(self.shipgirls)		# important!
	#...
```
 * the LCG seed (represented by `a` and `v`) is _also_ randomised:
```python
class LCG():
    def __init__(self, mod=131): 
        a = v = 100 #Initalised to 100; set to a random int within (0,mod)
        while math.gcd(a, v) != 1: a, v = random.randrange(mod), random.randrange(mod)
        self.a, self.v, self.mod, self.counter = a, v, mod, 0
```
You can verify this with a number of tests:
```
~$ python3.8 server.py
...
OK, what is Sabrina King's waifu?
hi
Sorry, that is not correct...
Sabrina King's waifu is Le Triomphant
...
~$ python3.8 server.py
...
OK, what is Patrick Park's waifu?
hi
Sorry, that is not correct...
Patrick Park's waifu is Jenkins
...
```
We'll have to break the curse of RNG and find out what dakimakura Sabrina Park has ahead of time. The only question is how.

## Data-gathering

Given that we get a startling 5000 good tries for a mere 250 successes, I figured that the most important thing to do first was to collate a sequence of positive waifu tests from the server. The LCG is _linear_, and a long enough output history from the server might be enough to reproduce the initial seed.

A little bit of pwnscript later, and we can grab a sufficient baseline input:
```python
r = remote('chals.whitehacks.ctf.sg', 10002) #process(['python3.8', './server.py'])
seen = {}
history = []
for i in range(4000):
    r.sendlineafter('waifu?','')
    r.recvuntil('waifu is ')
    waifu = r.recvline().strip()
    history.append(waifu)
    seen[waifu] = seen.get(waifu, ()) + (i,)
log.info('Long IO finally finished') #It takes about 10 minutes on remote. A few seconds for local
```
Here, we're collecting two pieces of data:
 1. a simple list of the waifus seen thus far (in order), and 
 2. A dict to reference the _indexes of repetition_ for every waifu

Part 2 is more important for our immediate needs. From a random sample, `seen` will contain key-pairs like:
```python
{
    ...
    b'Kalk': (126, 175, 252, 298, 542, 639, 773, 1022, 1089, 1206, 1275, 1306, 1402, 1445, 1580, 1863, 1979, 2395, 2413, 2651, 2834, 2923, 3247, 3515, 3610, 3658, 3917, 3988),
    b'Asashio': (128, 190, 324, 362, 547, 875, 955, 1058, 1382, 1454, 1545, 1633, 2028, 2246, 2396, 2550, 2662, 2837, 3006, 3114, 3177, 3214, 3316, 3598, 3654, 3828, 3998),
    b'Matchless': (136, 262, 355, 543, 764, 841, 937, 999, 1096, 1372, 1442, 1638, 1907, 1998, 2025, 2133, 2337, 2445, 2508, 2632, 2691, 2812, 2954, 3037, 3269, 3375, 3398, 3633, 3709, 3921),
    ...
}
```
If we knew of an LCG seed that causes _a_ waifu name (not necessarily Kalk) to repeat at the 126th, 175th, 252nd... occurrance, we could be _somewhat certain_ that the same LCG seed was used server-side. 

If we knew that that same seed produces identical patterns for _all recorded repetitions_ in `seen{}`, we'd be comfortably certain that the LCG seed we have is identical to the server's, barring unfortunate coincidences.

But while that _sounds_ great, LCGs were designed for semi-immunity against this kind of backtracing: it's simply not possible to guess the seed from a pattern, unless you happen to already have the seed. Having a (relatively) large pool of seed values for, e.g. `srand`, makes building a reference table of LCG patterns difficult.

The author of this challenge home-baked a personal LCG. For `class LCG`, the seed-pair (`a,v`) is limited to the range `0-130`.

With only `131**2==17161` seeds to store, backtracing LCG patterns becomes a distinct possibility.

## Building a waifu-db
To start, we'll want to generate all `17161` patterns for every distinct LCG. We can do it with a cut script, as so:
```python
import stuff
class LCG():
    def __init__(self, a,v, mod=131): 
        self.a, self.v, self.mod, self.counter = a,v,mod,0
    def next_bag(self): #...
    def get_next(self): #...
lcg_d = {}
for a in range(131):
    for v in range(131):
        if math.gcd(a,v) != 1: continue
        lcg = LCG(a,v)
        lcg_d[(a,v)] = tuple(lcg.get_next() for i in range(5000))
```
What we're creating is a dict, `lcg_d`, that has the history (up to 5000 values) of every LCG possible, indexed with `(a,v)` initial seeds.

If you understood that, then you know that the next part is to connect _these_ LCG sequences with the data collected under `seen`. To link the two together, I created a separate `dictionary`, `lcg_f`, that provides a list of (`a,v`) pairs that correlate with a given single-waifu `tuple` pattern of length 4000.

Basically, if you had a waifu that appeared (server-side) at the `5th, 17th, 31st, ...` queries, then you could cross-reference that with `lcg_f` to figure out which `(a,v)` pairs are liable to produce the same pattern. Test this enough times, and you'll know the exact `(a,v)` seed used by the server with 100% certainty.
```python
lcg_f = {}
for t in lcg_d:
    arr = lcg_d[t][:4000]
    d = {}
    for i in range(4000):
        d[arr[i]] = d.get(arr[i], ()) + (i,)
    for ind in d:
        lcg_f[d[ind]] = lcg_f.get(d[ind], []) + [(ind, t)]
```
You might also notice that the code tacks on the index `ind` of the waifu-id stored from lcg_d. We do this for reasons you'll see in a bit. First though, we'll grab the correct `(a,v)` tuple with a little bit of `set` magic:

```python
possible_t = None
for waifu in seen:
    potential_t = set(map(lambda t: t[1], lcg_f[seen[waifu]]))
    if possible_t == None: possible_t = potential_t
    else: possible_t &= potential_t
av = possible_t.pop()
```
This is needlessly inefficient, but it helps in proving that the final a-v pair _really does_ match up with all of the curled data, which is something that an alternative algorithm (like e.g. grabbing the most common matching seed) might let by.

After that, we use the a-v seed, in conjunction with the server's `history[]` obtained earlier, to build a cross-reference, mapping LCG numbers to waifus.
```python
waifu_dict = {} #Think of it like a booru ID matching to an image.
for i in range(4000): waifu_dict[lcg_d[av][i]] = history[i]
```
Finally, we can use the `waifu_dict` plus `lcg_d` to pull off accurate predictions for the next 250 shipgirls:
```python
the_rest = lcg_d[av][4000:]
for i in range(250):
    r.sendlineafter('waifu?', waifu_dict[the_rest[i]])
    r.recvuntil('waifu is ')
r.interactive()
```
And with that, we're done!
## Flag
`WH2020{L1near_C0ngruenCe_Sh1pGirLS}`
### Server
Shortened code for `server.py`
```python
import stuff

class LCG():
    def __init__(self, mod=131): 
        a = v = 100
        while math.gcd(a, v) != 1: a, v = random.randrange(mod), random.randrange(mod)
        self.a, self.v, self.mod, self.counter = a, v, mod, 0
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

class Gacha():
    def __init__(self):
        self.shipgirls = [ "weeb stuff" ]	# len() == 131
        random.shuffle(self.shipgirls)		# important!
        self.lcg, self.counter = LCG(), 0	# 
    def get_next_shipgirl(self): return self.shipgirls[self.lcg.get_next()]

def main():
    gacha, faker, solves, tries = Gacha(), Faker(), 0, 5000
	print("fluff")
    while tries:
        tries -= 1
        name = faker.name()
        print(f"OK, what is {name}'s waifu?")
        correct = gacha.get_next_shipgirl()
        guess = input()
        if (guess == correct):
            solves += 1
            print("Wow that is correct!")
        else:
            solves = 0
            print("Sorry, that is not correct...")
        print(f"{name}'s waifu is {correct}")
        if (solves == 250):
            print("CONGRATULATIONS, YOU ARE CLAIRVOYANT WINNER!")
            print("HERE FLAG: <CENSORED>")
            tries = 0
    print("Goodbye!")