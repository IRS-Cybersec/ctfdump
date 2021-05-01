from z3 import *
passwd = [ BitVec('v%s' % i, 32) for i in range(14) ] #32 is probably overkill; but 8 was too small
s = Solver()
for v in passwd: s.add(0 <= v, v <= 5)
#very amazing code
temp = 0
for i in range(14): temp ^= passwd[i]
s.add(4 == temp)
thing = 0
for i in range(14): thing = passwd[i] ^ 2 * thing
s.add(52117 == thing)
right = 0
for i in range(14): right = passwd[i] ^ 4 * right
s.add(289197077 == right)

print(s.check())
print(s.model())
