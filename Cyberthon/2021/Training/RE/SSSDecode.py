import random
test = 0
for x in range(256):
    test ^= random.randint(0, 256)

flag = "CTFSG{Z}"
final = test
for x in flag:
    final ^= ord(x)

#print(final)
final2 = 0
for x in range(0, len(flag)-1, 1):
    final2 ^= ord(flag[x])

#print(final2)
#print(final ^ final2)

#Solution
content = b""
with open("flag.txt.out", "rb") as f:
    content = f.read()

n2 = content[0]
n3 = 0
flag = ""
for x in range(1, len(content), 1):
    value = content[x] ^ n2 ^ n3
    flag += chr(value)
    n3 ^= value

print(flag)
