from base64 import b64decode as b64d, b64encode as b64e
from hashpumpy import hashpump
orig = b64d('ZnJvbT1QZXRlciZhbW91bnQ9MjA=')
h, req = hashpump('24a2efde8a32e7046aaeb11eb32a37ecf49937ef84c7a6b4bd943556fd2369cd', orig, '&from=Admin&amount=1000000', 19)
print(b64e(req))
print(h)
# Take the values printed and stick them in the AAA website 
