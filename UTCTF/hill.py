from string import lowercase
from sympy.matrices import *
charmap = dict(reversed(t) for t in enumerate(lowercase))

def mod(M,m): #this function is needed because my Sympy packge is outdated
    return M.applyfunc(lambda x: x%m)
def test_crib(c, m):
    '''returns the inverse-key D for which D*c == m (mod 26)
    this follows the method on http://practicalcryptography.com, using
    two blocks of known plaintext-ciphertext pairs to get D = K^-1'''
    def toM(s): #helper function to matrify a string
        return Matrix(2,2, map(lambda c: charmap[c], s))
    C, M = map(lambda t: toM([t[0], t[2], t[1], t[3]]), [c,m]) #matrify inputs
    D = mod(M*C.inv_mod(26),26)
    return D
def test_key(s, D, w=2):
    '''decrypts encrypted text `s` using inverse key `D`
    w is the size of each block, which is 2 for this challenge'''
    m=''
    for enc in [map(lambda c: charmap[c],s[i*w:i*w+w]) for i in range(len(s)/w)]:
        m += ''.join(map(lambda v: lowercase[v], mod(D*Matrix(enc),26)))
    return m
enc='wznqca{d4uqop0fk_q1nwofDbzg_eu}' #original ciphertext given
crib = 'utfl' #we KNOW that plaintext starts with "utflag{"
D = test_crib(enc[:4], crib)  #find K inverse (which is D)
#strip away non-hill cipherable chars from `enc`, and decipher using D
msg = test_key(''.join(c for c in enc if c.isalpha()).lower(), D)   

#add back the non-hill characters (i.e. numbers, "{_}", etc)
j = 0
answer = ''
for i in range(len(enc)):
    if enc[i].islower(): answer += msg[i-j]
    elif enc[i].isupper(): answer += msg[i-j].upper()
    else:
        answer += enc[i]
        j+=1
print answer
