from pickle import load, dump
with open('lcg.dump', 'rb') as f: lcg_d = load(f)
lcg_formatted = {}
for t in lcg_d:
    arr = lcg_d[t][:4000]
    d = {}
    for i in range(4000):
        d[arr[i]] = d.get(arr[i], ()) + (i,)
    for ind in d:
        lcg_formatted[d[ind]] = lcg_formatted.get(d[ind], []) + [(ind, t)]

with open('lcg.formatted', 'wb') as f: lcg_d = dump(lcg_formatted,f)
k = lcg_formatted.keys()[0]
print(k,lcg_formatted[k])
