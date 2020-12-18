# Many Paths [205] Points
SOLVED

Today in Santa's course in Advanced Graph Algorithms, Santa told us about the adjacency matrix of an undirected graph. I'm sure this last problem, he gave us is unsolvable, but I don't know much, maybe you do.

**Target**: nc challs.xmas.htsp.ro 6053

**Authors**: Gabies, Nutu

## Problem solving
```sh
$ nc challs.xmas.htsp.ro 6053
I swear that Santa is going crazy with those problems, this time we're really screwed!
The new problem asks us the following:
Given an undirected graph of size N by its adjacency matrix and a set of forbidden nodes, tell me how many paths from node 1 to node N of exactly length L that don't pass through any of the forbidden nodes exist (please note that a node can be visited multiple times)?
And if that wasn't enough, we need to answer 40 of those problems in 45 seconds and to give each output modulo 666013. What does that even mean!?
```
Given a graph of size N && its adjacency matrix && a set of untraversable nodes, we're tasked to find the number of length-L walks between the starting node (1) and the final node (N).

Let's consider a few cases.
```
Test number: 1/40
N = 3
adjacency matrix:
0,0,0
0,0,0
0,0,0
forbidden nodes: [2]
L = 3
```
In this case, the answer is 0, because the graph has no edges.
```
N = 5
adjacency matrix:
0,0,1,0,1
0,0,0,1,1
1,0,0,1,1
0,1,1,0,1
1,1,1,1,0
forbidden nodes: []
L = 3
```
For this example, the valid walks are `[3-4-5, 3-1-5, 5-1-5, 5-2-5, 5-3-5, 5-4-5]`, making the answer 6. Solving that one by-hand took nearly 45 seconds; how can this be implemented quickly?

Googling provides a [nice](https://math.stackexchange.com/questions/2009493/finding-number-of-distinct-walks-between-two-vertices-in-a-graph-using-matrix-mu) [algorithm](https://math.stackexchange.com/questions/2009493/finding-number-of-distinct-walks-between-two-vertices-in-a-graph-using-matrix-mu): raising the given adjacency matrix by power `L`, the number of walks between node 1 and node N will be the value at `[1,N]` (1-indexed) in the exponented matrix.

Or in simpler terms,
```
for N,adjacency_matrix,forbidden_nodes,L in every case:
    for node in forbidden_nodes: adjacency_matrix.remove_edges(node)
    adjacency_matrix **= L
    adjacency_matrix %= 666013
    yield adjacency_matrix[1,N]
```
To handle the i/o, we'll use `pwntools` && `re.findall` to handle basic parsing:
```python
from pwn import *
from re import findall
r = remote('challs.xmas.htsp.ro', 6053)
def getallints(): return map(int,findall(b'[0-9]+', r.recvline()))
for i in range(40):
    print(r.recvuntil('/40\n'))
    N = next(getallints())
    r.recvline()
    adj_m = Matrix([list(getallints()) for _ in range(N)]) # 0-indexed
    for forbid in getallints(): # remove edges to forbidden node
        for i in range(N): adj_m[forbid-1,i] = adj_m[i,forbid-1] = 0
    pathm = modexp(adj_m, 666013, next(getallints()))
```
We'll get `Matrix()` from `sympy`, and we'll implement modulo'd exponentation of matrices via a home-baked exponentation-by-squaring method:
```python
from sympy import *
from math import log2,floor
def modexp(M,m,e):
    exponentations = [M,M%m]
    if e < 1: raise ValueError('exponent too small!')
    for i in range(2,floor(log2(e))+2): exponentations.append((exponentations[i-1]**2)%m)
    return prod(exponentations[i+1] for i,b in enumerate(bin(e)[:1:-1]) if b=='1')%m
```
That's the algorithm done. All we need to do is to run it:
```python
$ python3 proggraph.py
[+] Opening connection to challs.xmas.htsp.ro on port 6053: Done
...
b'\nGood, thats right!\nTest number: 36/40\n'
[DEBUG] Received 0x5c bytes:
    b',0,0,0,1,0,0,0,1,0,0,1,1,1,1,1,1,0,0,0,0,1,0,0,1,1,1,0\n'
    b'forbidden nodes: [10,7,8]\n'
    b'L = 44380\n'
    b'\n'
[DEBUG] Sent 0x6 bytes:
    b'98205\n'
Traceback (most recent call last):
  File "proggraph.py", line 14, in <module>
    print(r.recvuntil('/40\n'))
  File "/pwntools/pwnlib/tubes/tube.py", line 333, in recvuntil
    res = self.recv(timeout=self.timeout)
  File "/pwntools/pwnlib/tubes/tube.py", line 105, in recv
    return self._recv(numb, timeout) or b''
  File "/pwntools/pwnlib/tubes/tube.py", line 183, in _recv
    if not self.buffer and not self._fillbuffer(timeout):
  File "/pwntools/pwnlib/tubes/tube.py", line 154, in _fillbuffer
    data = self.recv_raw(self.buffer.get_fill_size())
  File "/pwntools/pwnlib/tubes/sock.py", line 58, in recv_raw
    raise EOFError
EOFError
```
Uh oh.
## Speeding things up
The algorithm itself is probably optimal enough, considering it *almost* reaches the last few test cases. I had a few ideas on how to shave off a few seconds:
1. Attempt to run the script in pypy
   ```python
   $ pypy3 proggraph.py
   [+] Opening connection to challs.xmas.htsp.ro on port 6053: Done
   b'\nGood, thats right!\nTest number: 38/40\n'
   [DEBUG] Sent 0x6 bytes:
       b'61781\n'
   Traceback (most recent call last):
     File "proggraph.py", line 14, in <module>
       print(r.recvuntil('/40\n'))
   ```
   That's an improvement, but still not enough. I attempted to switch to pypy2 for even more speed, but this was troublesome because pypy-pip was stripped from the ubuntu repos a while back.
2. Try to shift to a faster matrix library like numpy
   I put a significant amount of effort into this, but numpy matrices broke my algorithm somehow. Not sure what happened here.
3. Rewrite everything in a faster language
   This looked like a really fun thing to do, so I did just that:
```c
#include <math.h>
#include <stdlib.h>
#include <stdio.h>
#define ind(M,y,x)    M.data[(y)*M.N+(x)]
#define for_xy_in_(M)  for (int y = 0; y < M.N; y++) for (int x = 0; x < M.N; x++)
typedef struct Matrix {
    long long *data;
    int N;
} Matrix;
void pprint(Matrix M) {
    for_xy_in_(M) printf(x+1 == M.N ? "%d\n" : "%d,", ind(M,y,x));
}
Matrix mod_inplace(Matrix M, int mod) { // in place
    for (int i = 0; i < M.N; i++) {
        for (int j = 0; j < M.N; j++) 
            ind(M,i,j) %= mod;
    }
    return M;
}
Matrix square(Matrix M) { //creates new one
    Matrix squared = { .data = calloc(M.N*M.N,sizeof(long long)), .N = M.N};
    for_xy_in_(M) {
        for (int k = 0; k < M.N; k++)
            ind(squared,y,x) += ind(M,y,k)*ind(M,k,x);
    }
    return squared;
}
Matrix identity(int N){
    Matrix iden = {.data = calloc(N*N, sizeof(long long)), .N = N};
    for (int i = 0; i < N; i++) ind(iden,i,i) = 1;
    return iden;
}
Matrix mul(Matrix M, Matrix other) { // creates new, assumes equal length.
    Matrix prod = { .data = calloc(M.N*M.N,sizeof(long long)), .N = M.N};
    for_xy_in_(M) {
        for (int k = 0; k < M.N; k++)
            ind(prod,y,x) += ind(M,y,k)*ind(other,k,x);
    }
    return prod;
}
Matrix modexp(Matrix M, int mod, int e) {
    int binmax = floor(log2(e))+2;
    Matrix *expts = calloc(binmax, sizeof(Matrix));
    expts[0] = M; expts[1] = mod_inplace(M,mod); //nothing new
    for (int i = 2; i < binmax; i++) {
        expts[i] = mod_inplace(square(expts[i-1]),mod); //creates new
    }
    Matrix total = identity(M.N); // creates new
    for (int i = 0; i < binmax; i++) {
        if (e&(1<<i)) {
            Matrix prod = mod_inplace(mul(total,expts[i+1]),mod); // creates new
            free(total.data);
            total = prod;
        }
    }
    for (int i = 2; i < binmax; i++) free(expts[i].data);
    return total;
}
int main(){ //spaghetti code for i/o
    int N;
    scanf("N = %d",&N);
    Matrix adj_m = {.data = calloc(N*N, sizeof(long long)), .N = N};
    while (getchar() != ':'); getchar();
    for_xy_in_(adj_m) {
        scanf("%d", &ind(adj_m,y,x));
        getchar();
    }
    while (getchar() != ':');
    char line[5000], tmp[5000];
    fgets(line, 5000, stdin);
    int forbid = 0;
    while (sscanf(line,"%[^0123456789]%s",tmp,line)>1 || sscanf(line,"%d%s",&forbid,line)) {
        if (tmp[0]=='\0') { // number found
            for (int i = 0; i < N; i++)
                ind(adj_m,forbid-1,i) = ind(adj_m,i,forbid-1) = 0;
        }
        *tmp = 0;
    }
    int L;
    scanf("L = %d", &L);
    Matrix pathm = modexp(adj_m, 666013, L);
    free(adj_m.data);
    printf("%d\n", ind(pathm,0,N-1));
    free(pathm.data);
}
```
This program will take the input for a single test case && print out the answer. To instrument this, I used python's `subprocess` module to get the answer for all 40 test cases:
```python
from pwn import *
from subprocess import check_output
r = remote('challs.xmas.htsp.ro', 6053)
for i in range(40):
    r.recvuntil('/40\n')
    text = r.recvuntil('L') + r.recvline()
    ans = check_output(['./a.out'], input=text)
    r.send(ans)
r.interactive()
```
With that, we're done:
```sh
$ gcc matrix.c -O2 -lm
$ python3.8 instrument.py 
[+] Opening connection to challs.xmas.htsp.ro on port 6053: Done
[*] Switching to interactive mode

Good, thats right!
I cannot believe you figured this one out, how does this code even work?
I'm baffled, here's the flag: 
```
## Flag
`X-MAS{n0b0dy_3xp3c73d_th3_m47r1x_3xp0n3n71a7i0n}`