#!/usr/local/bin/python3.8
from pwn import *   #just for remote i/o
from decimal import *
getcontext().prec = 50 #given numbers are ~15dp, so this should be sufficient
r = remote('chals.whitehacks.ctf.sg', 11004)
input = r.recvline
#context.log_level='debug'
while 1: #there are many test cases
    #get first line
    l = input()
    try: 
        N, T = map(Decimal, l.split())
    except Exception: #This is when a flag appears.
        print(l, r.recvline())
        N, T = map(Decimal, input().split())
    N = int(N)
    #data formatting for the next N lines
    arr, lea = [], []
    for i in range(N):  
        start, end, n = map(Decimal, input().split())
        n = int(n)
        arr.append((start, n))
        lea.append((end, n))
    arr, lea = map(sorted, (arr, lea))
    #Basically, shift the timerange between range boundaries and check for maximum
    #A lot, and I do really mean _a lot_ of misalgorithms happened in the process,
    #even if the resultant code looks short
    ppl, maxno, righti, lefti = 0,0,0,0
    while righti < N:   
        ppl += arr[righti][1]
        while arr[righti][0] - lea[lefti][0] > T:
            ppl -= lea[lefti][1]
            lefti += 1
        if maxno < ppl: maxno = ppl
        righti += 1
    r.sendline(str(maxno))
    print(r.recvline())
r.interactive()
