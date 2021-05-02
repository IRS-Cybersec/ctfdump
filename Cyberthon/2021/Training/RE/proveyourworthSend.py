import pwn

r = pwn.remote("3qo9k5hk5cprtqvnlkvotlnj9d14b7mt.ctf.sg", 40101)
print(r.recvuntil(b"=> "))
r.send(b"3 45 48 93 141")
r.send(b"i hate mondays")
r.send(b"14 12 6 9 8")
r.send(b"\n")
r.interactive()
