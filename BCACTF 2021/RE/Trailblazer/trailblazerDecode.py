import pwn

#Length of flag == 47 chars
#8 bytes of encoded_func are xored with 8 bytes of flag to get expected_func at each "iteration"
encoded_func = ["662b573c6b32e82a", "63245020640cfc27", "6d3f48176f3ce317", "410f5432413fe917", "100f5d214921ff17", "bef079323565df"]

shell1 = """
mov rdx,QWORD PTR [rbx+0x8]
xor QWORD PTR [rax+0x8],rdx
"""
shell2 = """
mov rdx,QWORD PTR [rbx+16]
xor QWORD PTR [rax+16],rdx
"""
shell3 = """
mov rdx,QWORD PTR [rbx+24]
xor QWORD PTR [rax+24],rdx
"""
shell4 = """
mov rdx,QWORD PTR [rbx+32]
xor QWORD PTR [rax+32],rdx
"""
shell5 = """
mov rdx,QWORD PTR [rbx+40]
xor QWORD PTR [rax+40],rdx
"""
shell6 = """
mov eax, 0
leave
ret
"""
expected_func = [shell1, shell2, shell3, shell4, shell5, shell6]
for x in range(0, len(expected_func), 1):
    if (x == 5):
        expected_func[x] = pwn.asm(expected_func[x]).hex()
    else:
        expected_func[x] = pwn.asm(expected_func[x], arch="amd64").hex()
    reversed = ""
    for y in range(len(encoded_func[x]), -1, -2):
#        print(encoded_func[x])
        reversed += encoded_func[x][y-2:y]
    encoded_func[x] = reversed
    
flag = ""

for x in range(0, len(encoded_func), 1):
    for y in range(0, len(encoded_func[x]), 2):
       #print(encoded_func[x])
       #print(expected_func[x])
       #print("---")
        character = int(encoded_func[x][y:y+2],16) ^ int(expected_func[x][y:y+2], 16)
        flag += chr(character)

print(flag)
