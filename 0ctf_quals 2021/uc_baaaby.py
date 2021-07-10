from pwn import *
#r = process(['python3.8', 'uc_baaaby/uc_baaaby.py'])
context.arch = 'amd64'
CODE = 0xdeadbeef000
DATA = 0xbabecafe000

# make stack
sc = 'mov rsp, {}\n'.format(hex(DATA+0x400))
# setup initial MD5 state
sc+= 'mov rdi, {}\n'.format(hex(DATA+0x800))
sc+= 'mov DWORD PTR [rdi], 0x67452301\n'
sc+= 'mov DWORD PTR [rdi+4], 0xEFCDAB89\n'
sc+= 'mov DWORD PTR [rdi+8], 0x98BADCFE\n'
sc+= 'mov DWORD PTR [rdi+0xc], 0x10325476\n'
# set padding && size bytes for md5
sc+= 'mov rsi, {}\n'.format(hex(DATA))
sc+= 'mov BYTE PTR [rsi+50], 0x80\n'
sc+= 'mov WORD PTR [rsi+56], 0x190\n'
# copy from online
sc+='''movq   xmm0,rbx
movq   xmm1,rbp
mov    rbp,rsi
mov    eax,DWORD PTR [rdi]
mov    ebx,DWORD PTR [rdi+0x4]
mov    ecx,DWORD PTR [rdi+0x8]
mov    edx,DWORD PTR [rdi+0xc]
mov    r8,rdi
mov    esi,ecx
add    eax,DWORD PTR [rbp+0x0]
xor    esi,edx
and    esi,ebx
xor    esi,edx
lea    eax,[esi+eax*1-0x28955b88]
rol    eax,0x7
add    eax,ebx
mov    esi,ebx
add    edx,DWORD PTR [rbp+0x4]
xor    esi,ecx
and    esi,eax
xor    esi,ecx
lea    edx,[esi+edx*1-0x173848aa]
rol    edx,0xc
add    edx,eax
mov    esi,eax
add    ecx,DWORD PTR [rbp+0x8]
xor    esi,ebx
and    esi,edx
xor    esi,ebx
lea    ecx,[esi+ecx*1+0x242070db]
rol    ecx,0x11
add    ecx,edx
mov    esi,edx
add    ebx,DWORD PTR [rbp+0xc]
xor    esi,eax
and    esi,ecx
xor    esi,eax
lea    ebx,[esi+ebx*1-0x3e423112]
rol    ebx,0x16
add    ebx,ecx
mov    esi,ecx
add    eax,DWORD PTR [rbp+0x10]
xor    esi,edx
and    esi,ebx
xor    esi,edx
lea    eax,[esi+eax*1-0xa83f051]
rol    eax,0x7
add    eax,ebx
mov    esi,ebx
add    edx,DWORD PTR [rbp+0x14]
xor    esi,ecx
and    esi,eax
xor    esi,ecx
lea    edx,[esi+edx*1+0x4787c62a]
rol    edx,0xc
add    edx,eax
mov    esi,eax
add    ecx,DWORD PTR [rbp+0x18]
xor    esi,ebx
and    esi,edx
xor    esi,ebx
lea    ecx,[esi+ecx*1-0x57cfb9ed]
rol    ecx,0x11
add    ecx,edx
mov    esi,edx
add    ebx,DWORD PTR [rbp+0x1c]
xor    esi,eax
and    esi,ecx
xor    esi,eax
lea    ebx,[esi+ebx*1-0x2b96aff]
rol    ebx,0x16
add    ebx,ecx
mov    esi,ecx
add    eax,DWORD PTR [rbp+0x20]
xor    esi,edx
and    esi,ebx
xor    esi,edx
lea    eax,[esi+eax*1+0x698098d8]
rol    eax,0x7
add    eax,ebx
mov    esi,ebx
add    edx,DWORD PTR [rbp+0x24]
xor    esi,ecx
and    esi,eax
xor    esi,ecx
lea    edx,[esi+edx*1-0x74bb0851]
rol    edx,0xc
add    edx,eax
mov    esi,eax
add    ecx,DWORD PTR [rbp+0x28]
xor    esi,ebx
and    esi,edx
xor    esi,ebx
lea    ecx,[esi+ecx*1-0xa44f]
rol    ecx,0x11
add    ecx,edx
mov    esi,edx
add    ebx,DWORD PTR [rbp+0x2c]
xor    esi,eax
and    esi,ecx
xor    esi,eax
lea    ebx,[esi+ebx*1-0x76a32842]
rol    ebx,0x16
add    ebx,ecx
mov    esi,ecx
add    eax,DWORD PTR [rbp+0x30]
xor    esi,edx
and    esi,ebx
xor    esi,edx
lea    eax,[esi+eax*1+0x6b901122]
rol    eax,0x7
add    eax,ebx
mov    esi,ebx
add    edx,DWORD PTR [rbp+0x34]
xor    esi,ecx
and    esi,eax
xor    esi,ecx
lea    edx,[esi+edx*1-0x2678e6d]
rol    edx,0xc
add    edx,eax
mov    esi,eax
add    ecx,DWORD PTR [rbp+0x38]
xor    esi,ebx
and    esi,edx
xor    esi,ebx
lea    ecx,[esi+ecx*1-0x5986bc72]
rol    ecx,0x11
add    ecx,edx
mov    esi,edx
add    ebx,DWORD PTR [rbp+0x3c]
xor    esi,eax
and    esi,ecx
xor    esi,eax
lea    ebx,[esi+ebx*1+0x49b40821]
rol    ebx,0x16
add    ebx,ecx
mov    esi,edx
mov    edi,edx
add    eax,DWORD PTR [rbp+0x4]
not    esi
and    edi,ebx
and    esi,ecx
or     esi,edi
lea    eax,[esi+eax*1-0x9e1da9e]
rol    eax,0x5
add    eax,ebx
mov    esi,ecx
mov    edi,ecx
add    edx,DWORD PTR [rbp+0x18]
not    esi
and    edi,eax
and    esi,ebx
or     esi,edi
lea    edx,[esi+edx*1-0x3fbf4cc0]
rol    edx,0x9
add    edx,eax
mov    esi,ebx
mov    edi,ebx
add    ecx,DWORD PTR [rbp+0x2c]
not    esi
and    edi,edx
and    esi,eax
or     esi,edi
lea    ecx,[esi+ecx*1+0x265e5a51]
rol    ecx,0xe
add    ecx,edx
mov    esi,eax
mov    edi,eax
add    ebx,DWORD PTR [rbp+0x0]
not    esi
and    edi,ecx
and    esi,edx
or     esi,edi
lea    ebx,[esi+ebx*1-0x16493856]
rol    ebx,0x14
add    ebx,ecx
mov    esi,edx
mov    edi,edx
add    eax,DWORD PTR [rbp+0x14]
not    esi
and    edi,ebx
and    esi,ecx
or     esi,edi
lea    eax,[esi+eax*1-0x29d0efa3]
rol    eax,0x5
add    eax,ebx
mov    esi,ecx
mov    edi,ecx
add    edx,DWORD PTR [rbp+0x28]
not    esi
and    edi,eax
and    esi,ebx
or     esi,edi
lea    edx,[esi+edx*1+0x2441453]
rol    edx,0x9
add    edx,eax
mov    esi,ebx
mov    edi,ebx
add    ecx,DWORD PTR [rbp+0x3c]
not    esi
and    edi,edx
and    esi,eax
or     esi,edi
lea    ecx,[esi+ecx*1-0x275e197f]
rol    ecx,0xe
add    ecx,edx
mov    esi,eax
mov    edi,eax
add    ebx,DWORD PTR [rbp+0x10]
not    esi
and    edi,ecx
and    esi,edx
or     esi,edi
lea    ebx,[esi+ebx*1-0x182c0438]
rol    ebx,0x14
add    ebx,ecx
mov    esi,edx
mov    edi,edx
add    eax,DWORD PTR [rbp+0x24]
not    esi
and    edi,ebx
and    esi,ecx
or     esi,edi
lea    eax,[esi+eax*1+0x21e1cde6]
rol    eax,0x5
add    eax,ebx
mov    esi,ecx
mov    edi,ecx
add    edx,DWORD PTR [rbp+0x38]
not    esi
and    edi,eax
and    esi,ebx
or     esi,edi
lea    edx,[esi+edx*1-0x3cc8f82a]
rol    edx,0x9
add    edx,eax
mov    esi,ebx
mov    edi,ebx
add    ecx,DWORD PTR [rbp+0xc]
not    esi
and    edi,edx
and    esi,eax
or     esi,edi
lea    ecx,[esi+ecx*1-0xb2af279]
rol    ecx,0xe
add    ecx,edx
mov    esi,eax
mov    edi,eax
add    ebx,DWORD PTR [rbp+0x20]
not    esi
and    edi,ecx
and    esi,edx
or     esi,edi
lea    ebx,[esi+ebx*1+0x455a14ed]
rol    ebx,0x14
add    ebx,ecx
mov    esi,edx
mov    edi,edx
add    eax,DWORD PTR [rbp+0x34]
not    esi
and    edi,ebx
and    esi,ecx
or     esi,edi
lea    eax,[esi+eax*1-0x561c16fb]
rol    eax,0x5
add    eax,ebx
mov    esi,ecx
mov    edi,ecx
add    edx,DWORD PTR [rbp+0x8]
not    esi
and    edi,eax
and    esi,ebx
or     esi,edi
lea    edx,[esi+edx*1-0x3105c08]
rol    edx,0x9
add    edx,eax
mov    esi,ebx
mov    edi,ebx
add    ecx,DWORD PTR [rbp+0x1c]
not    esi
and    edi,edx
and    esi,eax
or     esi,edi
lea    ecx,[esi+ecx*1+0x676f02d9]
rol    ecx,0xe
add    ecx,edx
mov    esi,eax
mov    edi,eax
add    ebx,DWORD PTR [rbp+0x30]
not    esi
and    edi,ecx
and    esi,edx
or     esi,edi
lea    ebx,[esi+ebx*1-0x72d5b376]
rol    ebx,0x14
add    ebx,ecx
mov    esi,ecx
add    eax,DWORD PTR [rbp+0x14]
xor    esi,edx
xor    esi,ebx
lea    eax,[esi+eax*1-0x5c6be]
rol    eax,0x4
add    eax,ebx
mov    esi,ebx
add    edx,DWORD PTR [rbp+0x20]
xor    esi,ecx
xor    esi,eax
lea    edx,[esi+edx*1-0x788e097f]
rol    edx,0xb
add    edx,eax
mov    esi,eax
add    ecx,DWORD PTR [rbp+0x2c]
xor    esi,ebx
xor    esi,edx
lea    ecx,[esi+ecx*1+0x6d9d6122]
rol    ecx,0x10
add    ecx,edx
mov    esi,edx
add    ebx,DWORD PTR [rbp+0x38]
xor    esi,eax
xor    esi,ecx
lea    ebx,[esi+ebx*1-0x21ac7f4]
rol    ebx,0x17
add    ebx,ecx
mov    esi,ecx
add    eax,DWORD PTR [rbp+0x4]
xor    esi,edx
xor    esi,ebx
lea    eax,[esi+eax*1-0x5b4115bc]
rol    eax,0x4
add    eax,ebx
mov    esi,ebx
add    edx,DWORD PTR [rbp+0x10]
xor    esi,ecx
xor    esi,eax
lea    edx,[esi+edx*1+0x4bdecfa9]
rol    edx,0xb
add    edx,eax
mov    esi,eax
add    ecx,DWORD PTR [rbp+0x1c]
xor    esi,ebx
xor    esi,edx
lea    ecx,[esi+ecx*1-0x944b4a0]
rol    ecx,0x10
add    ecx,edx
mov    esi,edx
add    ebx,DWORD PTR [rbp+0x28]
xor    esi,eax
xor    esi,ecx
lea    ebx,[esi+ebx*1-0x41404390]
rol    ebx,0x17
add    ebx,ecx
mov    esi,ecx
add    eax,DWORD PTR [rbp+0x34]
xor    esi,edx
xor    esi,ebx
lea    eax,[esi+eax*1+0x289b7ec6]
rol    eax,0x4
add    eax,ebx
mov    esi,ebx
add    edx,DWORD PTR [rbp+0x0]
xor    esi,ecx
xor    esi,eax
lea    edx,[esi+edx*1-0x155ed806]
rol    edx,0xb
add    edx,eax
mov    esi,eax
add    ecx,DWORD PTR [rbp+0xc]
xor    esi,ebx
xor    esi,edx
lea    ecx,[esi+ecx*1-0x2b10cf7b]
rol    ecx,0x10
add    ecx,edx
mov    esi,edx
add    ebx,DWORD PTR [rbp+0x18]
xor    esi,eax
xor    esi,ecx
lea    ebx,[esi+ebx*1+0x4881d05]
rol    ebx,0x17
add    ebx,ecx
mov    esi,ecx
add    eax,DWORD PTR [rbp+0x24]
xor    esi,edx
xor    esi,ebx
lea    eax,[esi+eax*1-0x262b2fc7]
rol    eax,0x4
add    eax,ebx
mov    esi,ebx
add    edx,DWORD PTR [rbp+0x30]
xor    esi,ecx
xor    esi,eax
lea    edx,[esi+edx*1-0x1924661b]
rol    edx,0xb
add    edx,eax
mov    esi,eax
add    ecx,DWORD PTR [rbp+0x3c]
xor    esi,ebx
xor    esi,edx
lea    ecx,[esi+ecx*1+0x1fa27cf8]
rol    ecx,0x10
add    ecx,edx
mov    esi,edx
add    ebx,DWORD PTR [rbp+0x8]
xor    esi,eax
xor    esi,ecx
lea    ebx,[esi+ebx*1-0x3b53a99b]
rol    ebx,0x17
add    ebx,ecx
mov    esi,edx
not    esi
add    eax,DWORD PTR [rbp+0x0]
or     esi,ebx
xor    esi,ecx
lea    eax,[esi+eax*1-0xbd6ddbc]
rol    eax,0x6
add    eax,ebx
mov    esi,ecx
not    esi
add    edx,DWORD PTR [rbp+0x1c]
or     esi,eax
xor    esi,ebx
lea    edx,[esi+edx*1+0x432aff97]
rol    edx,0xa
add    edx,eax
mov    esi,ebx
not    esi
add    ecx,DWORD PTR [rbp+0x38]
or     esi,edx
xor    esi,eax
lea    ecx,[esi+ecx*1-0x546bdc59]
rol    ecx,0xf
add    ecx,edx
mov    esi,eax
not    esi
add    ebx,DWORD PTR [rbp+0x14]
or     esi,ecx
xor    esi,edx
lea    ebx,[esi+ebx*1-0x36c5fc7]
rol    ebx,0x15
add    ebx,ecx
mov    esi,edx
not    esi
add    eax,DWORD PTR [rbp+0x30]
or     esi,ebx
xor    esi,ecx
lea    eax,[esi+eax*1+0x655b59c3]
rol    eax,0x6
add    eax,ebx
mov    esi,ecx
not    esi
add    edx,DWORD PTR [rbp+0xc]
or     esi,eax
xor    esi,ebx
lea    edx,[esi+edx*1-0x70f3336e]
rol    edx,0xa
add    edx,eax
mov    esi,ebx
not    esi
add    ecx,DWORD PTR [rbp+0x28]
or     esi,edx
xor    esi,eax
lea    ecx,[esi+ecx*1-0x100b83]
rol    ecx,0xf
add    ecx,edx
mov    esi,eax
not    esi
add    ebx,DWORD PTR [rbp+0x4]
or     esi,ecx
xor    esi,edx
lea    ebx,[esi+ebx*1-0x7a7ba22f]
rol    ebx,0x15
add    ebx,ecx
mov    esi,edx
not    esi
add    eax,DWORD PTR [rbp+0x20]
or     esi,ebx
xor    esi,ecx
lea    eax,[esi+eax*1+0x6fa87e4f]
rol    eax,0x6
add    eax,ebx
mov    esi,ecx
not    esi
add    edx,DWORD PTR [rbp+0x3c]
or     esi,eax
xor    esi,ebx
lea    edx,[esi+edx*1-0x1d31920]
rol    edx,0xa
add    edx,eax
mov    esi,ebx
not    esi
add    ecx,DWORD PTR [rbp+0x18]
or     esi,edx
xor    esi,eax
lea    ecx,[esi+ecx*1-0x5cfebcec]
rol    ecx,0xf
add    ecx,edx
mov    esi,eax
not    esi
add    ebx,DWORD PTR [rbp+0x34]
or     esi,ecx
xor    esi,edx
lea    ebx,[esi+ebx*1+0x4e0811a1]
rol    ebx,0x15
add    ebx,ecx
mov    esi,edx
not    esi
add    eax,DWORD PTR [rbp+0x10]
or     esi,ebx
xor    esi,ecx
lea    eax,[esi+eax*1-0x8ac817e]
rol    eax,0x6
add    eax,ebx
mov    esi,ecx
not    esi
add    edx,DWORD PTR [rbp+0x2c]
or     esi,eax
xor    esi,ebx
lea    edx,[esi+edx*1-0x42c50dcb]
rol    edx,0xa
add    edx,eax
mov    esi,ebx
not    esi
add    ecx,DWORD PTR [rbp+0x8]
or     esi,edx
xor    esi,eax
lea    ecx,[esi+ecx*1+0x2ad7d2bb]
rol    ecx,0xf
add    ecx,edx
mov    esi,eax
not    esi
add    ebx,DWORD PTR [rbp+0x24]
or     esi,ecx
xor    esi,edx
lea    ebx,[esi+ebx*1-0x14792c6f]
rol    ebx,0x15
add    ebx,ecx
add    DWORD PTR [r8],eax
add    DWORD PTR [r8+0x4],ebx
add    DWORD PTR [r8+0x8],ecx
add    DWORD PTR [r8+0xc],edx
movq   rbx,xmm0
movq   rbp,xmm1
'''
print(len(sc.split('\n'))) # make sure this is less than 0x233
payload = asm(sc, vma=CODE).ljust(0x2000-2, b'\x67') + b'\x89\xe5' # padding with very long instruction
with open('payload.bin', 'wb') as f: f.write(payload) # after this, go send payload via nc manually
