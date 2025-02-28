from pwn import *

context.arch = 'amd64'
context.os = 'linux'


for line in """
mov ax, 0x6873
mov bx, 0x2f2f
mov cx, 0x6e69
mov dx, 0x622f""".splitlines()[1:]:
	print(asm(line).hex())
    #pass

for line in """
shl ax, 48
shl bx, 32
shl cx, 16
""".splitlines()[1:]:
	print(asm(line).hex())

