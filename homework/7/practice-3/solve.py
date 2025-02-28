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
b *main
'''.format(**locals())
with open("gdbscript", "w") as f:
    f.write(gdbscript)


# start remote
p = remote('tasks.ws24.softsec.rub.de', 33250)

#p=remote("127.0.0.1", 1024)
#p2=process('tmux split-window -h docker exec -ti "$(docker ps -q -f \'ancestor=softsec/debug/practice-3\')" /bin/bash -c \'gdb -p "$(pgrep -n vuln)"\'', shell=True)
#sleep(2)
#p2.close()


def cyclic_find_bytes(b):
    to_be_found = bytes.fromhex(hex(b)[2:])[::-1]
    return cyclic_find(to_be_found)


def generate_input():
    # The target array we're comparing to
    comp_value = [
        0x9c, 0xb0, 0xf8, 0xfd, 0xa0, 0x40, 0xf9, 0x88, 0x7f, 0x84,
        0xe5, 0x4d, 0x2a, 0xe0, 0x91, 0x09, 0xd9
    ]

    result = [0] * 17  # Placeholder for the correct input bytes
    local_9 = 0x42     # Starting value of local_9

    for i in range(17):
        # Extract comp_value[i] to reverse it
        bVar1 = comp_value[i]

        # Reverse XOR with local_9
        bVar1 ^= local_9

        # Reverse the addition of ((i << 3) - i) + 0xd
        bVar1 -= ((i << 3) - i) + 0xd

        # Reverse the shift operation
        shift = local_9 & 7
        for val in range(256):
            # Reverse the circular shift that was applied in the original function
            if ((val >> (8 - shift)) | (val << shift) & 0xFF) == bVar1:
                result[i] = val
                break

        # Update local_9 as per the original function logic
        local_9 = (local_9 + comp_value[i]) & 0xFF

    # Return the reconstructed input as bytes
    return bytes(result)

print(generate_input())

p.sendlineafter(b"Enter flag: ", b"time_flies_right?")


p.interactive()

#softsec{kbQAcZgPGlQYqdOG7gFdR84oakSGKoEn8hWbZjQJ0j2xHVB_yOWHmNA3dMYp3Wsa}