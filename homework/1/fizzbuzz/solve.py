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
p = remote('tasks.ws24.softsec.rub.de', 32858)

# start locally with docker
#p = remote('127.0.0.1', 1024)

# programm this code solving the task
# compile with "gcc -m64 -fno-stack-protector -z execstack -o shellcode.o -c shellcode.c"
"""
#include <stdint.h>

void magic(uint32_t* ptr) {
	for(int i = 0; i < 2048; i++) {
		if ((ptr[i] % 3) == 0) {
			if ((ptr[i] % 5) == 0) {
				ptr[i] = 2;
			} else {
				ptr[i] = 0;
			}
		} else if ((ptr[i] % 5) == 0) {
			ptr[i] = 1;
		} else {
			ptr[i] = 3;
		}
	}
}


void main() {
	uint32_t test[2048];
	magic(test);
}
"""

# extract assembly from shellcode.o with e.g. Ghidra
# payload getting the flag
payload = bytes.fromhex("f3 0f 1e fa 55 48 89 e5 48 89 7d e8 c7 45 fc 00 00 00 00 e9 1e 01 00 00 8b 45 fc 48 98 48 8d 14 85 00 00 00 00 48 8b 45 e8 48 01 d0 8b 08 89 ca b8 ab aa aa aa 48 0f af c2 48 c1 e8 20 89 c2 d1 ea 89 d0 01 c0 01 d0 29 c1 89 ca 85 d2 75 74 8b 45 fc 48 98 48 8d 14 85 00 00 00 00 48 8b 45 e8 48 01 d0 8b 08 89 ca b8 cd cc cc cc 48 0f af c2 48 c1 e8 20 89 c2 c1 ea 02 89 d0 c1 e0 02 01 d0 29 c1 89 ca 85 d2 75 1f 8b 45 fc 48 98 48 8d 14 85 00 00 00 00 48 8b 45 e8 48 01 d0 c7 00 02 00 00 00 e9 8b 00 00 00 8b 45 fc 48 98 48 8d 14 85 00 00 00 00 48 8b 45 e8 48 01 d0 c7 00 00 00 00 00 eb 6f 8b 45 fc 48 98 48 8d 14 85 00 00 00 00 48 8b 45 e8 48 01 d0 8b 08 89 ca b8 cd cc cc cc 48 0f af c2 48 c1 e8 20 89 c2 c1 ea 02 89 d0 c1 e0 02 01 d0 29 c1 89 ca 85 d2 75 1c 8b 45 fc 48 98 48 8d 14 85 00 00 00 00 48 8b 45 e8 48 01 d0 c7 00 01 00 00 00 eb 1a 8b 45 fc 48 98 48 8d 14 85 00 00 00 00 48 8b 45 e8 48 01 d0 c7 00 03 00 00 00 83 45 fc 01 81 7d fc ff 07 00 00 0f 8e d5 fe ff ff 90 90 5d c3".replace(" ", ""))

# verify we have no bad instructions in here
print(disasm(payload))

# send the payload
p.sendline(payload.hex().encode())

# gain the flag
p.interactive()

# softsec{oW1moIe-hoKsRHEIxsMmepzzfaTurRMswcIahxXfDjiMlgrdJ1XgEAHXSYvo8Lxi}