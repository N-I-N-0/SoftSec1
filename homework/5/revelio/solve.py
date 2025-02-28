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

binfile = './rev'
elf = context.binary = ELF(binfile)


# for debugging
gdbscript = '''
file /gdbscript/rev
#getline
#b *$base("rev")+0x17cf
#check input i
b *$base("rev")+0x185d
# inside check 2
#b *$base("rev")+0x136e
'''.format(**locals())
with open("gdbscript", "w") as f:
    f.write(gdbscript)


# start remote
p = remote('tasks.ws24.softsec.rub.de', 32852)

#p=remote("127.0.0.1", 1024)
#p2=process('tmux split-window -h docker exec -ti $(docker ps -q -f "ancestor=softsec/revelio") /bin/sh -c \'gdb -x /gdbscript/gdbscript -p $(pgrep -n rev)\'', shell=True)
#sleep(8)
#p2.close()


def cyclic_find_bytes(b):
    to_be_found = bytes.fromhex(hex(b)[2:])[::-1]
    return cyclic_find(to_be_found)

def encrypt(bytes_list):
    print("len: ", len(bytes_list))
    #bytes_list = bytes_list.ljust(200)
    new_bytes_list = [0]*len(bytes_list)
    for i in range(len(bytes_list)):
        new_bytes_list[i] = bytes_list[i] ^ ord(("Caput Draconis"[i % len("Caput Draconis")]))
    return bytes(new_bytes_list)


p.recvuntil(b"Enter flag 1: ")
p.sendline(encrypt(b"&\x0f\x15\x18\x1dE7-\x0e\x050\x1a\x01\x16\x1c\t\x15\x1c\x06\x7f&\x17\x16\x02\x1d\v"))




def build_flag_2():
    original_string = "ptvyertzbnqmujwxksrbhlyidegvsqadjgxklffucpmaohiczwno"
    string = list(original_string)
    for i in range(0, 52, 2):
        string[i] = "0"
    string = "".join(string)

    input_string = ""
    for c in "grffinrdoq":
        input_string += original_string[string.index(c) - 1]

    return input_string


p.recvuntil(b"Enter flag 2: ")
p.sendline(build_flag_2().encode())












class Astruct:
    def __init__(self, character):
        self.character = character
        self.moveL = None
        self.moveR = None

def return_malloc_ptr_with_content_argument(one_char):
    return Astruct(one_char)

def create_list():
    first_astruct = return_malloc_ptr_with_content_argument('a')
    second_astruct = return_malloc_ptr_with_content_argument('l')
    first_astruct.moveL = second_astruct
    
    second_astruct = return_malloc_ptr_with_content_argument('0')
    first_astruct.moveR = second_astruct
    
    temp = first_astruct.moveL
    third_astruct = return_malloc_ptr_with_content_argument('o')
    temp.moveR = third_astruct
    
    temp2 = first_astruct.moveL
    second_astruct = return_malloc_ptr_with_content_argument('0')
    temp2.moveL = second_astruct
    
    temp3 = first_astruct.moveR
    second_astruct = return_malloc_ptr_with_content_argument('0')
    temp3.moveL = second_astruct
    
    temp4 = first_astruct.moveL.moveL
    second_astruct = return_malloc_ptr_with_content_argument('0')
    temp4.moveL = second_astruct
    
    temp5 = first_astruct.moveL.moveR
    second_astruct = return_malloc_ptr_with_content_argument('h')
    temp5.moveR = second_astruct
    
    temp6 = first_astruct.moveR.moveL
    second_astruct = return_malloc_ptr_with_content_argument('0')
    temp6.moveR = second_astruct
    
    temp7 = first_astruct.moveL.moveL.moveL
    second_astruct = return_malloc_ptr_with_content_argument('0')
    temp7.moveR = second_astruct
    
    temp8 = first_astruct.moveL.moveR.moveR
    second_astruct = return_malloc_ptr_with_content_argument('o')
    temp8.moveL = second_astruct
    
    temp9 = first_astruct.moveL.moveR.moveR.moveL
    second_astruct = return_malloc_ptr_with_content_argument('0')
    temp9.moveL = second_astruct
    
    temp10 = first_astruct.moveL.moveR.moveR.moveL.moveL
    second_astruct = return_malloc_ptr_with_content_argument('0')
    temp10.moveR = second_astruct
    
    temp11 = first_astruct.moveL.moveR.moveR.moveL.moveL
    second_astruct = return_malloc_ptr_with_content_argument('0')
    temp11.moveL = second_astruct
    
    temp12 = first_astruct.moveL.moveR.moveR.moveL
    second_astruct = return_malloc_ptr_with_content_argument('m')
    temp12.moveR = second_astruct
    
    temp13 = first_astruct.moveL.moveR.moveR.moveL.moveR
    second_astruct = return_malloc_ptr_with_content_argument('o')
    temp13.moveL = second_astruct
    
    temp14 = first_astruct.moveL.moveR.moveR.moveL.moveR
    second_astruct = return_malloc_ptr_with_content_argument('0')
    temp14.moveR = second_astruct
    
    temp15 = first_astruct.moveL.moveR.moveR.moveL.moveR.moveL
    second_astruct = return_malloc_ptr_with_content_argument('r')
    temp15.moveR = second_astruct
    
    temp16 = first_astruct.moveL.moveR.moveR.moveL.moveR.moveL.moveR
    second_astruct = return_malloc_ptr_with_content_argument('a')
    temp16.moveL = second_astruct

    return first_astruct





def brute_force_search(node, target, current_path, move_path, visited):
    # If node is None, stop the search
    if node is None:
        return None
    
    # Add current node's character to the path
    current_path += node.character

    # If the path matches the target, return the move path (sequence of L's and R's)
    if current_path == target:
        return move_path

    # Mark the current node as visited to prevent going back
    visited.add(node)

    # Try to move left if not visited
    if node.moveL and node.moveL not in visited:
        result = brute_force_search(node.moveL, target, current_path, move_path + 'L', visited)
        if result:
            return result

    # Try to move right if not visited
    if node.moveR and node.moveR not in visited:
        result = brute_force_search(node.moveR, target, current_path, move_path + 'R', visited)
        if result:
            return result

    # If neither direction worked, backtrack (end the current branch)
    visited.remove(node)
    return None


# Start brute-force search to find the path to "alohomora"
first_astruct = create_list()
target_word = "alohomora"
visited = set()
result = brute_force_search(first_astruct, target_word, "", "", visited)
print(result)

p.recvuntil(b"Enter flag 3: ")
p.sendline(result.encode())


p.interactive()

#softsec{oE3YfxDJcdu1QEZjujudSs5fg0w6jAw8ZM9zok8-ILIcAsQvYMFDXhg6RrgF7_g0}