from pwn import * 
p = remote("143.198.219.171",5003) 
p.sendlineafter(b"0: ",b'ICTF4')
p.sendlineafter(b"1: ",b'dasDASQWgjtrkodsc') 
p.sendlineafter(b"2: ",'\xef\xbe\xad\xde') 
p.sendlineafter(b"3: ",b'1') 
p.interactive() 
