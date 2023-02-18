### 1. BabyFlow
Tóm tắt đề :
- 1 file `babyFlow` để chạy trên linux

Ý tưởng:
- Đầu tiên ta sài IDA để decompile file

![](https://i.imgur.com/zH6PTrZ.png)

- Code đơn giản và có lỗi buffer overflow do sài hàm `gets`. Ta còn nhận thấy có hàm `get_shell` không được gọi và hàm này sẽ cho ta shell. Vậy thì ta sẽ lợi dụng buffer overflow để return về hàm `get_shell

![](https://i.imgur.com/9YC7inV.png)

- Ta sẽ debug để kiếm offset. Ở đây là 24

![](https://i.imgur.com/dNMYKsY.png)

- Vậy ta chỉ cần tìm địa chỉ hàm `get_shell` rồi viết script.

![](https://i.imgur.com/AjIe6Tb.png)

- Cuối cùng ta sẽ viết script.

![](https://i.imgur.com/kB4Ne3B.png)

- Chạy script trên ta sẽ có được shell.

### 2. GainMe
**Tóm tắt đề :**
- 1 file Gainme để chạy trên linux

**Ý tưởng :**
- Đầu tiên ta decompile file bằng IDA

![](https://i.imgur.com/539Gyux.png)

- Đọc qua thì thấy để lấy được flag ta phải trả lời 4 câu hỏi tương ứng với các hàm `lvlone`, `lvltwo`, `lvlthree`, `lvlfour`.
- Hàm `lvlone` thì đáp án có sẵn trong source.

![](https://i.imgur.com/fUOplni.png)

- Hàm `lvltwo` thì source ghi khá mơ hồ nên ta debug. Đặt breakpoint ở hàm `lvltwo`. `si` ở hàm `cmp` ta sẽ được đáp án thứ 2

![](https://i.imgur.com/I2zMMN0.png)

- Hàm `lvlthree` thì ta truyền `0xdeadbeef` vào
.
![](https://i.imgur.com/e0uYO95.png)

- Hàm `lvlfour` thì ta giải hệ bậc 3 `x^3 - 3x^2+ 3x-1 = 0`. Đáp án là 1.

![](https://i.imgur.com/tB0XS90.png)

- Cuối cùng ta sẽ viết script.

![](https://i.imgur.com/HBt6Zba.png)