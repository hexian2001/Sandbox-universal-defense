# Sandbox universal defense

```
Sandbox general defense is a general defense project prepared for ctf-awd-pwn
```



# Author

```
SkYe231: https://www.mrskye.cn/

H.greed(H.R.P): https://hgreed.vip/
```

# principle

```
Based on the function of lief module, the normal binary program is started from_ The start function executes main and returns when main ends_ Start is the last real end.
Our sandbox defense can be in .eh_frame section writes the sandbox assembly and the assembly code required to call the sandbox. In_ The place where start should have been written to the main function is changed to the address where the sandbox function is called, and the main function is called at the address where the sandbox function is called.
The above not only ensures that the stack frame is not damaged and the program executes normally, but also disables function calls according to their own rules.
```

# statement

```
All consequences arising from the use of the project shall be borne by the user. The project is only for learning and exchange because of the spirit of open source
```



# Scope of application

```
64 bit binary program under Ubuntu 18-Ubuntu 20 system
```



# How to use?

## Required modules

```shell
pip3 install setuptools --upgrade

sudo pip3 install lief
```

## explains

```
We have prepared four demos under the demo file. One to three demos contain binaries before and after patch and corresponding attack scripts. Demo4 is a simple sandbox C file. In the sandbox folder, the sand.py file is the sink code of the corresponding 64 bit sandbox. Change.py is the PY file used to write sandbox protection. The sandbox. C file is converted from the 64 bit sandbox assembly code to bytecode, and then uses the pointer function to perform sandbox protection. The function of this file is to produce hook binary programs (we have prepared it for you)
```

## how to make your hook Binary program

Since you cannot rely on the libc library, you need to use the following command

```shell
gcc -nostdlib -nodefaultlibs -fPIC -Wl,-shared hook.c -o hook
```

## how use change.py

example

```python
import lief
from pwn import *

def patch_call(file,srcaddr,dstaddr,arch = "amd64"):
	#print hex(dstaddr)
	length = p64((dstaddr - (srcaddr + 5 )) & 0xffffffff)
	order = b'\xe8'+length
	#print disasm(order,arch=arch)
	file.patch_address(srcaddr,[ord(i) for i in str(order)])

binary = lief.parse("./easypwn")
hook = lief.parse('./hook')

# write hook's .text content to binary's .eh_frame content 
sec_ehrame = binary.get_section('.eh_frame')
#print sec_ehrame.content
sec_text = hook.get_section('.rodata')
sec_text1=hook.get_section('.text')
#print sec_text.content
list=[0x90]*10
sec_ehrame.content = sec_text.content+sec_text1.content+list
print(sec_ehrame.content)
#print binary.get_section('.eh_frame').content

# hook target call
dstaddr = sec_ehrame.virtual_address
srcaddr = 0x400870

patch_call(binary,srcaddr,dstaddr)

binary.write('new2')

```

about sec_ehrame.content you can use arry to add that contents what you need.such as this  python file u can add some nop.



For srcaddr variable , we chose. eh_ frame_ hdr The starting address of the paragraph, which ensures that the content is written to. eh_ frame paragraph.



## How to call sandbox reasonably after hook is written

```
We have prepared the basic calling program in the hook binary program. When using, we only need to change the address of the calling sandbox and call the main function. For the calling address of the calling sandbox function, we choose_ The start function is changed as follows
```

### Sandbox execution and call sandbox

```c
.eh_frame:00000000004008C0 loc_4008C0:                             ; DATA XREF: .eh_frame:00000000004009B3↓o
.eh_frame:00000000004008C0                 push    rbp
.eh_frame:00000000004008C1                 mov     rbp, rsp
.eh_frame:00000000004008C4                 mov     r15, 6
.eh_frame:00000000004008CB                 push    r15
.eh_frame:00000000004008CD                 mov     r15, 7FFF000000000006h
.eh_frame:00000000004008D7                 push    r15
.eh_frame:00000000004008D9                 mov     r15, 3B00010015h
.eh_frame:00000000004008E3                 push    r15
.eh_frame:00000000004008E5                 mov     r15, 3800020015h
.eh_frame:00000000004008EF                 push    r15
.eh_frame:00000000004008F1                 mov     r15, 3200030015h
.eh_frame:00000000004008FB                 push    r15
.eh_frame:00000000004008FD                 mov     r15, 3100040015h
.eh_frame:0000000000400907                 push    r15
.eh_frame:0000000000400909                 mov     r15, 2A00050015h
.eh_frame:0000000000400913                 push    r15
.eh_frame:0000000000400915                 mov     r15, 2900060015h
.eh_frame:000000000040091F                 push    r15
.eh_frame:0000000000400921                 mov     r15, 4000000000070035h
.eh_frame:000000000040092B                 push    r15
.eh_frame:000000000040092D                 mov     r15, 20h ; ' '
.eh_frame:0000000000400934                 push    r15
.eh_frame:0000000000400936                 mov     r15, 0C000003E09000015h
.eh_frame:0000000000400940                 push    r15
.eh_frame:0000000000400942                 mov     r15, 400000020h
.eh_frame:000000000040094C                 push    r15
.eh_frame:000000000040094E                 mov     r15, rsp
.eh_frame:0000000000400951                 push    r15
.eh_frame:0000000000400953                 mov     r15, 0Ch
.eh_frame:000000000040095A                 push    r15
.eh_frame:000000000040095C                 mov     r15, rsp
.eh_frame:000000000040095F                 push    r15
.eh_frame:0000000000400961                 mov     rdi, 26h ; '&'
.eh_frame:0000000000400968                 mov     rsi, 1
.eh_frame:000000000040096F                 mov     rdx, 0
.eh_frame:0000000000400976                 mov     rcx, 0
.eh_frame:000000000040097D                 mov     r8, 0
.eh_frame:0000000000400984                 mov     rax, 9Dh
.eh_frame:000000000040098B                 syscall                 ; LINUX - sys_prctl
.eh_frame:000000000040098D                 mov     rdi, 16h
.eh_frame:0000000000400994                 mov     rsi, 2
.eh_frame:000000000040099B                 mov     rdx, r15
.eh_frame:000000000040099E                 mov     rax, 9Dh
.eh_frame:00000000004009A5                 syscall                 ; LINUX - sys_prctl
.eh_frame:00000000004009A7                 leave
.eh_frame:00000000004009A8                 retn
.eh_frame:00000000004009A8 ; ---------------------------------------------------------------------------
.eh_frame:00000000004009A9                 db  0Ah
.eh_frame:00000000004009AA                 db    0
.eh_frame:00000000004009AB ; ---------------------------------------------------------------------------
.eh_frame:00000000004009AB
.eh_frame:00000000004009AB ; int __fastcall loc_4009AB(int, char **, char **)
.eh_frame:00000000004009AB loc_4009AB:                             ; DATA XREF: _start+1D↑o
.eh_frame:00000000004009AB                 push    rbp
.eh_frame:00000000004009AC                 mov     rbp, rsp
.eh_frame:00000000004009AF                 sub     rsp, 10h
.eh_frame:00000000004009B3                 lea     rax, loc_4008C0
.eh_frame:00000000004009BA                 mov     [rbp-8], rax
.eh_frame:00000000004009BE                 mov     rax, [rbp-8]
.eh_frame:00000000004009C2                 mov     [rbp-10h], rax
.eh_frame:00000000004009C6                 mov     rax, [rbp-10h]
.eh_frame:00000000004009CA                 call    rax
.eh_frame:00000000004009CC                 nop
.eh_frame:00000000004009CD                 nop
.eh_frame:00000000004009CE                 call    main
.eh_frame:00000000004009D3                 retn
```

about _start function

```c
04005E0
.text:00000000004005E0                 public _start
.text:00000000004005E0 _start          proc near               ; DATA XREF: LOAD:0000000000400018↑o
.text:00000000004005E0                 xor     ebp, ebp
.text:00000000004005E2                 mov     r9, rdx         ; rtld_fini
.text:00000000004005E5                 pop     rsi             ; argc
.text:00000000004005E6                 mov     rdx, rsp        ; ubp_av
.text:00000000004005E9                 and     rsp, 0FFFFFFFFFFFFFFF0h
.text:00000000004005ED                 push    rax
.text:00000000004005EE                 push    rsp             ; stack_end
.text:00000000004005EF                 mov     r8, offset __libc_csu_fini ; fini
.text:00000000004005F6                 mov     rcx, offset __libc_csu_init ; init
.text:00000000004005FD                 mov     rdi, offset loc_4009AB ; main
.text:0000000000400604                 call    cs:__libc_start_main_ptr
.text:000000000040060A                 hlt
.text:000000000040060A _start          endp
```

This is where we need to modify

```c
.text:00000000004005FD                 mov     rdi, offset loc_4009AB ; main
```



For more details, please refer to the lief module. This project is only a derivative of this module
