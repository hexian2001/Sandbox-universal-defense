from pwn import *
context.arch = 'amd64'

sh=''
sh+="""
    push rbp
	mov rbp,rsp;
	mov r15,6;
	push r15
	mov r15,0x7FFF000000000006;
	push r15	
	mov r15,0x3B00010015;
	push r15
	mov r15 , 0x3800020015;
	push r15
	mov r15 , 0x3200030015;
	push r15
	mov r15 , 0x3100040015;
	push r15
	mov r15 , 0x2A00050015;
	push r15
	mov r15 , 0x2900060015;
	push r15
	mov r15 , 0x4000000000070035;
	push r15
	mov r15 , 0x20;
	push r15
	mov r15 , 0x0C000003E09000015;
	push r15
	mov r15 , 0x400000020;
	push r15
	mov r15,rsp;
	push r15
	mov r15 , 0x0c;
	push r15
	mov r15,rsp	;
	push r15
	mov rdi,38;
	mov rsi,1;
	mov rdx,0;
	mov rcx,0;
	mov r8,0;
	mov rax,157;
	syscall;
	mov rdi,22;
	mov rsi,2;
	mov rdx,r15;
	mov rax,157;
	syscall;
	leave;	
	ret;
    """
sc=asm(sh)
print(sc)
with open("11.c","a+") as f:
        f.write(sc)
