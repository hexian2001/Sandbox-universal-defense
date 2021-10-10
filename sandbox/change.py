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
