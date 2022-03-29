#coding:utf-8
from unicorn import *
from capstone import *
from unicorn.x86_const import *
from elftools.elf.elffile import ELFFile
from elftools.elf.segments import Segment
import ctypes
import binascii
# import hexdump

#https://blog.csdn.net/yalecaltech/article/details/104113779

# INC ecx
# DEC edx
code = b"\x41\x4a"

ADDRESS = 0x01000000
emu = Uc(UC_ARCH_X86,UC_MODE_32)
emu.mem_map(ADDRESS,2*1024*1024)
emu.mem_write(ADDRESS,code)

emu.reg_write(UC_X86_REG_ECX,0x1234)
emu.reg_write(UC_X86_REG_EDX,0x1111)






def disasm(bytecode,addr):
    md = Cs(CS_ARCH_X86,CS_MODE_32 + CS_MODE_LITTLE_ENDIAN)
    for asm in md.disasm(bytecode,addr):
        return '%s\t%s'%(asm.memonic,asm.op_str)

def hook_code(uc, address, size, user_data):
    bytecode = emu.mem_read(address,size)
    # print(" 0x%x :%s"%(address,disasm(bytecode,address)))
    if address == ADDRESS :
        emu.emu_stop()

emu.hook_add(UC_HOOK_CODE, hook_code)
emu.emu_start(ADDRESS,ADDRESS+len(code))

r_ecx = emu.reg_read(UC_X86_REG_ECX)
r_edx = emu.reg_read(UC_X86_REG_EDX)

print("0x{:x}".format(r_ecx))
