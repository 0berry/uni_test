# coding:utf-8

from unicorn import *
from capstone import *
from unicorn.x86_const import *
from elftools.elf.elffile import ELFFile
from elftools.elf.segments import Segment
import ctypes
import binascii
# import hexdump

# https://bbs.pediy.com/thread-267153.htm
# https://bbs.pediy.com/thread-253868.htm#msg_header_h1_5

filepath = './wayos_kernel.elf'

load_base=0
stack_base=0
stack_size=0x20000
var_base=load_base+stack_size
var_size=0x10000
stop_stub_addr=0x816E49C2
stop_stub_size=0x1000

emu = Uc(UC_ARCH_X86,UC_MODE_32 +UC_MODE_LITTLE_ENDIAN)

def disasm(bytecode,addr):
    md = Cs(CS_ARCH_X86,CS_MODE_32 + CS_MODE_LITTLE_ENDIAN)
    for asm in md.disasm(bytecode,addr):
        return '%s\t%s'%(asm.memonic,asm.op_str)

def align(addr,size,growl):
    UC_MEM_ALIGN = 0x1000
    to = ctypes.c_uint32(UC_MEM_ALIGN).value
    mask = ctypes.c_uint32(0xFFFFFFFF).value ^ ctypes.c_uint32(to -1).value
    right = addr + size
    right = (right + to - 1) & mask
    addr &= mask
    size = right - addr
    if growl:
        size  = (size + to - 1) & mask
    return addr,size

def hook_code(uc, address, size, user_data):
    bytecode=emu.mem_read(address,size)
    print(" 0x%x :%s"%(address,disasm(bytecode,address)))
    if address==stop_stub_addr:
        emu.emu_stop()

def  fhr_md5(key):
    with open(filepath, 'rb') as elffile:
        elf = ELFFile(elffile)
        load_segments = [x for x in elf.iter_segments() if x.header.p_type == 'PT_LOAD']

        # for segment in load_segments:
        segment = load_segments[0]
        prot = UC_PROT_ALL
        print('mem_map: addr=0x%x  size=0x%x' % (segment.header.p_vaddr, segment.header.p_memsz))
        addr, size = align(load_base + segment.header.p_vaddr, segment.header.p_memsz, True)
        print('%x  %x' %(addr,size))
        emu.mem_map(addr, size, prot)
        emu.mem_write(addr, segment.data())

    emu.mem_map(stack_base, stack_size, UC_PROT_ALL)
    emu.mem_map(var_base, var_size, UC_PROT_ALL)

    md5_ctx = var_base
    psw = var_base + 0x5000

    emu.mem_write(psw, key)

    # emu.mem_map(stop_stub_addr, stop_stub_size, UC_PROT_ALL)
    emu.reg_write(UC_X86_REG_EBX, md5_ctx)
    emu.reg_write(UC_X86_REG_ECX,stop_stub_addr)
    emu.reg_write(UC_X86_REG_ESP,stack_base+stack_size)

    my_MD5Init_addr=0x816E49A0
    my_MD5Update_addr=0x816E49D0
    my_MD5Final_addr=0x816E4A70

    # MD5Init
    code = emu.mem_read(my_MD5Init_addr, 0x816E49C9-0x816E49A0)
    x = ["0x{:x}".format(c) for c in code]
    emu.hook_add(UC_HOOK_CODE, hook_code)
    emu.emu_start(my_MD5Init_addr, my_MD5Init_addr + 0x816E49C9-0x816E49A0)

    # # MD5Update
    # emu.reg_write(UC_X86_REG_EBX, md5_ctx)
    # emu.reg_write(UC_MIPS_REG_A1, psw)
    # emu.reg_write(UC_MIPS_REG_A2, len(key))
    # emu.reg_write(UC_MIPS_REG_SP, stack_base + stack_size)
    # emu.reg_write(UC_MIPS_REG_RA, stop_stub_addr)
    # emu.emu_start(my_MD5Update_addr, my_MD5Update_addr + 0x1000)
    # # MD5Final
    #
    # emu.reg_write(UC_MIPS_REG_A0, md5_ctx)
    # emu.reg_write(UC_MIPS_REG_SP, stack_base + stack_size)
    # emu.reg_write(UC_MIPS_REG_RA, stop_stub_addr)
    # emu.emu_start(my_MD5Final_addr, my_MD5Final_addr + 0x1000)
fhr_md5(b'123')