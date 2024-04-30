import ida_segment
import ida_funcs
import ida_xref
import ida_gdl
import ida_ua
import ida_idaapi
import ida_bytes
import ida_name
import ida_nalt
import ida_allins
import idautils
import pdbparse.symlookup
from unicorn import *
from unicorn.x86_const import *

ntoskrnl_pdbpath = r"C:\Windows\SYMBOLS\ntkrnlmp.pdb\54C8C67BD2A54FA5BD82F1BE21CF4A3A1\ntkrnlmp.pdb"
ntoskrnl_imagebase = 0xFFFFF8027EA00000
ntoskrnl_imagesize = 0x01047000

fltmgr_pdbpath = r"C:\Windows\SYMBOLS\fltMgr.pdb\83BB2BA7D753BA4755EA363DD75677321\fltMgr.pdb"
fltmgr_imagebase = 0xFFFFF80282010000
fltmgr_imagesize = 0x0007A000

regs_iu = {
	idautils.procregs.rax.reg: UC_X86_REG_RAX,
	idautils.procregs.rcx.reg: UC_X86_REG_RCX,
	idautils.procregs.rdx.reg: UC_X86_REG_RDX,
	idautils.procregs.rbx.reg: UC_X86_REG_RBX,
	idautils.procregs.rsp.reg: UC_X86_REG_RSP,
	idautils.procregs.rbp.reg: UC_X86_REG_RBP,
	idautils.procregs.rsi.reg: UC_X86_REG_RSI,
	idautils.procregs.rdi.reg: UC_X86_REG_RDI,
	idautils.procregs.r8.reg: UC_X86_REG_R8,
	idautils.procregs.r9.reg: UC_X86_REG_R9,
	idautils.procregs.r10.reg: UC_X86_REG_R10,
	idautils.procregs.r11.reg: UC_X86_REG_R11,
	idautils.procregs.r12.reg: UC_X86_REG_R12,
	idautils.procregs.r13.reg: UC_X86_REG_R13,
	idautils.procregs.r14.reg: UC_X86_REG_R14,
	idautils.procregs.r15.reg: UC_X86_REG_R15,
}

def set_cmt(ea, comm, rptble):
	ida_bytes.create_byte(ea, 1, True) 
	ida_ua.create_insn(ea)
	ida_bytes.set_cmt(ea, comm, rptble)

class unicorn_c:
	uc = None
	stackbase, stacksize = 0, 0

	def __init__(self, imagebase, imagesize, stackbase = 0xF0000000, stacksize = 0x200000):
		self.uc = Uc(UC_ARCH_X86, UC_MODE_64)

		self.uc.mem_map(imagebase, imagesize)
		self.uc.mem_write(imagebase, ida_bytes.get_bytes(imagebase, imagesize))

		self.uc.mem_map(stackbase, stacksize)
		self.stackbase = stackbase
		self.stacksize = stacksize

	def restore_sp(self):
		self.uc.reg_write(UC_X86_REG_RSP, self.stackbase + self.stacksize - 0x1000)
		self.uc.reg_write(UC_X86_REG_RBP, self.stackbase + self.stacksize - 0x2000)

	def emu_start(self, address_start, address_end):
		self.restore_sp()
		self.uc.emu_start(address_start, address_end)

class symbols_c:
	syms = []

	def __init__(self, syms):
		for s in syms:
			sym = pdbparse.symlookup.Lookup([[s[0], s[1]]])
			if sym:
				self.syms.append([sym, s[1], s[2]])

	def lookup(address):
		for sym in syms:
			if address >= sym[1] and address <= (sym[1] + sym[2]):
				name = sym[0].lookup(Address)
				if name == "unknown":
					return None
				return name
		return None

class eac_parser_c:
	imagebase, imagesize = 0, 0
	uc, sym = None, None

	def __init__(self):
		last_segment = ida_segment.get_last_seg()

		self.imagebase = ida_nalt.get_imagebase()
		self.imagesize = last_segment.end_ea - self.imagebase

		self.uc = unicorn_c(self.imagebase, self.imagesize)
		self.sym = symbols_c([[ntoskrnl_pdbpath, ntoskrnl_imagebase, ntoskrnl_imagesize], [fltmgr_pdbpath, fltmgr_imagebase, fltmgr_imagesize]])

		print("imagesize: 0x%X, imagesize: 0x%X" % (self.imagebase, self.imagesize))

class eac_obffuncs_parser_c(eac_parser_c):
	current_fn = 0
	blocks_count = 0
	base_address = 0
	cf_handler = 0
	offset_reg = 0
	first_block = 0
	parsed_blocks = []

	def __init__(self):
		eac_parser_c.__init__(self)

		self.parse()

	def parse_block(self, address):
		insns = []
		child_offsets = []

		set_cmt(address, "Basic block start", False)

		locked = True
		address_t = address
		while True:
			insn = ida_ua.insn_t()
			size = ida_ua.decode_insn(insn, address_t)
			if size == 0:
				return []
			address_t += size

			if insn.itype == ida_allins.NN_push and insn.Op1.reg == self.offset_reg:
				locked = False
			if locked:
				continue

			insns.append(insn)
			if insn.itype == ida_allins.NN_jmp or insn.itype == ida_allins.NN_retn:
				set_cmt(insn.ea, "Basic block end", False)
				break
			
		for insn in reversed(insns):
			if insn.Op1.type == ida_ua.o_reg and insn.Op1.reg == self.offset_reg:
				if insn.Op2.type == ida_ua.o_imm:
					child_offsets.append([insn.ea, insn.Op2.value])
				elif insn.Op2.type == ida_ua.o_reg:
					address_r = insn.ea
					for _ in range(10):
						insn_r = ida_ua.insn_t()
						address_r = ida_ua.decode_prev_insn(insn_r, address_r)

						if insn_r.Op1.type == ida_ua.o_reg and insn_r.Op2.type == ida_ua.o_imm and insn_r.Op1.reg == insn.Op2.reg:
							child_offsets.append([insn.ea, insn_r.Op2.value])
							break

		return child_offsets

	def parse_blocks(self, offsets):
		for offset in offsets:
			address = (self.base_address + offset[1]) & 0xFFFFFFFFFFFFFFFF
			set_cmt(offset[0], "Jump to 0x%X" % address, False)

			if address in self.parsed_blocks:
				continue

			child_offsets = self.parse_block(address)
			self.parsed_blocks.append(address)

			self.parse_blocks(child_offsets)

	def is_cf_handler(self, address):
		types = [ida_allins.NN_push, ida_allins.NN_lea, ida_allins.NN_lea, ida_allins.NN_pop, ida_allins.NN_jmpni]

		for i in range(len(types)):
			insn = ida_ua.insn_t()
			size = ida_ua.decode_insn(insn, address)
			if size == 0 or types[i] != insn.itype:
				return False

			if i == 1:
				self.base_address = insn.Op2.addr
			elif i == 4:
				self.offset_reg = insn.Op1.reg

			address += size

		return True

	def hook_block(self, uc, address, size, user_data):
		ida_bytes.create_byte(address, 1, True) 
		ida_ua.create_insn(address)

		if self.is_cf_handler(address):
			self.cf_handler = address
			self.first_block = (self.base_address + uc.reg_read(regs_iu[self.offset_reg])) & 0xFFFFFFFFFFFFFFFF
			uc.reg_write(UC_X86_REG_RIP, 0)

		if self.blocks_count > 3:
			uc.reg_write(UC_X86_REG_RIP, 0)

		self.blocks_count += 1

	def parse(self):
		enter_fn_pattern = ida_bytes.compiled_binpat_vec_t()
		encoding = ida_nalt.get_default_encoding_idx(ida_nalt.BPU_1B)
		ida_bytes.parse_binpat_str(enter_fn_pattern, self.imagebase, "51 48 8D 0D 00 00 00 00 48 81 C1 ? ? ? ? 48 89 4C 24 ? 59 EB FF", 16, encoding)

		self.uc.uc.hook_add(UC_HOOK_BLOCK, self.hook_block)

		enter_fn = self.imagebase
		while True:
			enter_fn, _ = ida_bytes.bin_search3(enter_fn + 1, self.imagebase + self.imagesize, enter_fn_pattern, ida_bytes.BIN_SEARCH_FORWARD)
			if enter_fn == ida_idaapi.BADADDR:
				break

			self.current_fn = enter_fn
			self.blocks_count = 0
			self.base_address = 0
			self.cf_handler = 0
			self.offset_reg = 0
			self.first_block = 0
			self.parsed_blocks = []

			ida_bytes.create_byte(enter_fn, 1, True) 
			ida_ua.create_insn(enter_fn)

			try:
				self.uc.emu_start(enter_fn, 0)
			except UcError as e:
				pass

			if self.first_block == 0:
				continue

			self.parse_blocks(self.parse_block(self.first_block))

			set_cmt(enter_fn, "First block: 0x%X (Total: %i)" % (self.first_block, len(self.parsed_blocks)), False)
			print("Function 0x%X / First block: 0x%X (Total: %i)" % (enter_fn, self.first_block, len(self.parsed_blocks)))

def main():
	eac_obffuncs_parser_c()

if __name__ == "__main__":
	main()