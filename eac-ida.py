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
import string
import pdbparse.symlookup
from unicorn import *
from unicorn.x86_const import *

ntoskrnl_pdbpath = r"C:\Windows\SYMBOLS\ntkrnlmp.pdb\7AF38CD76BBE27EABD51A523C93EEAAC1\ntkrnlmp.pdb"
ntoskrnl_imagebase = 0xFFFFF8055F400000
ntoskrnl_imagesize = 0x01047000

fltmgr_pdbpath = r"C:\Windows\SYMBOLS\fltMgr.pdb\83BB2BA7D753BA4755EA363DD75677321\fltMgr.pdb"
fltmgr_imagebase = 0xFFFFF80563E00000
fltmgr_imagesize = 0x0007A000

cng_pdbpath = r"C:\Windows\SYMBOLS\cng.pdb\A1FD77265441DB21FB4CC9B565F8477B1\cng.pdb"
cng_imagebase = 0xFFFFF80564060000
cng_imagesize = 0x000BE000

decryptfn_address = 0xFFFFF805D59F3758

allowed_symbols = string.printable[:-5]

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

def set_cmt(ea, comm, code = True):
	ida_bytes.create_byte(ea, 1, True)
	if code:
		ida_ua.create_insn(ea)
	ida_bytes.set_cmt(ea, comm, False)

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

	def lookup(self, address):
		for sym in self.syms:
			if address >= sym[1] and address <= (sym[1] + sym[2]):
				name = sym[0].lookup(address)
				if name == "unknown":
					return "Unknown 0x%X" % address
				return name
		return "Unknown 0x%X" % address

class eac_parser_c:
	imagebase, imagesize = 0, 0
	uc = None

	def __init__(self):
		last_segment = ida_segment.get_last_seg()

		self.imagebase = ida_nalt.get_imagebase()
		self.imagesize = last_segment.end_ea - self.imagebase

		self.uc = unicorn_c(self.imagebase, self.imagesize)

class eac_funcs_parser_c(eac_parser_c):
	current_fn = 0
	blocks_count = 0
	base_address = 0
	cf_handler = 0
	offset_reg = 0
	first_block = 0
	block_xrefs = {}
	parsed_blocks = []

	def __init__(self):
		eac_parser_c.__init__(self)

		self.parse()

	def parse_block(self, address):
		insns = []
		child_offsets = []

		set_cmt(address, "Basic block start / Enter: 0x%X" % self.current_fn)

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
				set_cmt(insn.ea, "Basic block end")
				break
			
		for insn in reversed(insns):
			if insn.Op1.type == ida_ua.o_reg and insn.Op1.reg == self.offset_reg:
				if insn.Op2.type == ida_ua.o_imm:
					child_offsets.append([insn.ea, insn.Op2.value])
				elif insn.Op2.type == ida_ua.o_reg:
					address_r = insn.ea
					for _ in range(len(insns)):
						insn_r = ida_ua.insn_t()
						address_r = ida_ua.decode_prev_insn(insn_r, address_r)

						if insn_r.Op1.type == ida_ua.o_reg and insn_r.Op1.reg == insn.Op2.reg and insn_r.Op2.type == ida_ua.o_imm:
							child_offsets.append([insn.ea, insn_r.Op2.value])
							break

		return child_offsets

	def parse_blocks(self, parent_address, offsets):
		for offset in offsets:
			address = (self.base_address + offset[1]) & 0xFFFFFFFFFFFFFFFF
			if not(address >= self.imagebase and address <= (self.imagebase + self.imagesize)):
				continue

			set_cmt(offset[0], "Jump to 0x%X" % address)

			if parent_address:
				if address in self.block_xrefs and parent_address not in self.block_xrefs[address]:
					self.block_xrefs[address][1].append(parent_address)
				elif address not in self.block_xrefs:
					self.block_xrefs[address] = [self.current_fn, [parent_address]]

			if address in self.parsed_blocks:
				continue

			child_offsets = self.parse_block(address)
			self.parsed_blocks.append(address)

			self.parse_blocks(address, child_offsets)

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

		if self.blocks_count == 3:
			if self.is_cf_handler(address):
				self.cf_handler = address
				self.first_block = (self.base_address + uc.reg_read(regs_iu[self.offset_reg])) & 0xFFFFFFFFFFFFFFFF
			else:
				set_cmt(self.current_fn, "First block: 0x%X (Unknown control flow)" % address)
				set_cmt(address, "Basic block start / Enter: 0x%X" % self.current_fn)
				print("Function: 0x%X / First block: 0x%X (Unknown control flow)" % (self.current_fn, address))

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

			self.parse_blocks(None, self.parse_block(self.first_block))

			set_cmt(self.current_fn, "First block: 0x%X (Total: %i)" % (self.first_block, len(self.parsed_blocks)))
			print("Function: 0x%X / First block: 0x%X (Total: %i)" % (self.current_fn, self.first_block, len(self.parsed_blocks)))

		for block_address in self.block_xrefs:
			enter_fn = self.block_xrefs[block_address][0]
			xrefs = self.block_xrefs[block_address][1]
			if xrefs:
				set_cmt(block_address, "Basic block start / Enter: 0x%X / Xrefs: %s" % (enter_fn, " ".join("0x%X" % xref for xref in xrefs)))

		return True

class eac_imports_parser_c(eac_parser_c, symbols_c):
	parsed_keys = {}
	parse_type = 0
	key_address = 0
	trace_start_address = 0

	def __init__(self):
		eac_parser_c.__init__(self)
		symbols_c.__init__(self, [
			[ntoskrnl_pdbpath, ntoskrnl_imagebase, ntoskrnl_imagesize], 
			[fltmgr_pdbpath, fltmgr_imagebase, fltmgr_imagesize],
			[cng_pdbpath, cng_imagebase, cng_imagesize]])

		self.parse()

	def hook_code(self, uc, address, size, user_data):
		if address >= self.trace_start_address and address <= (self.trace_start_address + 0xFF):
			regs = [uc.reg_read(UC_X86_REG_RAX), uc.reg_read(UC_X86_REG_RDX)]
			for reg in regs:
				if (reg >> 48) == 0xFFFF and not(reg >= self.imagebase and reg <= self.imagebase + self.imagesize):
					self.parsed_keys[self.key_address] = [self.lookup(reg), reg]
					uc.reg_write(UC_X86_REG_RIP, 0)
					return

	def parse_call(self, address):
		self.parse_type = 0
		self.key_address = 0

		address_t = address
		for _ in range(10):
			insn = ida_ua.insn_t()
			address_t = ida_ua.decode_prev_insn(insn, address_t)
			if address_t == ida_idaapi.BADADDR:
				break

			if insn.itype == ida_allins.NN_lea and insn.Op1.reg == idautils.procregs.rcx.reg and insn.Op2.type == ida_ua.o_mem:
				self.key_address = insn.Op2.addr
				break

		if self.key_address == 0:
			return False

		if self.key_address in self.parsed_keys:
			set_cmt(address, "%s (0x%X)" % (self.parsed_keys[self.key_address][0], self.key_address))
			return True

		self.trace_start_address = address + ida_bytes.get_item_size(address)

		self.uc.uc.reg_write(UC_X86_REG_RCX, self.key_address)

		try:
			self.uc.emu_start(address, 0)
		except UcError as e:
			pass

		if self.key_address in self.parsed_keys:
			set_cmt(address, "%s (0x%X)" % (self.parsed_keys[self.key_address][0], self.key_address))

			set_cmt(self.key_address, "%s (Value: 0x%X)" % (self.parsed_keys[self.key_address][0], self.parsed_keys[self.key_address][1]), False)
			ida_name.set_name(self.key_address, self.parsed_keys[self.key_address][0], ida_name.SN_NOCHECK | ida_name.SN_NOWARN)

			print("Import: %s / Key: 0x%X (Type: 1)" % (self.parsed_keys[self.key_address][0], self.key_address))

			return True

		return False

	def parse_lea(self, address):
		self.parse_type = 1

		start_address = 0

		address_t = address
		for _ in range(10):
			insn = ida_ua.insn_t()
			size = ida_ua.decode_insn(insn, address_t)
			if size == 0:
				break

			if insn.itype == ida_allins.NN_callni and (insn.Op1.type == ida_ua.o_displ or insn.Op1.type == ida_ua.o_phrase):
				start_address = address_t
				self.trace_start_address = address_t + size
				break

			address_t += size

		if self.trace_start_address == 0:
			return False

		address_resolved = False

		address_t = self.trace_start_address
		for _ in range(20):
			insn = ida_ua.insn_t()
			address_t = ida_ua.decode_prev_insn(insn, address_t)
			if address_t == ida_idaapi.BADADDR:
				break

			if insn.itype == ida_allins.NN_lea and insn.Op1.reg == idautils.procregs.rcx.reg and insn.Op2.type == ida_ua.o_mem:
				self.key_address = insn.Op2.addr
				break		
			elif insn.itype == ida_allins.NN_mov and insn.Op1.reg == idautils.procregs.rcx.reg and insn.Op2.type == ida_ua.o_reg:
				rcx_address = insn.ea + insn.size

				address_r = rcx_address
				for _ in range(10):
					insn_r = ida_ua.insn_t()
					address_r = ida_ua.decode_prev_insn(insn_r, address_r)
					if address_r == ida_idaapi.BADADDR:
						break

					if insn_r.itype == ida_allins.NN_lea and insn_r.Op1.reg == insn.Op2.reg:
						try:
							self.uc.emu_start(insn_r.ea, rcx_address)
						except UcError as e:
							pass

						self.key_address = self.uc.uc.reg_read(UC_X86_REG_RCX)
						address_resolved = True
				break

		if self.key_address == 0:
			return False

		if self.key_address in self.parsed_keys:
			set_cmt(start_address, "%s (0x%X)" % (self.parsed_keys[self.key_address][0], self.key_address))
			if address_resolved:
				print("Import: %s / Key: 0x%X / Address: 0x%X (Type: 2)" % (self.parsed_keys[self.key_address][0], self.key_address, start_address))

			return True

		self.uc.uc.reg_write(UC_X86_REG_RCX, self.key_address)

		try:
			self.uc.emu_start(start_address, 0)
		except UcError as e:
			pass

		if self.key_address in self.parsed_keys:
			set_cmt(start_address, "%s (0x%X)" % (self.parsed_keys[self.key_address][0], self.key_address))

			set_cmt(self.key_address, "%s (Value: 0x%X)" % (self.parsed_keys[self.key_address][0], self.parsed_keys[self.key_address][1]), False)
			ida_name.set_name(self.key_address, self.parsed_keys[self.key_address][0], ida_name.SN_NOCHECK | ida_name.SN_NOWARN)

			if address_resolved:
				print("Import %s: / Key: 0x%X / Address: 0x%X (Type: 2)" % (self.parsed_keys[self.key_address][0], self.key_address, start_address))
			else:
				print("Import %s: / Key: 0x%X (Type: 2)" % (self.parsed_keys[self.key_address][0], self.key_address))

			return True

		return False

	def parse(self):
		self.uc.uc.hook_add(UC_HOOK_CODE, self.hook_code)

		xref = ida_xref.get_first_cref_to(decryptfn_address)
		while xref != ida_idaapi.BADADDR:
			insn = ida_ua.insn_t()
			ida_ua.decode_insn(insn, xref)

			self.key_address = 0
			self.trace_start_address = 0

			if insn.itype == ida_allins.NN_call:
				self.parse_call(xref)

			xref = ida_xref.get_next_cref_to(decryptfn_address, xref)

		xref = ida_xref.get_first_dref_to(decryptfn_address)
		while xref != ida_idaapi.BADADDR:
			insn = ida_ua.insn_t()
			ida_ua.decode_insn(insn, xref)

			self.key_address = 0
			self.trace_start_address = 0

			if insn.itype == ida_allins.NN_lea:
				self.parse_lea(xref)

			xref = ida_xref.get_next_dref_to(decryptfn_address, xref)

		return True

class eac_strings_parser_c(eac_parser_c):
	str_address = 0
	str_counter = 0
	str_size = 0
	insn_jmp = None

	def __init__(self):
		eac_parser_c.__init__(self)

		self.parse()

	def hook_mem_write(self, uc, access, address, size, value, user_data):
		if self.str_address:
			return

		address_t = uc.reg_read(UC_X86_REG_RAX)
		if address >= self.uc.stackbase and address <= (self.uc.stackbase + self.uc.stacksize) and address == address_t:
			self.str_address = address

	def hook_code(self, uc, address, size, user_data):
		if address == self.insn_jmp.ea and self.str_counter <= self.str_size:
			uc.reg_write(UC_X86_REG_RIP, self.insn_jmp.Op1.addr)
			self.str_counter += 1

	def parse(self):
		rdata = ida_segment.get_segm_by_name(".rdata")
		if not rdata:
			return False

		self.uc.uc.hook_add(UC_HOOK_MEM_WRITE, self.hook_mem_write)
		self.uc.uc.hook_add(UC_HOOK_CODE, self.hook_code)

		for address in range(rdata.start_ea, rdata.end_ea, 8):
			xref = ida_xref.get_first_dref_to(address)
			if xref == ida_idaapi.BADADDR:
				continue

			insn = ida_ua.insn_t()
			if ida_ua.decode_insn(insn, xref) == 0 or insn.itype != ida_allins.NN_lea:
				continue

			func = ida_funcs.get_func(xref)
			if not func:
				continue

			basic = ida_gdl.FlowChart(func)
			if basic.size < 2:
				continue

			block_first = None
			for block in basic:
				if block.end_ea >= xref + 1 and block.start_ea <= xref + 1:
					block_first = block
					break

			if not block_first:
				continue

			block_first_s = list(block_first.succs())
			if len(block_first_s) != 1:
				continue

			block_second = block_first_s[0]
			block_second_p = list(block_second.preds())
			if len(block_second_p) != 2:
				continue

			if block_second_p[0].id != block_first.id or block_second_p[1].id != block_second.id:
				continue

			self.insn_jmp = ida_ua.insn_t()
			ida_ua.decode_prev_insn(self.insn_jmp, block_second.end_ea)

			insn_cmp = ida_ua.insn_t()
			ida_ua.decode_prev_insn(insn_cmp, self.insn_jmp.ea)
			if insn_cmp.itype != ida_allins.NN_cmp:
				continue

			self.str_size = 512
			if insn_cmp.Op2.type == ida_ua.o_imm:
				self.str_size = insn_cmp.Op2.value

			self.str_address = 0
			self.str_counter = 0

			try:
				self.uc.emu_start(block_first.start_ea, block_second.end_ea)
			except UcError as e:
				pass

			if self.str_address == 0 or self.str_counter == 0:
				continue

			str_bytes = self.uc.uc.mem_read(self.str_address, self.str_size)

			str_bytes = str_bytes.lstrip(b"\0")
			if str_bytes[1] == 0:
				str_bytes = str_bytes[:str_bytes.find(b"\0\0")].replace(b"\0", b"")
			else:
				str_bytes = str_bytes[:str_bytes.find(b"\0")]

			str_decoded = str_bytes.decode("ascii", "ignore")

			str_valid = True
			for c in str_decoded:
				if c not in allowed_symbols:
					str_valid = False
					break

			if str_valid == False:
				continue

			set_cmt(address, str_decoded, False)
			ida_name.set_name(address, str_decoded, ida_name.SN_NOCHECK | ida_name.SN_NOWARN)

			print("String: %s / Address: 0x%X" % (str_decoded, address))

		return True

def main():
	eac_funcs_parser_c()
	eac_imports_parser_c()
	eac_strings_parser_c()

if __name__ == "__main__":
	main()