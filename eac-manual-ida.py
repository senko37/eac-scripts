import ida_idaapi
import ida_ua
import ida_name
import ida_bytes
import ida_segment
import ida_nalt
import ida_kernwin
import ida_allins
import ida_diskio
import idautils
import pdbparse.symlookup
from unicorn import *
from unicorn.x86_const import *
import subprocess

wingraph_template = "graph: {\ntitle: \"%s\"\n%s\n%s\n}"

regs = {
	"RAX": UC_X86_REG_RAX,
	"RCX": UC_X86_REG_RCX,
	"RDX": UC_X86_REG_RDX,
	"RDI": UC_X86_REG_RDI,
	"RSI": UC_X86_REG_RSI,
	"R8": UC_X86_REG_R8,
	"R9": UC_X86_REG_R9,
	"R10": UC_X86_REG_R10,
	"R11": UC_X86_REG_R11,
	"R12": UC_X86_REG_R12,
	"R13": UC_X86_REG_R13,
	"R14": UC_X86_REG_R14,
	"R15": UC_X86_REG_R15,
}

regs_iu = {
	0: UC_X86_REG_RAX,
	1: UC_X86_REG_RCX,
	2: UC_X86_REG_RDX,
	3: UC_X86_REG_RBX,
	4: UC_X86_REG_RSP,
	5: UC_X86_REG_RBP,
	6: UC_X86_REG_RSI,
	7: UC_X86_REG_RDI,
	8: UC_X86_REG_R8,
	9: UC_X86_REG_R9,
	10: UC_X86_REG_R10,
	11: UC_X86_REG_R11,
	12: UC_X86_REG_R12,
	13: UC_X86_REG_R13,
	14: UC_X86_REG_R14,
	15: UC_X86_REG_R15,
}

def set_cmt(ea, comm, code = True):
	ida_bytes.create_byte(ea, 1, True)
	if code:
		ida_ua.create_insn(ea)
	ida_bytes.set_cmt(ea, comm, False)

class eac_parser_settings_c(ida_kernwin.Form):
	def __init__(self):
		ida_kernwin.Form.__init__(self, r"""BUTTON YES* Start
BUTTON CANCEL Cancel
EAC manual parser (settings)

<##Key address:{key_address}>
<##Emu start address:{address_start}>
<##Emu stop address:{address_end}>""", 
		{
			"key_address": ida_kernwin.Form.DirInput(),
			"address_start": ida_kernwin.Form.DirInput(),
			"address_end": ida_kernwin.Form.DirInput(),
		})
		self.Compile()

	def Show(self):
		return self.Execute()

class eac_parser_setup_c(ida_kernwin.Form):
	def __init__(self):
		ida_kernwin.Form.__init__(self, r"""BUTTON YES* Setup
BUTTON CANCEL Cancel
EAC manual parser (setup)

<##Decrypt function address:{decrypt_address}>
<##Ntoskrnl imagebase:{ntosbase}>
<##Ntoskrnl pdb path:{ntospdb}>""", 
		{
			"decrypt_address": ida_kernwin.Form.DirInput(),
			"ntosbase": ida_kernwin.Form.DirInput(),
			"ntospdb": ida_kernwin.Form.DirInput(),
		})
		self.Compile()

		self.decrypt_address.value = "0xFFFFF805D59F3758"
		self.ntosbase.value = "0xFFFFF8055F400000"
		self.ntospdb.value = r"C:\Windows\SYMBOLS\ntkrnlmp.pdb\7AF38CD76BBE27EABD51A523C93EEAAC1\ntkrnlmp.pdb"

	def Show(self):
		return self.Execute()

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

		ida_kernwin.msg("Imagebase: 0x%X / Imagesize: 0x%X\n" % (self.imagebase, self.imagesize))

class eac_parser_manual_c(ida_idaapi.plugin_t):
	comment = ""
	help = ""
	wanted_name = "EAC manual parser"
	wanted_hotkey = "Ctrl-Shift-E"
	flags = ida_idaapi.PLUGIN_KEEP

	inited = False
	decryptfn_address = 0
	ntoskrnl_imagebase = 0
	ntoskrnl_pdbpath = ""
	eac_parser = None
	symbols = None

	def init(self):
		return self.flags

	def term(self):
		pass

	def run(self, arg):
		if self.inited:
			settings = eac_parser_settings_c()
			if settings.Show():
				key_address = int(settings.key_address.value, 16)
				self.eac_parser.uc.uc.reg_write(UC_X86_REG_RCX, key_address)

				try:
					self.eac_parser.uc.emu_start(self.decryptfn_address, 0)
				except UcError as e:
					pass

				address_start = int(settings.address_start.value, 16)
				address_end = int(settings.address_end.value, 16)

				try:
					self.eac_parser.uc.emu_start(address_start, address_end)
				except UcError as e:
					pass

				for reg in regs:
					value = self.eac_parser.uc.uc.reg_read(regs[reg])
					if (value >> 48) == 0xFFFF and not(value >= self.eac_parser.imagebase and value <= self.eac_parser.imagebase + self.eac_parser.imagesize):
						symbol = self.symbols.lookup(value)
						set_cmt(address_end, "%s (0x%X)" % (symbol, key_address))
						set_cmt(key_address, "%s (Value: 0x%X)" % (symbol, value), False)
						ida_name.set_name(key_address, symbol, ida_name.SN_NOCHECK | ida_name.SN_NOWARN)
						ida_kernwin.msg("%s: 0x%X (%s)\n" % (reg, value, symbol))

				ida_kernwin.msg("Key: 0x%X / Address: 0x%X\n" % (key_address, address_start))
		else:
			setup = eac_parser_setup_c()
			if setup.Show():
				self.decryptfn_address = int(setup.decrypt_address.value, 16)
				self.ntoskrnl_imagebase = int(setup.ntosbase.value, 16)
				self.ntoskrnl_pdbpath = setup.ntospdb.value

				self.eac_parser = eac_parser_c()
				self.symbols = symbols_c([[self.ntoskrnl_pdbpath, self.ntoskrnl_imagebase, 0xFFFFFFFFFFFFFFFF]])

				self.inited = True
				return self.run(arg)

class eac_funcs_parser_c(ida_idaapi.plugin_t):
	comment = ""
	help = ""
	wanted_name = "EAC manual parser"
	wanted_hotkey = "Ctrl-Shift-E"
	flags = ida_idaapi.PLUGIN_KEEP

	inited = False
	current_fn = 0
	blocks_count = 0
	base_address = 0
	cf_handler = 0
	offset_reg = 0
	first_block = 0
	block_xrefs = {}
	block_paths = {}
	parsed_blocks = []

	def init(self):
		return self.flags

	def term(self):
		pass

	def parse_block(self, address):
		insns = []
		child_offsets = []

		set_cmt(address, "Basic block start / Enter: 0x%X" % self.current_fn)

		address_t = address
		while True:
			insn = ida_ua.insn_t()
			size = ida_ua.decode_insn(insn, address_t)
			if size == 0:
				return []
			address_t += size

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

			if parent_address in self.block_paths:
				self.block_paths[parent_address][0].append(address)
			else:
				self.block_paths[parent_address] = [[address]]

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
				ida_kernwin.msg("Function: 0x%X / First block: 0x%X (Unknown control flow)\n" % (self.current_fn, address))

			uc.reg_write(UC_X86_REG_RIP, 0)

		self.blocks_count += 1

	def parse(self):
		enter_fn_pattern = ida_bytes.compiled_binpat_vec_t()
		encoding = ida_nalt.get_default_encoding_idx(ida_nalt.BPU_1B)
		ida_bytes.parse_binpat_str(enter_fn_pattern, self.imagebase, "51 48 8D 0D 00 00 00 00 48 81 C1 ? ? ? ? 48 89 4C 24 ? 59 EB FF", 16, encoding)

		self.uc.uc.hook_add(UC_HOOK_BLOCK, self.hook_block)

		enter_fn, _ = ida_bytes.bin_search3(ida_kernwin.get_screen_ea(), self.imagebase + self.imagesize, enter_fn_pattern, ida_bytes.BIN_SEARCH_FORWARD)
		if enter_fn == ida_idaapi.BADADDR:
			return False

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
			return False

		self.parse_blocks(self.first_block, self.parse_block(self.first_block))
		self.block_paths[enter_fn] = [[self.first_block], 0]

		set_cmt(enter_fn, "First block: 0x%X (Total: %i)" % (self.first_block, len(self.parsed_blocks)))
		ida_kernwin.msg("Function: 0x%X / First block: 0x%X (Total: %i)\n" % (enter_fn, self.first_block, len(self.parsed_blocks)))

		for block_address in self.block_xrefs:
			enter_fn = self.block_xrefs[block_address][0]
			xrefs = self.block_xrefs[block_address][1]

			if xrefs:
				set_cmt(block_address, "Basic block start / Enter: 0x%X / Xrefs: %s" % (enter_fn, " ".join("0x%X" % xref for xref in xrefs)))

		node_counter = 1
		nodes = "node: { title: \"0\" label: \"Enter: 0x%X\" color: orchid textcolor: black borderwidth: 5 bordercolor: black }\n" % self.current_fn
		edges = ""

		for block_address in self.block_paths:
			if block_address == self.current_fn:
				continue

			nodes += "node: { title: \"%i\" label: \"0x%X\" textcolor: black bordercolor: black }\n" % (node_counter, block_address)
			if self.block_paths[block_address]:
				self.block_paths[block_address].append(node_counter)
			node_counter += 1

		for block_address in self.block_paths:
			paths = self.block_paths[block_address][0]
			for path in paths:
				if path not in self.block_paths:
					nodes += "node: { title: \"%i\" label: \"0x%X\" color: red textcolor: black bordercolor: black }\n" % (node_counter, path)
					edges += "edge: { sourcename: \"%i\" targetname: \"%i\" }\n" % (self.block_paths[block_address][1], node_counter)
					node_counter += 1
				else:
					edges += "edge: { sourcename: \"%i\" targetname: \"%i\" }\n" % (self.block_paths[block_address][1], self.block_paths[path][1])

		wingraph_cfg = wingraph_template % ("Function 0x%X control flow" % self.current_fn, nodes, edges)
		ida_dir = ida_diskio.idadir(None)
		filename = "%s\\GRAPH_%X.tmp" % (ida_dir, self.current_fn)
		with open(filename, "w") as file:
			file.write(wingraph_cfg)

		subprocess.Popen(["%s\\qwingraph.exe" % ida_dir, "-remove", "-timelimit", "10", filename])

		return True

	def run(self, arg):
		if self.inited:
			self.parse()
		else:
			eac_parser_c.__init__(self)

			self.inited = True
			return self.run(arg)

def PLUGIN_ENTRY():
	return eac_funcs_parser_c()