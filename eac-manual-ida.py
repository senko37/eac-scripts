import ida_idaapi
import ida_name
import ida_bytes
import ida_segment
import ida_nalt
import ida_kernwin
import pdbparse.symlookup
from unicorn import *
from unicorn.x86_const import *

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

		self.decrypt_address.value = "0xFFFFF802EA115638"
		self.ntosbase.value = "0xFFFFF8027EA00000"
		self.ntospdb.value = r"C:\Windows\SYMBOLS\ntkrnlmp.pdb\54C8C67BD2A54FA5BD82F1BE21CF4A3A1\ntkrnlmp.pdb"

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
						ida_bytes.set_cmt(address_end, "%s (0x%X)" % (symbol, key_address), False)
						ida_bytes.set_cmt(key_address, "%s (Value: 0x%X)" % (symbol, value), False)
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

def PLUGIN_ENTRY():
	return eac_parser_manual_c()