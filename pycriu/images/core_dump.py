# This module is to generate valid elf core dump file from CRIU images.
# Code is inspired by google-coredumper:
#     https://code.google.com/p/google-coredumper/

from ctypes import *
import elf as elf_h
import os, sys, io
import images
import copy

class elfhdr(elf_h.Elf64_Ehdr):
	pass


class memelfnote(Structure):
	_fields_ = [
		('name',	c_char_p),
		('type',	c_int),
		('datasz',	c_uint),
		('data',	c_void_p)
		]


class elf_siginfo(Structure):
	_fields_ = [
		('si_signo',	c_int),	# signal number
		('si_code',	c_int),	# extra code
		('si_errno',	c_int)	# errno
		]


class timeval(Structure):
	_fields_ = [
		('tv_sec',	c_long),	# seconds
		('tv_usec',	c_long)		# microseconds
		]


class elf_gregset_t(Structure):
	_fields_ = [
		('r15', 	c_ulong),
		('r14', 	c_ulong),
		('r13', 	c_ulong),
		('r12',		c_ulong),
		('bp',		c_ulong),
		('bx',		c_ulong),
		('r11',		c_ulong),
		('r10',		c_ulong),
		('r9',		c_ulong),
		('r8',		c_ulong),
		('ax',		c_ulong),
		('cx',		c_ulong),
		('dx',		c_ulong),
		('si',		c_ulong),
		('di',		c_ulong),
		('orig_ax',	c_ulong),
		('ip',		c_ulong),
		('cs',		c_ulong),
		('flags',	c_ulong),
		('sp',		c_ulong),
		('ss',		c_ulong),
		('fs_base',	c_ulong),
		('gs_base',	c_ulong),
		('ds',		c_ulong),
		('es',		c_ulong),
		('fs',		c_ulong),
		('gs',		c_ulong)
		]


class elf_prstatus(Structure):
	_fields_ = [
		('pr_info',	elf_siginfo),	# Info associated with signal
		('pr_cursig',	c_short),	# Current signal
		('pr_sigpend',	c_ulong),	# Set of pending signals
		('pr_sighold',	c_ulong),	# Set of held signals
		('pr_pid',	c_int),
		('pr_ppid',	c_int),
		('pr_pgrp',	c_int),
		('pr_sid',	c_int),
		('pr_utime',	timeval),	# User time
		('pr_stime',	timeval),	# System time
		('pr_cutime',	timeval),	# Cumulative user time
		('pr_cstime',	timeval),	# Cumulative system time
		('pr_reg',	elf_gregset_t),	# GP registers
		#XXX Skip fields enabled by CONFIG_BINFMT_ELF_FDPIC
		('pr_fpvalid',	c_int)		# True if math co-processor being used
		]


class elf_prpsinfo(Structure):
	_fields_ = [
		('pr_state',	c_byte),	# Numeric process state
		('pr_sname',	c_char),	# Char for pr_state
		('pr_zomb',	c_byte),	# zombie
		('pr_nice',	c_char),	# Nice val
		('pr_flag',	c_ulong),	# flags
		('pr_uid',	c_uint),
		('pr_gid',	c_uint),
		('pr_pid',	c_int),
		('pr_ppid',	c_int),
		('pr_pgrp',	c_int),
		('pr_sid',	c_int),
		('pr_fname',	c_char*16),	# filename of executable
		('pr_psargs',	c_char*80),	# initial part of arg list
		]


class elf_note_info(Structure):
	_fields_ = [
		('notes',		POINTER(memelfnote)),
		('notes_files',		POINTER(memelfnote)),
		('prstatus',		POINTER(elf_prstatus)), #NT_PRSTATUS
		('psinfo',		POINTER(elf_prpsinfo)), #NT_PRPSINFO
		# ('thread_list',		list_head), XXX using list instead
		('fpu',			POINTER(elf_fpregset_t)),
		# elf_fpxregset_t *xfpu XXX 32bit
		('csigdata',		user_siginfo_t),
		('thread_status_size',	c_int),
		('numnote',		c_int)
		]


##################################
class fregs(Structure):
		_fields_ = [
		('cwd', c_uint),
		('swd', c_uint),
		('twd', c_uint),
		('fip', c_uint),
		('fcs', c_uint),
		('foo', c_uint),
		('fos', c_uint),
		('st_space', c_uint*20),
		]

class prpsinfo_X86_64(Structure):
	_fields_ = [
		('pr_state',	c_ubyte),
		('pr_sname',	c_byte),
		('pr_zomb',	c_ubyte),
		('pr_nice',	c_byte),
		('pr_flag',	c_ulong),
		('pr_uid',	c_uint),
		('pr_gid',	c_uint),
		('pr_pid',	c_int),
		('pr_ppid',	c_int),
		('pr_pgrp',	c_int),
		('pr_sid',	c_int),
		('pr_fname',	c_char*16),
		('pr_psargs',	c_char*80)
	]

class regs_X86_64(Structure):
	_fields_ = [
		('r15',		c_ulonglong),
		('r14',		c_ulonglong),
		('r13',		c_ulonglong),
		('r12',		c_ulonglong),
		('rbp',		c_ulonglong),
		('rbx',		c_ulonglong),
		('r11',		c_ulonglong),
		('r10',		c_ulonglong),
		('r9',		c_ulonglong),
		('r8',		c_ulonglong),
		('rax',		c_ulonglong),
		('rcx',		c_ulonglong),
		('rdx',		c_ulonglong),
		('rsi',		c_ulonglong),
		('rdi',		c_ulonglong),
		('orig_rax',	c_ulonglong),
		('rip',		c_ulonglong),
		('cs',		c_ulonglong),
		('eflags',	c_ulonglong),
		('rsp',		c_ulonglong),
		('ss',		c_ulonglong),
		('fs_base',	c_ulonglong),
		('gs_base',	c_ulonglong),
		('ds',		c_ulonglong),
		('es',		c_ulonglong),
		('fs',		c_ulonglong),
		('gs',		c_ulonglong),
	]

class fpregs_X86_64(Structure):
	_fields_ = [
		('cwd',		c_ushort),
		('swd',		c_ushort),
		('twd',		c_ushort),
		('fop',		c_ushort),
		('fip',		c_uint),
		('fcs',		c_uint),
		('foo',		c_uint),
		('fos',		c_uint),
		('mxcsr',	c_uint),
		('mxcsr_mask',	c_uint),
		('st_space',	c_uint*32),
		('xmm_space',	c_uint*64),
		('padding',	c_uint*24)
	]

class core_user_X86_64(Structure):
	_fields_ = [
		('regs',	regs_X86_64),
		('fpvalid',	c_ulong),
		('fpregs',	fpregs_X86_64),
		('tsize',	c_ulong),
		('dsize',	c_ulong),
		('ssize',	c_ulong),
		('start_code',	c_ulong),
		('start_stack', c_ulong),
		('signal',	c_ulong),
		('reserved',	c_ulong),
		('regs_ptr',	POINTER(regs_X86_64)),
		('fpregs_ptr',	POINTER(fpregs_X86_64)),
		('magic',	c_ulong),
		('comm',	c_char*32),
		('debugreg',	c_ulong),
		('error_code',	c_ulong),
		('fault_address', c_ulong)
	]

class elf_siginfo(Structure):
	_fields_ = [
		('si_signo',	c_int),
		('si_code',	c_int),
		('si_errno',	c_int)
	]

class elf_timeval(Structure):
	_fields_ = [
		('tv_sec',	c_long),
		('tv_usec',	c_long)
	]

class prstatus_x86_64(Structure):
	_fields_ = [
		('pr_info',	elf_siginfo),
		('pr_cursig',	c_ushort),
		('pr_sigpend',	c_ulong),
		('pr_sighold',	c_ulong),
		('pr_pid',	c_int),
		('pr_ppid',	c_int),
		('pr_pgrp',	c_int),
		('pr_sid',	c_int),
		('pr_utime',	elf_timeval),
		('pr_stime',	elf_timeval),
		('pr_cutime',	elf_timeval),
		('pr_cstime',	elf_timeval),
		('pr_reg',	regs_X86_64),
		('pr_fpvalid',	c_uint)
	]

class core_dump_desc:
	def __init__(self, ehdr, ELFCLASS, ELFDATA, phdr, nhdr,\
			auxv_t, prpsinfo, core_user, regs, fpregs, prstatus):
		self.ehdr	= ehdr
		self.ELFCLASS	= ELFCLASS
		self.ELFDATA	= ELFDATA
		self.phdr	= phdr
		self.nhdr	= nhdr
		self.auxv_t	= auxv_t
		self.prpsinfo	= prpsinfo
		self.core_user	= core_user
		self.regs	= regs
		self.fpregs	= fpregs
		self.prstatus	= prstatus

desc_by_arch = {
	'X86_64'	: core_dump_desc(
				elf.Elf64_Ehdr,
				elf.ELFCLASS64,
				elf.ELFDATA2LSB,
				elf.Elf64_Phdr,
				elf.Elf64_Nhdr,
				elf.Elf64_auxv_t,
				prpsinfo_X86_64,
				core_user_X86_64,
				regs_X86_64,
				fpregs_X86_64,
				prstatus_x86_64)
}

class core_dump:
	def parse_imgs(self, imgs_dir, pid):
		"""
		Open and load all needed images to generate core dump.
		"""
		self.pid	= pid
		self.imgs_dir	= imgs_dir
		# Try to obtain needed images
		# FIXME make one helper function for this zoo
		self.pstree	= self._open_and_load('pstree')
		self.creds	= self._open_and_load('creds-'+str(self.pid))[0]
		self.core	= self._open_and_load('core-'+str(self.pid))[0]
		self.mm		= self._open_and_load('mm-'+str(self.pid))[0]
		self.pagemap	= self._open_and_load('pagemap-'+str(self.pid))
		#FIXME maybe open in binary mode? Or just read everything?
		self.pages	= open(self.imgs_dir+'/pages-'+str(self.pagemap[0]['pages_id']) + '.img')

		self.elf		= elf_h.Elf64_Ehdr()
		self.info		= [] # XXX elf_note_info inside
		self.phdr4note		= elf_h.Elf64_Phdr()
		self.phdr4extnum	= elf_h.Elf64_Shdr()
		self._get_vdso()

		self.auxvs		= self._get_auxvs()

	def _open_and_load(self, base_name):
		"""
		Simple helper to open image, load it and extract entries.
		"""
		fname = self.imgs_dir + '/' + base_name + '.img'
		f = None
		img = None

		try:
			f = open(fname)
		except IOError as e:
			raise Exception("Can't open " + fname + ":" + e.strerror)

		try:
			img = images.load(f)
		except Exception as e:
			raise Exception("Can't load " + fname + ":" + a.message)

		f.close()
		return img['entries']

	def _get_prpsinfo(self):
		p = self.desc.prpsinfo()

		memset(addressof(p), 0, sizeof(p))
		#('pr_state',	c_ubyte),
		p.pr_state	= self.core['tc']['task_state']#FIXME Is it?
		#('pr_sname',	c_byte),
		p.pr_sname	= ord('R')
		#('pr_zomb',	c_ubyte), #FIXME WTF IS THIS ONE? IT IS NOT SET IN GOOGLE COREDUMPER
		#('pr_nice',	c_byte),
		p.pr_nice	= self.core['thread_core']['sched_nice']
		#('pr_flag',	c_ulong),
		p.pr_flag	= self.core['tc']['flags']
		#('pr_uid',	c_uint),
		p.pr_uid	= self.creds['euid']
		#('pr_gid',	c_uint),
		p.pr_gid	= self.creds['egid']
		#('pr_pid',	c_int),
		p.pr_pid	= self.pid
		#('pr_ppid',	c_int),
		p.pr_ppid	= filter(lambda x: x['pid'] == self.pid, self.pstree)[0]['ppid']
		#('pr_pgrp',	c_int),
		p.pr_pgrp	= filter(lambda x: x['pid'] == self.pid, self.pstree)[0]['pgid']
		#('pr_sid',	c_int),
		p.pr_sid	= filter(lambda x: x['pid'] == self.pid, self.pstree)[0]['sid']
		#('pr_fname',	c_char*16),
		p.pr_fname	= self.core['tc']['comm']#FIXME should we use full path here? look into mm for env or smth!
		#('pr_psargs',	c_char*80)
		p.pr_psargs	= "" #FIXME Looks like we don't have a special field for this one, but maybe it could be extracted from memory? -- YES!!! Look into mm for mm_arg and so on.

		return p

	def _get_regs(self, pid=None):
		r = self.desc.regs()
		if pid == None or pid == self.pid:
			core_regs = self.core['thread_info']['gpregs']
		else:
			core_regs = self._open_and_load('core-'+str(pid))[0]['thread_info']['gregs']

		memset(addressof(r), 0, sizeof(r))
		#('r15',		c_ulonglong),
		r.r15		= core_regs['r15']
		#('r14',		c_ulonglong),
		r.r14		= core_regs['r14']
		#('r13',		c_ulonglong),
		r.r13		= core_regs['r13']
		#('r12',		c_ulonglong),
		r.r12		= core_regs['r12']
		#('rbp',		c_ulonglong),
		r.rbp		= core_regs['bp']
		#('rbx',		c_ulonglong),
		r.rbx		= core_regs['bx']
		#('r11',		c_ulonglong),
		r.r11		= core_regs['r11']
		#('r10',		c_ulonglong),
		r.r10		= core_regs['r10']
		#('r9',		c_ulonglong),
		r.r9		= core_regs['r9']
		#('r8',		c_ulonglong),
		r.r8		= core_regs['r8']
		#('rax',		c_ulonglong),
		r.rax		= core_regs['ax']
		#('rcx',		c_ulonglong),
		r.rcx		= core_regs['cx']
		#('rdx',		c_ulonglong),
		r.rdx		= core_regs['dx']
		#('rsi',		c_ulonglong),
		r.rsi		= core_regs['si']
		#('rdi',		c_ulonglong),
		r.rdi		= core_regs['di']
		#('orig_rax',	c_ulonglong),
		r.orig_rax	= core_regs['orig_ax']
		#('rip',		c_ulonglong),
		r.rip		= core_regs['ip']
		#('cs',		c_ulonglong),
		r.cs		= core_regs['cs']
		#('eflags',	c_ulonglong),
		r.eflags	= core_regs['flags']
		#('rsp',		c_ulonglong),
		r.rsp		= core_regs['sp']
		#('ss',		c_ulonglong),
		r.ss		= core_regs['ss']
		#('fs_base',	c_ulonglong),
		r.fs_base	= core_regs['fs_base']
		#('gs_base',	c_ulonglong),
		r.gs_base	= core_regs['gs_base']
		#('ds',		c_ulonglong),
		r.ds		= core_regs['ds']
		#('es',		c_ulonglong),
		r.es		= core_regs['es']
		#('fs',		c_ulonglong),
		r.fs		= core_regs['fs']
		#('gs',		c_ulonglong),
		r.gs		= core_regs['gs']

		return r

	def _get_fpregs(self, pid=None):
		fp = self.desc.fpregs()

		if pid == self.pid or pid == None:
			core_regs = self.core['thread_info']['fpregs']
		else:
			core_regs = self._open_and_load('core-'+str(pid))[0]['thread_info']['fpregs']

		memset(addressof(fp), 0, sizeof(fp))
		#('cwd',		c_ushort),
		fp.cwd			= core_regs['cwd']
		#('swd',		c_ushort),
		fp.swd			= core_regs['swd']
		#('twd',		c_ushort),
		fp.twd			= core_regs['twd']
		#('fop',		c_ushort),
		fp.fop			= core_regs['fop']
		#('fip',		c_uint), FIXME no such thing in our images
		#('fcs',		c_uint), FIXME no such thing in our images
		#('foo',		c_uint), FIXME no such thing in our images
		#('fos',		c_uint), FIXME no such thing in out images
		#('mxcsr',	c_uint),
		fp.mxcsr		= core_regs['mxcsr']
		#('mxcsr_mask',	c_uint),
		fp.mxcsr_mask		= core_regs['mxcsr_mask']
		#('st_space',	c_uint*32),
		fp.st_space		= (c_uint * len(core_regs['st_space']))(*core_regs['st_space'])
		#('xmm_space',	c_uint*64),
		fp.xmm_space		= (c_uint * len(core_regs['xmm_space']))(*core_regs['xmm_space'])
		#('padding',	c_uint*24)# not used

		return fp

	def _get_core_user(self):
		c = self.desc.core_user()

		memset(addressof(c), 0, sizeof(c))
		#('regs',	regs),
		c.regs		= self._get_regs()
		#('fpvalid',	c_ulong),
		c.fpvalid	= 1
		#('fpregs',	fpregs),
		c.fpregs	= self._get_fpregs()
		#('tsize',	c_ulong), #FIXME all *size should be in pages!!!!!!!!!
		tsize_bytes	= self.mm['mm_end_code'] - self.mm['mm_start_code']
		c.tsize		= tsize_bytes/4096 + (1 if tsize_bytes % 4096 else 0)
		#('dsize',	c_ulong),
		dsize_bytes	= self.mm['mm_end_data'] - self.mm['mm_start_data']
		c.dsize		= dsize_bytes/4096 + (1 if tsize_bytes % 4096 else 0)
		#('ssize',	c_ulong), #FIXME HOW TO FIND STACK SIZE??????
		# Find stack vma. FIXME make sure that it is actually stack and not just
		# stack-like thing.
		MAP_GROWSDOWN = 0x00100 	
		for vma in self.mm['vmas']:
			if vma['flags'] & MAP_GROWSDOWN:
				ssize_bytes = vma['end'] - vma['start']
				break

		c.ssize	= ssize_bytes/4096 + (1 if ssize_bytes % 4096 else 0)
		#('start_code',	c_ulong),
		c.start_code	= self.mm['mm_start_code']
		#('start_stack', c_ulong),
		c.start_stack	= self.mm['mm_start_stack']
		#('signal',	c_ulong),# just 0
		#('reserved',	c_ulong),# not used
		#('regs_ptr',	POINTER(regs)),# not used
		#('fpregs_ptr',	POINTER(fpregs)),# not used
		#('magic',	c_ulong),# not used
		#('comm',	c_char*32),
		c.comm		= self.core['tc']['comm']
		#('debugreg',	c_ulong),# not used
		#('error_code',	c_ulong),# just 0
		#('fault_address', c_ulong)# just 0
		return c

	def _get_prstatus(self, pid):
		p = self.desc.prstatus()

		memset(addressof(p), 0, sizeof(p))

		# FIXME FILL WITH INFO!!!
		#('pr_info',	elf_siginfo),
		#FIXME fill it with info
		esi = elf_siginfo()
		memset(addressof(esi), 0, sizeof(esi))
		p.pr_info	= esi
		#('pr_cursig',	c_ushort),
		#FIXME fill
		p.pr_cursig	= 0
		#('pr_sigpend',	c_ulong),
		#('pr_sighold',	c_ulong),
		#('pr_pid',	c_int),
		p.pid		= pid
		#('pr_ppid',	c_int),
		p.pr_ppid	= filter(lambda x: x['pid'] == pid, self.pstree)[0]['ppid']
		#('pr_pgrp',	c_int),
		p.pr_pgrp	= filter(lambda x: x['pid'] == pid, self.pstree)[0]['pgid']
		#('pr_sid',	c_int),
		p.pr_sid	= filter(lambda x: x['pid'] == pid, self.pstree)[0]['sid']
		#('pr_utime',	elf_timeval),
		#('pr_stime',	elf_timeval),
		#('pr_cutime',	elf_timeval),
		#('pr_cstime',	elf_timeval),
		#('pr_reg',	regs),
		p.pr_reg	= self._get_regs(pid)
		#('pr_fpvalid',	c_uint)

		return p

	def _write_thread_regs(self, buf, pid):
		nhdr = self.desc.nhdr()
		memset(addressof(nhdr), 0, sizeof(nhdr))
		nhdr.n_namesz	= 5
		nhdr.n_descsz	= sizeof(self.desc.prstatus())
		nhdr.n_type	= elf.NT_PRSTATUS

		buf.write(nhdr)
		buf.write("CORE\0\0\0\0")
		buf.write(self._get_prstatus(pid))

		nhdr.n_descsz	= sizeof(self.desc.fpregs())
		nhdr.n_type	= elf.NT_FPREGSET

		buf.write(nhdr)
		buf.write("CORE\0\0\0\0")
		buf.write(self._get_fpregs())

	def _get_mem_chunk(self, vaddr, size):
		chunk = io.BytesIO()
		ofs = 0
		# Skip first entry, as it is pagemap_head.
		for m in self.pagemap[1:]:
			if m['vaddr'] >= vaddr and\
			   m['vaddr'] + 4096*m['nr_pages'] <= vaddr + size:
				ofs += vaddr - m['vaddr']
				self.pages.seek(ofs)
				chunk.write(self.pages.read(size))
				# Don't forget to rewind
				self.pages.seek(0)
				break

			ofs += 4096*m['nr_pages']

		chunk.seek(0)
		return chunk

	def _get_auxvs(self):
		auxvs = []

		#FIXME add helper for auxv
		for i in range(len(self.mm['mm_saved_auxv'])/2):
			auxv = self.desc.auxv_t()
			auxv.a_type	= self.mm['mm_saved_auxv'][i]
			auxv.a_un.a_val	= self.mm['mm_saved_auxv'][i+1]

			auxvs.append(auxv)

		return auxvs


	def write(self, f):
		buf = io.BytesIO()
		num_mappings = len(self.mm['vmas'])
		num_threads = len(filter(lambda x: x['pid'] == self.pid, self.pstree)[0]['threads'])

		num_extra_headers = len(self.vdso.phdrs)
		# FIXME no vdso in real core dump
		#num_extra_headers = 0

		# EHDR
		ehdr = self.desc.ehdr()
		memset(addressof(ehdr), 0, sizeof(ehdr))
		ehdr.e_ident[elf.EI_MAG0]	= elf.ELFMAG0
		ehdr.e_ident[elf.EI_MAG1]	= ord(elf.ELFMAG1)
		ehdr.e_ident[elf.EI_MAG2]	= ord(elf.ELFMAG2)
		ehdr.e_ident[elf.EI_MAG3]	= ord(elf.ELFMAG3)
		ehdr.e_ident[elf.EI_CLASS]	= self.desc.ELFCLASS
		ehdr.e_ident[elf.EI_DATA]	= self.desc.ELFDATA
		ehdr.e_ident[elf.EI_VERSION]	= elf.EV_CURRENT

		ehdr.e_type		= elf.ET_CORE
		ehdr.e_machine		= elf.EM_X86_64
		ehdr.e_version		= elf.EV_CURRENT
		ehdr.e_phoff		= sizeof(elf.Elf64_Ehdr())
		ehdr.e_ehsize		= sizeof(elf.Elf64_Ehdr())
		ehdr.e_phentsize	= sizeof(elf.Elf64_Phdr())
		ehdr.e_phnum		= num_mappings + num_extra_headers + 1
		ehdr.e_shentsize	= sizeof(elf.Elf64_Shdr())

		buf.write(ehdr)

		# PHDRs starting with the PT_NOTE
		phdr = self.desc.phdr()

		offset = sizeof(self.desc.ehdr())
		offset += (num_mappings + num_extra_headers + 1)*sizeof(phdr)

		filesz = sizeof(self.desc.nhdr()) + 8 + sizeof(self.desc.prpsinfo())
		filesz += sizeof(self.desc.nhdr()) + 8 + sizeof(self.desc.core_user())
		filesz += num_threads*(sizeof(self.desc.nhdr()) + 8 +\
				sizeof(self.desc.prstatus())+\
				sizeof(self.desc.nhdr()) + 8 + sizeof(self.desc.fpregs()))

		if len(self.auxvs) != 0:
			filesz += 8 + sizeof(self.desc.nhdr()) + len(self.auxvs)*sizeof(self.desc.auxv_t())

		# Write PT_NOTE
		memset(addressof(phdr), 0, sizeof(phdr))
		phdr.p_type	= elf.PT_NOTE
		phdr.p_offset	= offset
		phdr.p_filesz	= filesz

		buf.write(phdr)

		# Write phdrs for each mem segment
		phdr.p_type	= elf.PT_LOAD
		phdr.p_align	= 4096#FIXME maybe use sysconf?
		phdr.p_paddr	= 0
		note_align	= phdr.p_align - ((offset + filesz) % phdr.p_align)

		if note_align == phdr.p_align:
			note_align = 0

		offset		+= note_align

		for vma in self.mm['vmas']:
			offset	+= filesz
			filesz	= vma['end'] - vma['start']
			phdr.p_offset	= offset
			phdr.p_vaddr	= vma['start']
			phdr.p_memsz	= filesz

			filesz	= vma['end'] - vma['start']
			phdr.p_filesz	= filesz
			phdr.p_flags	= vma['prot']

			buf.write(phdr)

		# Write vdso phdrs FIXME no vdso phdrs in real core dump!!
		for p in self.vdso.phdrs:
			offset += filesz
			filesz = p.p_filesz
			p.p_offset = offset
			p.p_paddr = 0
			buf.write(p)

		# Write the note section
		nhdr = self.desc.nhdr()
		memset(addressof(nhdr), 0, sizeof(nhdr))
		nhdr.n_namesz	= 5
		nhdr.n_descsz	= sizeof(self.desc.prpsinfo())
		nhdr.n_type	= elf.NT_PRPSINFO
		buf.write(nhdr)
		buf.write("CORE\0\0\0\0")
		buf.write(self._get_prpsinfo())

		nhdr.n_descsz	= sizeof(self.desc.core_user()) # FIXME no such thing in real core dump
		nhdr.n_type	= elf.NT_PRXREG
		buf.write(nhdr)
		buf.write("CORE\0\0\0\0")
		buf.write(self._get_core_user())

		# AUXV
		nhdr.n_descsz	= len(self.auxvs) * sizeof(self.desc.auxv_t())
		nhdr.n_type	= elf.NT_AUXV
		buf.write(nhdr)
		buf.write("CORE\0\0\0\0")

		for a in self.auxvs:
			buf.write(a)

		# Thread regs
		# Main thread first
		self._write_thread_regs(buf, self.pid)

		for t in filter(lambda x: x != self.pid, filter(lambda x: x['pid'] == self.pid, self.pstree)[0]['threads']):
			self._write_thread_regs(buf, t)

		# User provided notes should be here, but we have none

		# Align
		if note_align:
			scratch = (c_char * note_align)()
			memset(scratch, 0, sizeof(scratch))
			buf.write(scratch)

		# And write all memory segments
		buf.write(self.pages.read())
		# Don't forget to rewind
		self.pages.seek(0)

		# Write vdso contents FIXME no vdso in real core dump
		for c in self.vdso.conts:
			buf.write(c.read())

		# Finally dump buf into file
		buf.seek(0)
		f.write(buf.read())

################################################################################
	def _get_vdso(self):
		# Find vdso ehdr
		auxv = filter(lambda x: x.a_type == elf.AT_SYSINFO_EHDR, self.auxvs)[0]
		addr = auxv.a_un.a_val

		ehdr = elf_h.Elf64_Ehdr()
		self._get_mem_chunk(addr, sizeof(ehdr)).readinto(ehdr)

		# Skip offset
		addr += ehdr.e_phoff

		# Read all phdrs, but read contents later
		phdrs = []
		conts = []
		for i in range(ehdr.e_phnum):
			phdr = elf_h.Elf64_Ehdr()
			self._get_mem_chunk(addr, sizeof(phdr)).readinto(phdr)
			addr += sizeof(phdr)

			#cont = self._get_mem_chunk(phdr.p_vaddr, phdr.p_filesz)
			
			phdrs.append(phdr)
			#conts.append(cont)


		class vdso_class:
			ehdr	= None
			phdrs	= []

		self.vdso	= vdso_class()
		self.vdso.ehdr	= ehdr
		self.vdso.phdrs	= phdrs

	def _fill_note_info(self):
		"""
		Collect all the non-memory information about the process for the
		notes. This also sets up the file header.
		"""
		#FIXME
		pass

	def _fill_note_phdr(self, sz, offset):
		#FIXME
		pass

	def _roundup(self):
		#FIXME
		pass

	def _vma_dump_size(vma):
		#FIXME should be "if vma->vm_flags & VM_DONTDUMP return 0"
		# but i'm not sure how to implement

		#FIXME Need to investigate by looking at vma_dump_size from fs/binfmt_elf.c
		# For example, it says that we should dump only 1 page of DSO(NOT Vdso!) or
		# executable mapping.

		#FIXME RIGHT FUCKING NOW!!!!
		# Ask Pavel how dump of a file mapping is done.

		return vma['end'] - vma['start']

	def _elf_core_extra_phdrs(self):
		#FIXME CONSIDER case when there is no vDSO. rework get_vdso too
		return self.vsyscall_ehdr.e_phnum

	def _get_note_info_size(self):
		return self.info.size

	def _elf_core_extra_data_size(self):
		for phdr in self.vdso.phdrs:
			if phdr.p_type == elf_h.PT_LOAD:
				return phdr.p_filesz

	def _dump_emit(self, f, obj):
		"""
		Write obj to f. Even though we don't actualy have any restrictions
		on core dump size, we keep function names to be similar to thouse
		found in kernel.
		"""
		#FIXME
		pass

	def write(self, f):
		segs =	len(self.mm['vmas'])
		segs +=	self._elf_core_extra_phdrs()

		#XXX here should be gate_vma handling, but we don't support 32bit
		#tasks, which use linux-gate*.so, so we can skip it for now.

		# For notes section
		segs += 1

		# If segs > PN_XNUM(0xffff), then e_phnum overflows. To avoid
		# this, kernel supports extended numbering. Have a look at
		# include/linux/elf.h for further information. */
		e_phnum = PN_XNUM if segs > PN_XNUM else segs

		self._fill_note_info()

		offset = 0
		offset += sizeof(self.elf)			# Elf header
		offset += segs * sizeof(elf_h.Elf64_Phdr())	# Program headers

		# Write notes phdr entry
		sz = self._get_note_info_size()
		self._fill_note_phdr(sz, offset)
		offset += sz

		ELF_EXEC_PAGESIZE = 4096
		offset = self._roundup(offset, ELF_EXEC_PAGESIZE)
		dataoff = offset

		vma_data_size = 0
		vma_filesz = []
		for vma in self.mm['vmas']:
			dump_size	= self._vma_dump_size(vma)
			vma_filesz.append(dump_size)
			vma_data_size	+= dump_size

		offset += vma_data_size
		offset += self._elf_core_extra_data_size()
		e_shoff = offset

		if e_phnum == PN_XNUM:
			self._fill_extnum_info(e_shoff, segs)

		offset = dataoff

		self._dump_emit(f, self.elf)
		self._dump_emit(f, self.phdr4note)

		# Write program headers for segments dump
		for vma in self.mm['vmas']:
			phdr = elf_h.Elf64_Phdr()

			phdr.p_type	= elf_h.PT_LOAD:
			phdr.p_offset	= offset
			phdr.p_vaddr	= vma['start']
			phdr.p_paddr	= 0
			phdr.p_filesz	= 
