#include <Python.h>

#include <elf.h>

/* Only x64 macros for now */
#define Ehdr Elf64_Ehdr
#define Phdr Elf64_Phdr
#define ELFCLASS ELFCLASS64

#if defined(__x86_64__)
	#define ELF_MACHINE EM_X86_64
#elif defined(__arm__)
	#define ELF_MACHINE EM_ARM
#elif defined(__aarch64__)
	#define ELF_MACHINE EM_AARCH64
#endif

static unsigned char get_ei_data()
{
	/* Determine the byte-order */
	int probe = 1;
	if (!*(char *)&probe)
		return ELFDATA2MSB;
	else
		return ELFDATA2LSB;
}
static PyObject *core_dump(PyObject *self,
			   PyObject *core,
			   PyObject *pagemap,
			   PyObject *pages)
{
	Ehdr ehdr;

	memset(&ehdr, 0, sizeof(Ehdr));
	ehdr.e_indent[EI_MAG0]		= ELFMAG0;
	ehdr.e_indent[EI_MAG1]		= ELFMAG1;
	ehdr.e_indent[EI_MAG2]		= ELFMAG2;
	ehdr.e_indent[EI_MAG3]		= ELFMAG3;
	ehdr.e_indent[EI_CLASS]		= ELF_CLASS;
	ehdr.e_indent[EI_DATA]		= get_ei_data();
	ehdr.e_indent[EI_VERSION]	= EV_CURRENT;

	ehdr.e_type			= ET_CORE;
	ehdr.e_machine			= ELF_MACHINE;
	ehdr.e_version			= EV_CURRENT;
	ehdr.e_phoff			= sizeof(Ehdr);
	ehdr.e_ehsize			= sizeof(Ehdr);
	ehdr.e_phentsize		= sizeof(Phdr);
	ehdr.e_phnum			= /*FIXME investigate!*/
}
