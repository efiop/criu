CFLAGS += -iquote pie/piegen

obj-y += main.o
ifneq ($(filter ia32 x86, $(ARCH)),)
obj-y += elf-x86-32.o
obj-y += elf-x86-64.o
endif
ifeq ($(SRCARCH),ppc64)
obj-y += elf-ppc64.o
endif

cleanup-y += $(obj)/piegen
cleanup-y += $(obj)/*.o

ifneq ($(MAKECMDGOALS),clean)
ifneq ($(MAKECMDGOALS),mrproper)
incdeps := y
endif
endif
