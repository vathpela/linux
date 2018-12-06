# SPDX-License-Identifier: GPL-2.0
#
# Copyright 2018 Peter Jones <pjones@redhat.com>

ARCH_DIR := arch/efi

filechk_gen_header = $<

HEADER_ARCH 	:= $(SUBARCH)

ifneq ($(filter $(SUBARCH),x86 x86_64 i386),)
	HEADER_ARCH := x86
endif
override SRCARCH=$(HEADER_ARCH)

HOST_DIR := arch/$(HEADER_ARCH)

core-y += $(ARCH_DIR)/kernel/ \
	  $(HOST_DIR)/efi/

include $(HOST_DIR)/Makefile

# select defconfig based on actual architecture
ifeq ($(SUBARCH),x86)
	ifeq ($(shell uname -m),x86_64)
		KBUILD_DEFCONFIG := x86_64_defconfig
	else
		KBUILD_DEFCONFIG := i386_defconfig
	endif
else
	KBUILD_DEFCONFIG := $(SUBARCH)_defconfig
endif

SHARED_HEADERS	:= $(ARCH_DIR)/include/shared
ARCH_INCLUDE	:= -I$(srctree)/$(SHARED_HEADERS)
ARCH_INCLUDE	+= -I$(srctree)/$(HOST_DIR)/efi/shared
LINUXINCLUDE	+= -I$(srctree)/arch/$(HEADER_ARCH)/include \
		   -I$(srctree)/arch/$(HEADER_ARCH)/include/generated \

KBUILD_CPPFLAGS	+= -I$(srctree)/$(HOST_DIR)/efi \
		   -I$(srctree)/$(HOST_DIR)/include \
		   -I$(srctree)/$(HOST_DIR)/include/uapi \
		   -I$(objtree)/$(HOST_DIR)/include/generated \
		   -I$(objtree)/$(HOST_DIR)/include/generated/uapi

KERNEL_DEFINES	= $(strip $(ARCH_KERNEL_DEFINES))

# override asm-generic := -f $(srctree)/$(HOST_DIR)/efi/Makefile.asm-generic obj

KBUILD_CFLAGS	+= $(CFLAGS) $(CFLAGS-y) \
		   $(KERNEL_DEFINES) -D__arch_efi__ \
		   $(ARCH_INCLUDE) $(MODE_INCLUDE)

KBUILD_AFLAGS	+= $(ARCH_INCLUDE)

MRPROPER_FILES += arch/$(SUBARCH)/include/generated

efi-prepare-objtool:
	$(MAKE) ARCH=$(SUBARCH) -f$(srctree)/Makefile tools/objtool

prepare-objtool : efi-prepare-objtool

override KBUILD_LDS	= arch/$(HEADER_ARCH)/kernel/vmlinux.lds

efi_archheaders:
	$(Q)$(MAKE) -f $(srctree)/Makefile ARCH=$(HEADER_ARCH) asm-generic archheaders

archheaders: efi_archheaders

export HEADER_ARCH SUBARCH
