# SPDX-License-Identifier: GPL-2.0
#
# Copyright 2018 Peter Jones <pjones@redhat.com>

ARCH_DIR := arch/efi
$(info arch/efi/Makefile:6 ARCH_DIR:$(ARCH_DIR))

filechk_gen_header = $<

HEADER_ARCH := $(SUBARCH)

ifneq ($(filter $(SUBARCH),x86 x86_64 i386),)
        HEADER_ARCH := x86
endif
override SRCARCH := $(HEADER_ARCH)

HOST_DIR := arch/$(HEADER_ARCH)

core-y += $(ARCH_DIR)/kernel/ \
	  $(ARCH_DIR)/drivers/ \
	  $(HOST_DIR)/efi/

include $(HOST_DIR)/Makefile

# select defconfig based on actual architecture
$(info arch/efi/Makefile:26 ARCH:$(ARCH) SRCARCH:$(SRCARCH) SUBARCH:$(SUBARCH))

ifeq ($(SUBARCH),x86)
        ifeq ($(shell uname -m),x86_64)
                KBUILD_DEFCONFIG := x86_64_efi_defconfig
        else
                KBUILD_DEFCONFIG := i386_efi_defconfig
        endif
else
        KBUILD_DEFCONFIG := $(SUBARCH)_efi_defconfig
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

$(info arch/efi/Makefile:50 ARCH_KERNEL_DEFINES:$(ARCH_KERNEL_DEFINES))
KERNEL_DEFINES	= $(strip $(ARCH_KERNEL_DEFINES))

# override asm-generic := -f $(srctree)/$(HOST_DIR)/efi/Makefile.asm-generic obj

KBUILD_CFLAGS	+= $(CFLAGS) $(CFLAGS-y) \
		   -D__arch_efi__ \
		   $(ARCH_INCLUDE) $(MODE_INCLUDE)
override KBUILD_CFLAGS := $(KBUILD_CFLAGS)

KBUILD_AFLAGS	+= $(ARCH_INCLUDE)

MRPROPER_FILES += arch/$(SUBARCH)/include/generated

efi-prepare-objtool:
	$(MAKE) ARCH=$(SUBARCH) -f$(srctree)/Makefile tools/objtool

prepare-objtool : efi-prepare-objtool

override KBUILD_LDS	= arch/$(HEADER_ARCH)/kernel/vmlinux.lds

export HEADER_ARCH SUBARCH HOST_DIR ARCH_INCLUDE LINUXINCLUDE
