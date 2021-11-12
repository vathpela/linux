# SPDX-License-Identifier: GPL-2.0
#
# Copyright 2018 Peter Jones <pjones@redhat.com>

# (info arch/efi/Makefile:5 ARCH:$(ARCH) SRCARCH:$(SRCARCH) SUBARCH:$(SUBARCH) ARCH_EFI_MAKEFILE_ONCE:$(ARCH_EFI_MAKEFILE_ONCE) KBUILD_CFLAGS:"$(KBUILD_CFLAGS)")
ifeq ($(ARCH_EFI_MAKEFILE_ONCE),)
ARCH_EFI_MAKEFILE_ONCE := y
export ARCH_EFI_MAKEFILE_ONCE

ARCH_DIR := arch/efi
ifeq ($(ARCH),efi)
ifneq ($(SRCARCH),efi)
ifeq ($(SUBARCH),)
SUBARCH := $(SRCARCH)
endif
endif
endif

filechk_gen_header = $<

HEADER_ARCH := $(SUBARCH)

ifneq ($(filter $(SUBARCH),x86 x86_64 i386),)
        HEADER_ARCH := x86
endif
override SRCARCH := $(HEADER_ARCH)

HOST_DIR := arch/$(HEADER_ARCH)

obj-y += kernel/
obj-y += drivers/

# for cleaning
subdir- += include/

include $(srctree)/$(HOST_DIR)/Makefile

# select defconfig based on actual architecture
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
ARCH_INCLUDE	:= -I$(srctree)/$(SHARED_HEADERS) \
		   -I$(srctree)/$(HOST_DIR)/efi/shared
LINUXINCLUDE	+= -I$(srctree)/arch/$(HEADER_ARCH)/include \
		   -I$(srctree)/arch/$(HEADER_ARCH)/include/generated \
		   -I$(srctree)/arch/$(ARCH)/include \
		   -I$(srctree)/arch/$(ARCH)/include/generated

KBUILD_CPPFLAGS	+= -I$(srctree)/$(HOST_DIR)/efi \
		   -I$(srctree)/$(HOST_DIR)/include \
		   -I$(srctree)/$(HOST_DIR)/include/uapi \
		   -I$(objtree)/$(HOST_DIR)/include/generated \
		   -I$(objtree)/$(HOST_DIR)/include/generated/uapi
$(info arch/efi/Makefile:62 SHARED_HEADERS:"$(SHARED_HEADERS)" ARCH_INCLUDE:"$(ARCH_INCLUDE)" LINUXINCLUDE:"$(LINUXINCLUDE)" KBUILD_CPPFLAGS:"$(KBUILD_CPPFLAGS)" KBUILD_CFLAGS:"$(KBUILD_CFLAGS)")

# (info arch/efi/Makefile:66 ARCH_KERNEL_DEFINES:$(ARCH_KERNEL_DEFINES))
# KERNEL_DEFINES	= $(strip $(ARCH_KERNEL_DEFINES))

# override asm-generic := -f $(srctree)/$(HOST_DIR)/efi/Makefile.asm-generic obj

# KBUILD_CFLAGS += $(CFLAGS) $(CFLAGS-y)
# subdir-ccflags-y += -D__arch_efi__ $(ARCH_INCLUDE)
# $(MODE_INCLUDE)
# override KBUILD_CFLAGS := $(KBUILD_CFLAGS)
# KBUILD_AFLAGS	+= $(ARCH_INCLUDE)

MRPROPER_FILES += arch/$(SUBARCH)/include/generated

efi-prepare-objtool:
	@echo one
	$(MAKE) ARCH=$(SUBARCH) -f$(srctree)/Makefile tools/objtool
	@echo two

prepare-objtool : efi-prepare-objtool

override KBUILD_LDS	= arch/$(HEADER_ARCH)/kernel/vmlinux.lds

export HEADER_ARCH SUBARCH HOST_DIR ARCH_INCLUDE LINUXINCLUDE
endif
# (info arch/efi/Makefile:88 ARCH_KERNEL_DEFINES:$(ARCH_KERNEL_DEFINES) KBUILD_CFLAGS:"$(KBUILD_CFLAGS)")
