# SPDX-License-Identifier: GPL-2.0
# (info arch/efi/kernel/Makefile:2 got here)

# Avoid instrumenting ARCH=efi kernel code so we don't access the
# instrumentation buffer before it's initialized.
KCOV_INSTRUMENT                := n

CPPFLAGS_vmlinux.lds := -DSTART=$(LDS_START)		\
                        -DELF_ARCH=$(LDS_ELF_ARCH)	\
                        -DELF_FORMAT=$(LDS_ELF_FORMAT)	\
			$(LDS_EXTRA)
extra-y := vmlinux.lds

obj-y += bs.o

clean-files :=
