# SPDX-License-Identifier: GPL-2.0
#
# Copyright 2018 Peter Jones <pjones@redhat.com>

# Avoid instrumenting ARCH=efi kernel code so we don't access the
# instrumentation buffer before it's initialized.
KCOV_INSTRUMENT                := n

clean-files :=

obj-y = bs.o
