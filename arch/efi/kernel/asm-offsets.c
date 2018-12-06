/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright 2018 Peter Jones <pjones@redhat.com>
 */

#include <linux/stddef.h>
#include <linux/sched.h>
#include <linux/elf.h>
#include <linux/crypto.h>
#include <linux/kbuild.h>
#include <asm/mman.h>

#if defined(CONFIG_X86_32) || defined(CONFIG_X86_64)
# include "../../x86/kernel/asm-offsets.c"
#else
void common(void) {
	BLANK();
}
#endif
