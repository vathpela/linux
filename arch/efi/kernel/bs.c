/* SPDX-License-Identifier: GPL-2.0 */
/*
 * bs.c - a thread in which we run the EFI Boot Services and similar code
 *
 * Copyright 2018 Peter Jones <pjones@redhat.com>
 */

#include <linux/module.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/kthread.h>
#include <linux/efi.h>

struct bs_ctx {
	struct task_struct *thread;
	efi_system_table_t *systab;
};

static int bs_thread(void *data)
{
	//struct bs_ctx *ctx = data;

	while (1) {
		if (unlikely(kthread_should_stop())) {
			set_current_state(TASK_RUNNING);
			break;
		}

		set_current_state(TASK_INTERRUPTIBLE);
	}

	return 0;
}

static struct bs_ctx bs_ctx;

int __init efi_bs_init(efi_system_table_t *systab)
{
	int rc = 0;

	bs_ctx.systab = systab;
	bs_ctx.thread = kthread_create(bs_thread, &bs_ctx,
                                       "efi_boot_services");
	if (IS_ERR(bs_ctx.thread)) {
		rc = PTR_ERR(bs_ctx.thread);
		bs_ctx.thread = NULL;
		efi_printk(systab,
			   "Could not start EFI Boot Services thread\n");
		return rc;
	}
	wake_up_process(bs_ctx.thread);

	return rc;
}

/* vim: set ts=8 sw=8 noet tw=80 : */
