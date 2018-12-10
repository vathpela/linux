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
#include <linux/completion.h>
#include <asm/efi.h>

struct bs_ctx {
	struct task_struct *thread;
	struct completion bs_context_entry;
	struct completion bs_context_exit;

	efi_event_t event;
	efi_system_table_t *systab;
};

static struct bs_ctx bs_ctx;

void efi_bs_ingress(void)
{
	set_current_state(TASK_UNINTERRUPTIBLE);
	preempt_disable();

	/* TODO: disable interrupts */
	/* Optional TODO: swap page tables */
	/* TODO: swap interrupt handlers */

	complete(&bs_ctx.bs_context_entry);
	reinit_completion(&bs_ctx.bs_context_exit);
}

void efi_bs_egress(void)
{
	preempt_enable();
	set_current_state(TASK_INTERRUPTIBLE);

	/* TODO: swap interrupt handlers */
	/* Optional TODO: swap page tables */
	/* TODO: enable interrupts */

	reinit_completion(&bs_ctx.bs_context_entry);
	complete(&bs_ctx.bs_context_exit);
}

int bs_set_timer(u32 ms)
{
	efi_status_t status;

	/*
	 * set_timer()'s units are 100ns intervals
	 */
	u64 hns = (u64)ms * 10000ULL;

	status = efi_call_early(set_timer, bs_ctx.event, EfiTimerRelative,hns);

	return efi_status_to_err(status);
}

void bs_handle_timer(efi_event_t event, void *context)
{
	efi_bs_egress();
	/* TODO: schedule bs_thread */
}

static int bs_thread(void *data)
{
	efi_status_t status;

	/*
	 * We create this as TPL_APPLICATION so that it *doesn't* interrupt any
	 * actual EFI work being done.
	 */
	status = efi_call_early(create_event, EFI_EVT_TIMER,
				EFI_TPL_APPLICATION, bs_handle_timer,
				(void *)&bs_ctx, &bs_ctx.event);
	if (status != EFI_SUCCESS)
		return efi_status_to_err(status);

	while (1) {
		if (unlikely(kthread_should_stop())) {
			set_current_state(TASK_RUNNING);
			break;
		}

		efi_bs_ingress();
		/*
		 * TODO: make this number dynamic based on the next thing we
		 * have otherise scheduled in linux.
		 */
		bs_set_timer(1000);
		wait_for_completion(&bs_ctx.bs_context_exit);
	}

	return 0;
}

int __init efi_bs_init(efi_system_table_t *systab)
{
	int rc = 0;

	init_completion(&bs_ctx.bs_context_entry);
	init_completion(&bs_ctx.bs_context_exit);

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

	wait_for_completion(&bs_ctx.bs_context_exit);

	return rc;
}

/* vim: set ts=8 sw=8 noet tw=80 : */
