// SPDX-License-Identifier: GPL-2.0
/*
 * Information about EFI variable storage.
 *
 * Copyright 2019 Peter Jones <pjones@redhat.com>
 *
 */
#include <linux/efi.h>
#include <asm/efi.h>

#include "efistub.h"

void efi_save_varinfo(efi_system_table_t *sys_table)
{
	efi_status_t status;
	unsigned long size;
	unsigned int i;
	efi_guid_t varinfo_table_guid = LINUX_EFI_VARIABLE_INFO_TABLE_GUID;
	struct efi_varinfo_table *bs_table;
	unsigned long bs_addr = 0;

	size = round_up(sizeof(*bs_table), EFI_PAGE_SIZE);

	status = efi_low_alloc_above(size, EFI_PAGE_SIZE, &bs_addr, EFI_PAGE_SIZE);
	if (status != EFI_SUCCESS) {
		efi_err("Failed to allocate variable info config table!\n");
		return;
	}
	bs_table = (struct efi_varinfo_table *)bs_addr;

	memset(bs_table, 0, size);

	for (i = 0; i < efi_varinfo_attrs_max; i++) {
		struct efi_varinfo *info = &bs_table->info[i];

		switch (i) {
		case efi_varinfo_attrs_bs:
			info->attrs = EFI_VARIABLE_BOOTSERVICE_ACCESS;
			break;
		case efi_varinfo_attrs_bs_nv:
			info->attrs = EFI_VARIABLE_BOOTSERVICE_ACCESS
				      | EFI_VARIABLE_NON_VOLATILE;
			break;
		case efi_varinfo_attrs_rt:
			info->attrs = EFI_VARIABLE_RUNTIME_ACCESS;
			break;
		case efi_varinfo_attrs_rt_nv:
			info->attrs = EFI_VARIABLE_RUNTIME_ACCESS
				      | EFI_VARIABLE_NON_VOLATILE;
			break;
		case efi_varinfo_attrs_bs_rt:
			info->attrs = EFI_VARIABLE_BOOTSERVICE_ACCESS
				      | EFI_VARIABLE_RUNTIME_ACCESS;
			break;
		case efi_varinfo_attrs_bs_rt_nv:
			info->attrs = EFI_VARIABLE_BOOTSERVICE_ACCESS
				      | EFI_VARIABLE_RUNTIME_ACCESS
				      | EFI_VARIABLE_NON_VOLATILE;
			break;
		}

		status = efi_rt_call(query_variable_info, info->attrs,
				     &info->maxstor, &info->remstor,
				     &info->maxvar);
		info->status = status;
		if (status != EFI_SUCCESS)
			info->maxstor = info->remstor = info->maxvar = ~0;
	}

	status = efi_bs_call(install_configuration_table,
			     &varinfo_table_guid,
			     bs_table);
	if (status != EFI_SUCCESS)
		efi_err("Failed to install variable info config table!\n");
}
