/*
 * Copyright 2012 Intel Corporation
 * Author: Josh Triplett <josh@joshtriplett.org>
 *
 * Based on the bgrt driver:
 * Copyright 2012 Red Hat, Inc <mjg@redhat.com>
 * Author: Matthew Garrett
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/acpi.h>
#include <linux/efi.h>
#include <linux/efi-bgrt.h>

struct acpi_table_bgrt bgrt_tab;
size_t bgrt_image_size;

struct bmp_header {
	u16 id;
	u32 size;
} __packed;

static inline int bgrt_table_exists(void)
{
	if (!efi_enabled(EFI_CONFIG_TABLES))
		return 0;
	if (efi.bgrt == EFI_INVALID_TABLE_ADDR)
		return 0;
	return 1;
}

void __init efi_bgrt_init(void)
{
        efi_memory_desc_t md;
	int rc;
	void *va;
	phys_addr_t end;
	size_t size, max;
	struct bmp_header bmph;

	pr_debug("bgrt-init: loading.\n");
	if (!bgrt_table_exists())
		return;

	rc = efi_mem_desc_lookup(efi.bgrt, &md);
	if (rc < 0 ||
	    (!(md.attribute & EFI_MEMORY_RUNTIME) &&
	     md.type != EFI_BOOT_SERVICES_DATA &&
	     md.type != EFI_RUNTIME_SERVICES_DATA)) {
		pr_warn("bgrt header is not in the memory map.\n");
		return;
	}

	max = efi_mem_desc_end(&md);
	if (max < efi.bgrt) {
		pr_err("EFI memory descriptor is invalid. (bgrt: %p max: %p)\n",
		       (void *)efi.bgrt, (void *)max);
		return;
	}

	size = sizeof(bgrt_tab);
	max -= efi.esrt;

	if (max < size) {
		pr_err("BGRT header doesn't fit on single memory map entry. (size: %zu max: %zu)\n",
		       size, max);
		return;
	}


	va = early_memremap(efi.bgrt, size);
	if (!va) {
		pr_err("early_memremap(%p, %zu) failed.\n", (void *)efi.bgrt,
		       size);
		return;
	}

	memcpy(&bgrt, va, sizeof(bgrt));
	early_memunmap(va, size);

	size += bgrt.length;

	acpi_bgrt_init(efi.bgrt);

	pr_debug("bgrt-init: loaded.\n");
}

void __init acpi_bgrt_init(struct acpi_table_header *table)
{
	void *image;
	struct bmp_header bmp_header;
	struct acpi_table_bgrt *bgrt = &bgrt_tab;

	if (acpi_disabled)
		return;

	if (!efi_enabled(EFI_MEMMAP))
		return;

	if (table->length < sizeof(bgrt_tab)) {
		pr_notice("Ignoring BGRT: invalid length %u (expected %zu)\n",
		       table->length, sizeof(bgrt_tab));
		return;
	}
	*bgrt = *(struct acpi_table_bgrt *)table;
	if (bgrt->version != 1) {
		pr_notice("Ignoring BGRT: invalid version %u (expected 1)\n",
		       bgrt->version);
		goto out;
	}
	if (bgrt->status & 0xfe) {
		pr_notice("Ignoring BGRT: reserved status bits are non-zero %u\n",
		       bgrt->status);
		goto out;
	}
	if (bgrt->image_type != 0) {
		pr_notice("Ignoring BGRT: invalid image type %u (expected 0)\n",
		       bgrt->image_type);
		goto out;
	}
	if (!bgrt->image_address) {
		pr_notice("Ignoring BGRT: null image address\n");
		goto out;
	}

	if (efi_mem_type(bgrt->image_address) != EFI_BOOT_SERVICES_DATA) {
		pr_notice("Ignoring BGRT: invalid image address\n");
		goto out;
	}
	image = early_memremap(bgrt->image_address, sizeof(bmp_header));
	if (!image) {
		pr_notice("Ignoring BGRT: failed to map image header memory\n");
		goto out;
	}

	memcpy(&bmp_header, image, sizeof(bmp_header));
	early_memunmap(image, sizeof(bmp_header));
	if (bmp_header.id != 0x4d42) {
		pr_notice("Ignoring BGRT: Incorrect BMP magic number 0x%x (expected 0x4d42)\n",
			bmp_header.id);
		goto out;
	}
	bgrt_image_size = bmp_header.size;
        efi_reserve_mem_region(bgrt->image_address, bgrt_image_size);
	efi_mem_reserve(bgrt->image_address, bgrt_image_size);

	return;
out:
	memset(bgrt, 0, sizeof(bgrt_tab));
}
