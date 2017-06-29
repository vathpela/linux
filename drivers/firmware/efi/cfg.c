/*
 * cfg.c - EFI configuration table support.
 *
 * Copyright 2017 Peter Jones <pjones@redhat.com>
 * Copyright 2017 Red Hat, Inc.
 *
 * This provides a driver interface for EFI configuration tables.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/efi.h>
#include <linux/random.h>
#include <linux/kexec.h>
#include <linux/acpi.h>

static LIST_HEAD(config_table_drivers);

void __init efi_config_table_register(efi_config_table_type_t *drv)
{
	if (!drv->name) {
		pr_err("EFI Configuration table has no name set\n");
		return;
	}
	drv->info->pa = EFI_INVALID_TABLE_ADDR;
	drv->info->size = -1;
	INIT_LIST_HEAD(&drv->cfg_drv_list);
	list_add_tail(&drv->cfg_drv_list, &config_table_drivers);
}

efi_config_table_type_t efi_mem_attr_config_table;
efi_config_table_type_t rng_seed_config_table;
efi_config_table_type_t properties_config_table;
efi_config_table_type_t acpi20_config_table;
efi_config_table_type_t acpi_config_table;

static efi_config_table_type_t *common_tables[] = {
	efi_mem_attr_config_table,
	rng_seed_config_table,
	properties_config_table,
	acpi20_config_table,
	acpi_config_table,
	NULL
};

static __init int match_config_table(efi_guid_t *guid, unsigned long table)
{
	efi_config_table_type_t *drv;
	char guid_str[EFI_VARIABLE_GUID_LEN+1];
	phys_addr_t pa = (phys_addr_t)table;
	int rc;
	efi_memory_desc_t md;
	size_t max_sz;

	efi_guid_to_str(guid, guid_str);

	rc = efi_mem_desc_lookup(pa, &md);
	if (rc < 0) {
		pr_warn("Config table %s is not in the memory map. Ignoring\n",
			guid_str);
		return;
	}

	max_sz = efi_mem_desc_end(&md);
	if (max_sz <= table) {
		pr_err("EFI memory descriptor is invalid. (addr: %p max: %p)\n",
		       (void *)pa, (void *)max_sz);
		return;
	}
	max_sz -= table;

	list_for_each_entry(drv, &config_table_drivers, cfg_drv_list) {
		if (!efi_guidcmp(*guid, drv->guid)) {
			const char *name = drv->name ? drv->name : guid_str;

			if (drv->probe) {
				drv->info->size = drv->probe((phys_addr_t)table,
							     max_sz);
				if (drv->info->size < 0) {
					drv->info->pa = EFI_INVALID_TABLE_ADDR;
					pr_cont(" %s=(invalid) ", name);
				} else {
					drv->info->pa = (phys_addr_t)table;
					pr_cont(" %s=0x%lx (%zd bytes) ",
						name, table, drv->info->size);
				}
			} else {
				drv->info->pa = (phys_addr_t)table;
			}
			return;
		}
	}
}

static __init int efi_parse_config_tables(void *config_tables, int count,
					  int sz)
{
	void *tablep;
	int i;

	tablep = config_tables;
	pr_info("");
	for (i = 0; i < count; i++) {
		efi_guid_t guid;
		unsigned long table;

		if (efi_enabled(EFI_64BIT)) {
			u64 table64;
			guid = ((efi_config_table_64_t *)tablep)->guid;
			table64 = ((efi_config_table_64_t *)tablep)->table;
			table = table64;
#ifndef CONFIG_64BIT
			if (table64 >> 32) {
				pr_cont("\n");
				pr_err("Table located above 4GB, disabling EFI.\n");
				return -EINVAL;
			}
#endif
		} else {
			guid = ((efi_config_table_32_t *)tablep)->guid;
			table = ((efi_config_table_32_t *)tablep)->table;
		}

		if (!match_config_table(&guid, table, common_tables))
			match_config_table(&guid, table, arch_tables);

		tablep += sz;
	}
	pr_cont("\n");
	set_bit(EFI_CONFIG_TABLES, &efi.flags);

	if (efi_config_table_valid(&efi.rng_seed)) {
		struct linux_efi_random_seed *seed;
		u32 size = 0;

		seed = early_memremap(efi.rng_seed.pa, sizeof(*seed));
		if (seed != NULL) {
			size = seed->size;
			early_memunmap(seed, sizeof(*seed));
		} else {
			pr_err("Could not map UEFI random seed!\n");
		}
		if (size > 0) {
			seed = early_memremap(efi.rng_seed.pa,
					      sizeof(*seed) + size);
			if (seed != NULL) {
				pr_notice("seeding entropy pool\n");
				add_device_randomness(seed->bits, seed->size);
				early_memunmap(seed, sizeof(*seed) + size);
			} else {
				pr_err("Could not map UEFI random seed!\n");
			}
		}
	}

	if (efi_enabled(EFI_MEMMAP))
		efi_memattr_init();

	efi_tpm_eventlog_init();

	/* Parse the EFI Properties table if it exists */
	if (efi_config_table_valid(&efi.properties_table)) {
		efi_properties_table_t *tbl;

		tbl = early_memremap(efi.properties_table.pa, sizeof(*tbl));
		if (tbl == NULL) {
			pr_err("Could not map Properties table!\n");
			return -ENOMEM;
		}

		if (tbl->memory_protection_attribute &
		    EFI_PROPERTIES_RUNTIME_MEMORY_PROTECTION_NON_EXECUTABLE_PE_DATA)
			set_bit(EFI_NX_PE_DATA, &efi.flags);

		early_memunmap(tbl, sizeof(*tbl));
	}
	return 0;
}

efi_config_table_type_t acpi_config_table;
efi_config_table_type_t acpi20_config_table;
efi_config_table_type_t smbios_config_table;
efi_config_table_type_t smbios3_config_table;
efi_config_table_type_t esrt_config_table;
efi_config_table_type_t properties_config_table;
efi_config_table_type_t rng_seed_config_table;
efi_config_table_type_t tpm_log_config_table;
efi_config_table_type_t mem_reserve_config_table;

int __init efi_enumerate_config_tables(void)
{
	void *config_tables;
	int sz, ret = 0;

	if (efi_enabled(EFI_64BIT))
		sz = sizeof(efi_config_table_64_t);
	else
		sz = sizeof(efi_config_table_32_t);

	/*
	 * Let's see what config tables the firmware passed to us.
	 */
	config_tables = early_memremap(efi.systab->tables,
				       efi.systab->nr_tables * sz);
	if (config_tables == NULL) {
		pr_err("Could not map Configuration table!\n");
		return -ENOMEM;
	}

	ret = efi_parse_config_tables(config_tables, efi.systab->nr_tables, sz);

	early_memunmap(config_tables, efi.systab->nr_tables * sz);
	return ret;
}

int __init efi_config_table_init(void)
{
	void *config_tables;
	int sz, ret;

	if (efi_enabled(EFI_64BIT))
		sz = sizeof(efi_config_table_64_t);
	else
		sz = sizeof(efi_config_table_32_t);

	/*
	 * Let's see what config tables the firmware passed to us.
	 */
	config_tables = early_memremap(efi.systab->tables,
				       efi.systab->nr_tables * sz);
	if (config_tables == NULL) {
		pr_err("Could not map Configuration table!\n");
		return -ENOMEM;
	}

	ret = efi_config_parse_tables(config_tables, efi.systab->nr_tables, sz,
				      arch_tables);

	early_memunmap(config_tables, efi.systab->nr_tables * sz);
	return ret;
}

/* Everything below here is smallish common table handlers... */
ssize_t __init rng_seed_probe(phys_addr_t pa, size_t max)
{
	struct linux_efi_random_seed *seed;
	u32 size = 0;

	if (sizeof(*seed) > max)
		return -EINVAL;

	seed = early_memremap(pa, sizeof(*seed));
	if (seed == NULL) {
		pr_err("Could not map UEFI random seed!\n");
		return -1;
	}

	size = seed->size;
	early_memunmap(seed, sizeof(*seed));

	if (size == 0)
		return sizeof(*seed);

	if (size > (SIZE_MAX >> 1) - sizeof(*seed))
		return -EINVAL;
	size += sizeof(*seed);
	return size;
}

static efi_config_table_type_t rng_seed_config_table = {
	.guid = LINUX_EFI_RANDOM_SEED_TABLE_GUID,
	.name = "RNG",
	.probe = rng_seed_probe,
	.init = rng_seed_init,
	.info = &efi.rng_seed,
	.reserve = true,
};

static int __init rng_seed_init(phys_addr_t pa, size_t size)
{
	struct linux_efi_random_seed *seed;

	seed = early_memremap(pa, size);
	if (seed == NULL) {
		pr_err("Could not map UEFI random seed!\n");
		return -ENOMEM;
	}

	add_device_randomness(seed->bits, seed->size);
	early_memunmap(seed, size);
	return 0;
}

#ifdef CONFIG_KEXEC
static int update_efi_random_seed(struct notifier_block *nb,
				  unsigned long code, void *unused)
{
	struct linux_efi_random_seed *seed;

	if (!efi_config_table_valid(&efi.rng_seed))
		return NOTIFY_DONE;

	if (!kexec_in_progress)
		return NOTIFY_DONE;

	seed = memremap(efi.rng_seed.pa, efi.rng_seed.size,
			MEMREMAP_WB);
	if (seed == NULL) {
		pr_err("Could not map UEFI random seed!\n");
		return NOTIFY_DONE;
	}

	get_random_bytes(seed->bits, seed->size);
	memunmap(seed);

	return NOTIFY_DONE;
}

static struct notifier_block efi_random_seed_nb = {
	.notifier_call = update_efi_random_seed,
};

static int register_update_efi_random_seed(void)
{
	if (!efi_config_table_valid(&efi.rng_seed))
		return 0;

	return register_reboot_notifier(&efi_random_seed_nb);
}
late_initcall(register_update_efi_random_seed);
#endif

static ssize_t __init properties_probe(phys_addr_t pa, size_t max_sz)
{
	efi_properties_table_t *tbl;

	if (max_sz < sizeof (*tbl))
		return -EINVAL;

	tbl = early_memremap(pa, sizeof(*tbl));
	if (tbl == NULL) {
		pr_err("Could not map Properties table!\n");
		return -ENOMEM;
	}

	if (tbl->memory_protection_attribute &
	    EFI_PROPERTIES_RUNTIME_MEMORY_PROTECTION_NON_EXECUTABLE_PE_DATA)
		set_bit(EFI_NX_PE_DATA, &efi.flags);

	early_memunmap(tbl, sizeof(*tbl));
	return sizeof(*tbl);
}

static efi_config_table_type_t properties_config_table = {
	.guid = EFI_PROPERTIES_TABLE_GUID,
	.name = "PROP",
	.probe = properties_probe,
	.info = &efi.properties_table,
	.reserve = true,
};

static ssize_t __init
efi_acpi20_probe(phys_addr_t pa, size_t max)
{
	struct acpi_table_rsdp *rsdp;
	if (max < sizeof(*rsdp))
		return -EINVAL;

	return sizeof(*rsdp);
}

static efi_config_table_type_t acpi20_config_table = {
	.guid = ACPI_20_TABLE_GUID,
	.name = "ACPI20",
	.probe = efi_acpi20_probe,
	.info = &efi.acpi20,
	.reserve = true,
};

static efi_config_table_type_t acpi_config_table = {
	.guid = ACPI_TABLE_GUID,
	.name = "ACPI",
	.probe = efi_acpi20_probe,
	.info = &efi.acpi,
	.reserve = true,
};
