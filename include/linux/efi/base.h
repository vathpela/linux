#ifndef _LINUX_EFI_BASE_H
#define _LINUX_EFI_BASE_H

/*
 * All runtime access to EFI goes through this structure:
 */
extern struct efi_arch_priv efi_arch_priv;

extern struct efi {
	efi_system_table_t *systab;	/* EFI system table */
	struct efi_arch_priv *arch_priv;/* Architecture specific private data */
	unsigned int runtime_version;	/* Runtime services version */
	unsigned long acpi;		/* ACPI table  (IA64 ext 0.71) */
	unsigned long acpi20;		/* ACPI table  (ACPI 2.0) */
	unsigned long smbios;		/* SMBIOS table (32 bit entry point) */
	unsigned long smbios3;		/* SMBIOS table (64 bit entry point) */
	unsigned long fw_vendor;	/* fw_vendor */
	unsigned long runtime;		/* runtime table */
	unsigned long config_table;	/* config tables */
	unsigned long esrt;		/* ESRT table */
	unsigned long properties_table;	/* properties table */
	unsigned long mem_attr_table;	/* memory attributes table */
	unsigned long rng_seed;		/* UEFI firmware random seed */
	unsigned long tpm_log;		/* TPM2 Event Log table */
	unsigned long mem_reserve;	/* Linux EFI memreserve table */
	efi_get_time_t *get_time;
	efi_set_time_t *set_time;
	efi_get_wakeup_time_t *get_wakeup_time;
	efi_set_wakeup_time_t *set_wakeup_time;
	efi_get_variable_t *get_variable;
	efi_get_next_variable_t *get_next_variable;
	efi_set_variable_t *set_variable;
	efi_set_variable_t *set_variable_nonblocking;
	efi_query_variable_info_t *query_variable_info;
	efi_query_variable_info_t *query_variable_info_nonblocking;
	efi_update_capsule_t *update_capsule;
	efi_query_capsule_caps_t *query_capsule_caps;
	efi_get_next_high_mono_count_t *get_next_high_mono_count;
	efi_reset_system_t *reset_system;
	efi_set_virtual_address_map_t *set_virtual_address_map;
	struct efi_memory_map memmap;
	unsigned long flags;
} efi;

/*
 * We play games with efi_enabled so that the compiler will, if
 * possible, remove EFI-related code altogether.
 */
#define EFI_BOOT		0	/* Were we booted from EFI? */
#define EFI_CONFIG_TABLES	2	/* Can we use EFI config tables? */
#define EFI_RUNTIME_SERVICES	3	/* Can we use runtime services? */
#define EFI_MEMMAP		4	/* Can we use EFI memory map? */
#define EFI_64BIT		5	/* Is the firmware 64-bit? */
#define EFI_PARAVIRT		6	/* Access is via a paravirt interface */
#define EFI_ARCH_1		7	/* First arch-specific bit */
#define EFI_DBG			8	/* Print additional debug info at runtime */
#define EFI_NX_PE_DATA		9	/* Can runtime data regions be mapped non-executable? */
#define EFI_MEM_ATTR		10	/* Did firmware publish an EFI_MEMORY_ATTRIBUTES table? */

#ifdef CONFIG_EFI
/*
 * Test whether the above EFI_* bits are enabled.
 */
static inline bool efi_enabled(int feature)
{
	return test_bit(feature, &efi.flags) != 0;
}
extern void efi_reboot(enum reboot_mode reboot_mode, const char *__unused);

extern bool efi_is_table_address(unsigned long phys_addr);

extern int efi_apply_persistent_mem_reservations(void);
#else
static inline bool efi_enabled(int feature)
{
	return false;
}
static inline void
efi_reboot(enum reboot_mode reboot_mode, const char *__unused) {}
#endif

#endif /* !_LINUX_EFI_BASE_H */
