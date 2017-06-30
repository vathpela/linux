/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_EFI_H
#define _LINUX_EFI_H

/*
 * Extensible Firmware Interface
 * Based on 'Extensible Firmware Interface Specification' version 0.9, April 30, 1999
 *
 * Copyright (C) 1999 VA Linux Systems
 * Copyright (C) 1999 Walt Drummond <drummond@valinux.com>
 * Copyright (C) 1999, 2002-2003 Hewlett-Packard Co.
 *	David Mosberger-Tang <davidm@hpl.hp.com>
 *	Stephane Eranian <eranian@hpl.hp.com>
 */
#include <linux/init.h>
#include <linux/string.h>
#include <linux/time.h>
#include <linux/types.h>
#include <linux/proc_fs.h>
#include <linux/rtc.h>
#include <linux/ioport.h>
#include <linux/pfn.h>
#include <linux/pstore.h>
#include <linux/range.h>
#include <linux/reboot.h>
#include <linux/uuid.h>
#include <linux/screen_info.h>

#include <linux/efi/types.h>
#include <linux/efi/base.h>
#include <asm/page.h>

void efi_native_runtime_setup(void);

int __efi_capsule_setup_info(struct capsule_info *cap_info);

void efi_native_runtime_setup(void);

static inline int
efi_guidcmp (efi_guid_t left, efi_guid_t right)
{
	return memcmp(&left, &right, sizeof (efi_guid_t));
}

static inline char *
efi_guid_to_str(efi_guid_t *guid, char *out)
{
	sprintf(out, "%pUl", guid->b);
        return out;
}

extern void efi_init (void);
extern void *efi_get_pal_addr (void);
extern void efi_map_pal_code (void);
extern void efi_memmap_walk (efi_freemem_callback_t callback, void *arg);
extern void efi_gettimeofday (struct timespec64 *ts);
extern void efi_enter_virtual_mode (void);	/* switch EFI to virtual mode, if possible */
#ifdef CONFIG_X86
extern efi_status_t efi_query_variable_store(u32 attributes,
					     unsigned long size,
					     bool nonblocking);
extern void efi_find_mirror(void);
#else

static inline efi_status_t efi_query_variable_store(u32 attributes,
						    unsigned long size,
						    bool nonblocking)
{
	return EFI_SUCCESS;
}
#endif
extern void __iomem *efi_lookup_mapped_addr(u64 phys_addr);

extern phys_addr_t __init efi_memmap_alloc(unsigned int num_entries);
extern int __init efi_memmap_init_early(struct efi_memory_map_data *data);
extern int __init efi_memmap_init_late(phys_addr_t addr, unsigned long size);
extern void __init efi_memmap_unmap(void);
extern int __init efi_memmap_install(phys_addr_t addr, unsigned int nr_map);
extern int __init efi_memmap_split_count(efi_memory_desc_t *md,
					 struct range *range);
extern void __init efi_memmap_insert(struct efi_memory_map *old_memmap,
				     void *buf, struct efi_mem_range *mem);

extern int efi_config_init(efi_config_table_type_t *arch_tables);
#ifdef CONFIG_EFI_ESRT
extern void __init efi_esrt_init(void);
#else
static inline void efi_esrt_init(void) { }
#endif
extern int efi_config_parse_tables(void *config_tables, int count, int sz,
				   efi_config_table_type_t *arch_tables);
extern u64 efi_get_iobase (void);
extern int efi_mem_type(unsigned long phys_addr);
extern u64 efi_mem_attributes (unsigned long phys_addr);
extern u64 efi_mem_attribute (unsigned long phys_addr, unsigned long size);
extern int __init efi_uart_console_only (void);
extern u64 efi_mem_desc_end(efi_memory_desc_t *md);
extern int efi_mem_desc_lookup(u64 phys_addr, efi_memory_desc_t *out_md);
extern void efi_mem_reserve(phys_addr_t addr, u64 size);
extern int efi_mem_reserve_persistent(phys_addr_t addr, u64 size);
extern void efi_initialize_iomem_resources(struct resource *code_resource,
		struct resource *data_resource, struct resource *bss_resource);
extern int efi_get_fdt_params(struct efi_fdt_params *params);
extern struct kobject *efi_kobj;

extern int efi_reboot_quirk_mode;
extern bool efi_poweroff_required(void);

#ifdef CONFIG_EFI_FAKE_MEMMAP
extern void __init efi_fake_memmap(void);
#else
static inline void efi_fake_memmap(void) { }
#endif

/*
 * efi_memattr_perm_setter - arch specific callback function passed into
 *                           efi_memattr_apply_permissions() that updates the
 *                           mapping permissions described by the second
 *                           argument in the page tables referred to by the
 *                           first argument.
 */
typedef int (*efi_memattr_perm_setter)(struct mm_struct *, efi_memory_desc_t *);

extern int efi_memattr_init(void);
extern int efi_memattr_apply_permissions(struct mm_struct *mm,
					 efi_memattr_perm_setter fn);

/*
 * efi_early_memdesc_ptr - get the n-th EFI memmap descriptor
 * @map: the start of efi memmap
 * @desc_size: the size of space for each EFI memmap descriptor
 * @n: the index of efi memmap descriptor
 *
 * EFI boot service provides the GetMemoryMap() function to get a copy of the
 * current memory map which is an array of memory descriptors, each of
 * which describes a contiguous block of memory. It also gets the size of the
 * map, and the size of each descriptor, etc.
 *
 * Note that per section 6.2 of UEFI Spec 2.6 Errata A, the returned size of
 * each descriptor might not be equal to sizeof(efi_memory_memdesc_t),
 * since efi_memory_memdesc_t may be extended in the future. Thus the OS
 * MUST use the returned size of the descriptor to find the start of each
 * efi_memory_memdesc_t in the memory map array. This should only be used
 * during bootup since for_each_efi_memory_desc_xxx() is available after the
 * kernel initializes the EFI subsystem to set up struct efi_memory_map.
 */
#define efi_early_memdesc_ptr(map, desc_size, n)			\
	(efi_memory_desc_t *)((void *)(map) + ((n) * (desc_size)))

/* Iterate through an efi_memory_map */
#define for_each_efi_memory_desc_in_map(m, md)				   \
	for ((md) = (m)->map;						   \
	     (md) && ((void *)(md) + (m)->desc_size) <= (m)->map_end;	   \
	     (md) = (void *)(md) + (m)->desc_size)

/**
 * for_each_efi_memory_desc - iterate over descriptors in efi.memmap
 * @md: the efi_memory_desc_t * iterator
 *
 * Once the loop finishes @md must not be accessed.
 */
#define for_each_efi_memory_desc(md) \
	for_each_efi_memory_desc_in_map(&efi.memmap, md)

/*
 * Format an EFI memory descriptor's type and attributes to a user-provided
 * character buffer, as per snprintf(), and return the buffer.
 */
char * __init efi_md_typeattr_format(char *buf, size_t size,
				     const efi_memory_desc_t *md);

/**
 * efi_range_is_wc - check the WC bit on an address range
 * @start: starting kvirt address
 * @len: length of range
 *
 * Consult the EFI memory map and make sure it's ok to set this range WC.
 * Returns true or false.
 */
static inline int efi_range_is_wc(unsigned long start, unsigned long len)
{
	unsigned long i;

	for (i = 0; i < len; i += (1UL << EFI_PAGE_SHIFT)) {
		unsigned long paddr = __pa(start + i);
		if (!(efi_mem_attributes(paddr) & EFI_MEMORY_WC))
			return 0;
	}
	/* The range checked out */
	return 1;
}

#ifdef CONFIG_EFI_PCDP
extern int __init efi_setup_pcdp_console(char *);
#endif

#ifndef CONFIG_EFI
static inline bool
efi_capsule_pending(int *reset_type)
{
	return false;
}

static inline bool efi_is_table_address(unsigned long phys_addr)
{
	return false;
}

static inline int efi_apply_persistent_mem_reservations(void)
{
	return 0;
}
#endif

extern int efi_status_to_err(efi_status_t status);

#if IS_ENABLED(CONFIG_EFI_DEV_PATH_PARSER)
struct device *efi_get_device_by_path(struct efi_dev_path **node, size_t *len);
#endif

static inline void memrange_efi_to_native(u64 *addr, u64 *npages)
{
	*npages = PFN_UP(*addr + (*npages<<EFI_PAGE_SHIFT)) - PFN_DOWN(*addr);
	*addr &= PAGE_MASK;
}

/*
 * EFI Variable support.
 *
 * Different firmware drivers can expose their EFI-like variables using
 * the following.
 */

struct efivar_operations {
	efi_get_variable_t *get_variable;
	efi_get_next_variable_t *get_next_variable;
	efi_set_variable_t *set_variable;
	efi_set_variable_t *set_variable_nonblocking;
	efi_query_variable_store_t *query_variable_store;
};

struct efivars {
	struct kset *kset;
	struct kobject *kobject;
	const struct efivar_operations *ops;
};

/*
 * The maximum size of VariableName + Data = 1024
 * Therefore, it's reasonable to save that much
 * space in each part of the structure,
 * and we use a page for reading/writing.
 */

#define EFI_VAR_NAME_LEN	1024

struct efi_variable {
	efi_char16_t  VariableName[EFI_VAR_NAME_LEN/sizeof(efi_char16_t)];
	efi_guid_t    VendorGuid;
	unsigned long DataSize;
	__u8          Data[1024];
	efi_status_t  Status;
	__u32         Attributes;
} __attribute__((packed));

struct efivar_entry {
	struct efi_variable var;
	struct list_head list;
	struct kobject kobj;
	bool scanning;
	bool deleting;
};

extern struct list_head efivar_sysfs_list;

static inline void
efivar_unregister(struct efivar_entry *var)
{
	kobject_put(&var->kobj);
}

int efivars_register(struct efivars *efivars,
		     const struct efivar_operations *ops,
		     struct kobject *kobject);
int efivars_unregister(struct efivars *efivars);
struct kobject *efivars_kobject(void);

int efivar_init(int (*func)(efi_char16_t *, efi_guid_t, unsigned long, void *),
		void *data, bool duplicates, struct list_head *head);

int efivar_entry_add(struct efivar_entry *entry, struct list_head *head);
int efivar_entry_remove(struct efivar_entry *entry);

int __efivar_entry_delete(struct efivar_entry *entry);
int efivar_entry_delete(struct efivar_entry *entry);

int efivar_entry_size(struct efivar_entry *entry, unsigned long *size);
int __efivar_entry_get(struct efivar_entry *entry, u32 *attributes,
		       unsigned long *size, void *data);
int efivar_entry_get(struct efivar_entry *entry, u32 *attributes,
		     unsigned long *size, void *data);
int efivar_entry_set(struct efivar_entry *entry, u32 attributes,
		     unsigned long size, void *data, struct list_head *head);
int efivar_entry_set_get_size(struct efivar_entry *entry, u32 attributes,
			      unsigned long *size, void *data, bool *set);
int efivar_entry_set_safe(efi_char16_t *name, efi_guid_t vendor, u32 attributes,
			  bool block, unsigned long size, void *data);

int efivar_entry_iter_begin(void);
void efivar_entry_iter_end(void);

int __efivar_entry_iter(int (*func)(struct efivar_entry *, void *),
			struct list_head *head, void *data,
			struct efivar_entry **prev);
int efivar_entry_iter(int (*func)(struct efivar_entry *, void *),
		      struct list_head *head, void *data);

struct efivar_entry *efivar_entry_find(efi_char16_t *name, efi_guid_t guid,
				       struct list_head *head, bool remove);

bool efivar_validate(efi_guid_t vendor, efi_char16_t *var_name, u8 *data,
		     unsigned long data_size);
bool efivar_variable_is_removable(efi_guid_t vendor, const char *name,
				  size_t len);

extern struct work_struct efivar_work;
void efivar_run_worker(void);

#if defined(CONFIG_EFI_VARS) || defined(CONFIG_EFI_VARS_MODULE)
int efivars_sysfs_init(void);

#define EFIVARS_DATA_SIZE_MAX 1024

#endif /* CONFIG_EFI_VARS */
extern bool efi_capsule_pending(int *reset_type);

extern int efi_capsule_supported(efi_guid_t guid, u32 flags,
				 size_t size, int *reset);

extern int efi_capsule_update(efi_capsule_header_t *capsule,
			      phys_addr_t *pages);

#ifdef CONFIG_EFI_RUNTIME_MAP
int efi_runtime_map_init(struct kobject *);
int efi_get_runtime_map_size(void);
int efi_get_runtime_map_desc_size(void);
int efi_runtime_map_copy(void *buf, size_t bufsz);
#else
static inline int efi_runtime_map_init(struct kobject *kobj)
{
	return 0;
}

static inline int efi_get_runtime_map_size(void)
{
	return 0;
}

static inline int efi_get_runtime_map_desc_size(void)
{
	return 0;
}

static inline int efi_runtime_map_copy(void *buf, size_t bufsz)
{
	return 0;
}

#endif

/* prototypes shared between arch specific and generic stub code */

void efi_printk(efi_system_table_t *sys_table_arg, char *str);

void efi_free(efi_system_table_t *sys_table_arg, unsigned long size,
	      unsigned long addr);

char *efi_convert_cmdline(efi_system_table_t *sys_table_arg,
			  efi_loaded_image_t *image, int *cmd_line_len);

efi_status_t efi_get_memory_map(efi_system_table_t *sys_table_arg,
				struct efi_boot_memmap *map);

efi_status_t efi_low_alloc(efi_system_table_t *sys_table_arg,
			   unsigned long size, unsigned long align,
			   unsigned long *addr);

efi_status_t efi_high_alloc(efi_system_table_t *sys_table_arg,
			    unsigned long size, unsigned long align,
			    unsigned long *addr, unsigned long max);

efi_status_t efi_relocate_kernel(efi_system_table_t *sys_table_arg,
				 unsigned long *image_addr,
				 unsigned long image_size,
				 unsigned long alloc_size,
				 unsigned long preferred_addr,
				 unsigned long alignment);

efi_status_t handle_cmdline_files(efi_system_table_t *sys_table_arg,
				  efi_loaded_image_t *image,
				  char *cmd_line, char *option_string,
				  unsigned long max_addr,
				  unsigned long *load_addr,
				  unsigned long *load_size);

efi_status_t efi_parse_options(char const *cmdline);

efi_status_t efi_setup_gop(efi_system_table_t *sys_table_arg,
			   struct screen_info *si, efi_guid_t *proto,
			   unsigned long size);

bool efi_runtime_disabled(void);
extern void efi_call_virt_check_flags(unsigned long flags, const char *call);

enum efi_secureboot_mode {
	efi_secureboot_mode_unset,
	efi_secureboot_mode_unknown,
	efi_secureboot_mode_disabled,
	efi_secureboot_mode_enabled,
};
enum efi_secureboot_mode efi_get_secureboot(efi_system_table_t *sys_table);

#ifdef CONFIG_RESET_ATTACK_MITIGATION
void efi_enable_reset_attack_mitigation(efi_system_table_t *sys_table_arg);
#else
static inline void
efi_enable_reset_attack_mitigation(efi_system_table_t *sys_table_arg) { }
#endif

void efi_retrieve_tpm2_eventlog(efi_system_table_t *sys_table);

/*
 * Arch code can implement the following three template macros, avoiding
 * reptition for the void/non-void return cases of {__,}efi_call_virt():
 *
 *  * arch_efi_call_virt_setup()
 *
 *    Sets up the environment for the call (e.g. switching page tables,
 *    allowing kernel-mode use of floating point, if required).
 *
 *  * arch_efi_call_virt()
 *
 *    Performs the call. The last expression in the macro must be the call
 *    itself, allowing the logic to be shared by the void and non-void
 *    cases.
 *
 *  * arch_efi_call_virt_teardown()
 *
 *    Restores the usual kernel environment once the call has returned.
 */

#define efi_call_virt_pointer(p, f, args...)				\
({									\
	efi_status_t __s;						\
	unsigned long __flags;						\
									\
	arch_efi_call_virt_setup();					\
									\
	local_save_flags(__flags);					\
	__s = arch_efi_call_virt(p, f, args);				\
	efi_call_virt_check_flags(__flags, __stringify(f));		\
									\
	arch_efi_call_virt_teardown();					\
									\
	__s;								\
})

#define __efi_call_virt_pointer(p, f, args...)				\
({									\
	unsigned long __flags;						\
									\
	arch_efi_call_virt_setup();					\
									\
	local_save_flags(__flags);					\
	arch_efi_call_virt(p, f, args);					\
	efi_call_virt_check_flags(__flags, __stringify(f));		\
									\
	arch_efi_call_virt_teardown();					\
})

typedef efi_status_t (*efi_exit_boot_map_processing)(
	efi_system_table_t *sys_table_arg,
	struct efi_boot_memmap *map,
	void *priv);

efi_status_t efi_exit_boot_services(efi_system_table_t *sys_table,
				    void *handle,
				    struct efi_boot_memmap *map,
				    void *priv,
				    efi_exit_boot_map_processing priv_func);

#define EFI_RANDOM_SEED_SIZE		64U

struct linux_efi_random_seed {
	u32	size;
	u8	bits[];
};

struct linux_efi_tpm_eventlog {
	u32	size;
	u8	version;
	u8	log[];
};

extern int efi_tpm_eventlog_init(void);

/*
 * efi_runtime_service() function identifiers.
 * "NONE" is used by efi_recover_from_page_fault() to check if the page
 * fault happened while executing an efi runtime service.
 */
enum efi_rts_ids {
	NONE,
	GET_TIME,
	SET_TIME,
	GET_WAKEUP_TIME,
	SET_WAKEUP_TIME,
	GET_VARIABLE,
	GET_NEXT_VARIABLE,
	SET_VARIABLE,
	QUERY_VARIABLE_INFO,
	GET_NEXT_HIGH_MONO_COUNT,
	RESET_SYSTEM,
	UPDATE_CAPSULE,
	QUERY_CAPSULE_CAPS,
};

/*
 * efi_runtime_work:	Details of EFI Runtime Service work
 * @arg<1-5>:		EFI Runtime Service function arguments
 * @status:		Status of executing EFI Runtime Service
 * @efi_rts_id:		EFI Runtime Service function identifier
 * @efi_rts_comp:	Struct used for handling completions
 */
struct efi_runtime_work {
	void *arg1;
	void *arg2;
	void *arg3;
	void *arg4;
	void *arg5;
	efi_status_t status;
	struct work_struct work;
	enum efi_rts_ids efi_rts_id;
	struct completion efi_rts_comp;
};

extern struct efi_runtime_work efi_rts_work;

/* Workqueue to queue EFI Runtime Services */
extern struct workqueue_struct *efi_rts_wq;

struct linux_efi_memreserve {
	int		size;			// allocated size of the array
	atomic_t	count;			// number of entries used
	phys_addr_t	next;			// pa of next struct instance
	struct {
		phys_addr_t	base;
		phys_addr_t	size;
	} entry[0];
};

#define EFI_MEMRESERVE_SIZE(count) (sizeof(struct linux_efi_memreserve) + \
	(count) * sizeof(((struct linux_efi_memreserve *)0)->entry[0]))

#define EFI_MEMRESERVE_COUNT(size) (((size) - sizeof(struct linux_efi_memreserve)) \
	/ sizeof(((struct linux_efi_memreserve *)0)->entry[0]))

#endif /* _LINUX_EFI_H */
