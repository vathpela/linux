/*
 * tpm2.c
 *
 * This module exports the TCG TPM 2.0 Event Log table so the rest of the
 * kernel can get at it.
 *
 * Data is currently exported by drivers/char/tpm/tpm2_eventlog.c
 */
#include <linux/efi.h>
#include <asm/efi.h>
#include <asm/setup.h>
#include <linux/tpm2_eventlog.h>

#include "tpm2-efi.h"

static phys_addr_t tcg2_event_log;
static phys_addr_t tcg2_event_log_first_entry;
static phys_addr_t tcg2_event_log_last_entry;
static size_t tcg2_event_log_size;
static bool tcg2_event_log_truncated;

efi_tcg2_boot_service_capability_t *tpm2_boot_service_capability = NULL;
static efi_tcg2_boot_service_capability_t bs_cap;

static bool have_log = false;

static tcg_efi_spec_id_event_algorithm_size_t
	algorithms[EFI_TCG2_BOOT_HASH_ALGORITHMS+1];

static ssize_t
get_region_size(efi_physical_addr_t pa)
{
	int rc;
	efi_memory_desc_t md;
	size_t max;

	/* Find a bounding box in the memory map for our allocation */
	rc = efi_mem_desc_lookup(pa, &md);
	if (rc < 0)
		return rc;

	max = efi_mem_desc_end(&md);
	if (max < pa)
		return rc;

	return max - pa;
}

static ssize_t
tcg2_get_entry_size(efi_physical_addr_t event_log_entry_pa)
{
	struct tcg_pcr_event2 *event;
	size_t event2_size, aligned;
	u32 event_size;

	event2_size = offsetof(struct tcg_pcr_event2, event);
	aligned = PAGE_ALIGN(event2_size);

	event = early_memremap(event_log_entry_pa, aligned);
	if (!event)
		return -ENOMEM;

	event_size = event->event.event_size;
	early_memunmap(event, aligned);

	if (SIZE_MAX - event2_size < event_size)
		return -ENOMEM;

	event2_size += event_size;
	return event2_size;
}

static int __init
tcg2_get_header_info(efi_physical_addr_t event_log_header_pa)
{
	ssize_t region_size;
	ssize_t structure_size = 0;
	u8 *vendor_info_size;
	u32 num_algs;
	struct tcg_efi_specid_event *id_event_struct;
	ssize_t algorithm_table_size;
	unsigned int x;
	int ret = -EINVAL;
	int found = 0;

	region_size = get_region_size(event_log_header_pa);
	if (region_size <= 0)
		return region_size;

	structure_size = offsetof(struct tcg_efi_specid_event,
				  num_algs)
			 + sizeof(id_event_struct->num_algs);
	if (region_size <= structure_size)
		return -EINVAL;

	id_event_struct = early_memremap(event_log_header_pa,
					 PAGE_ALIGN(structure_size));
	if (!id_event_struct)
		return -ENOMEM;

	if (memcmp(id_event_struct->signature, "Spec ID Event03", 16))
		goto unmap;

	num_algs = id_event_struct->num_algs;
	if (num_algs < 0)
		goto unmap;

	if (SIZE_MAX / sizeof (tcg_efi_spec_id_event_algorithm_size_t)
	    < num_algs)
		goto unmap;

	algorithm_table_size = num_algs *
				sizeof (tcg_efi_spec_id_event_algorithm_size_t);
	if (SIZE_MAX - algorithm_table_size < structure_size)
		goto unmap;

	structure_size +=  algorithm_table_size;
	vendor_info_size = (u8 *)id_event_struct + structure_size;
	if (SIZE_MAX - *vendor_info_size < structure_size)
		goto unmap;

	structure_size += sizeof (*vendor_info_size) + *vendor_info_size;
	if (region_size <= structure_size)
		goto unmap;

	for (x = 0; x < num_algs; x++) {
		u16 alg_id = id_event_struct->digest_sizes[x].alg_id;
		int which;

		/*
		 * Check and ensure this is a defined algorithm; if it's not,
		 * ignore it.
		 */
		switch (alg_id) {
			case EFI_TCG2_BOOT_HASH_ALG_SHA1:
				which = 0;
				break;
			case EFI_TCG2_BOOT_HASH_ALG_SHA256:
				which = 1;
				break;
			case EFI_TCG2_BOOT_HASH_ALG_SHA384:
				which = 2;
				break;
			case EFI_TCG2_BOOT_HASH_ALG_SHA512:
				which = 3;
				break;
			case EFI_TCG2_BOOT_HASH_ALG_SM3_256:
				which = 4;
				break;
			default:
				continue;
		}
		memcpy(&algorithms[which], &id_event_struct->digest_sizes[x],
		       sizeof (algorithms[which]));
		found |= alg_id;
		if (found == (EFI_TCG2_BOOT_HASH_ALG_SHA1|
			      EFI_TCG2_BOOT_HASH_ALG_SHA256|
			      EFI_TCG2_BOOT_HASH_ALG_SHA384|
			      EFI_TCG2_BOOT_HASH_ALG_SHA512|
			      EFI_TCG2_BOOT_HASH_ALG_SM3_256))
			break;
	}
	if (!(found & EFI_TCG2_BOOT_HASH_ALG_SHA512))
		memcpy(&algorithms[3], &algorithms[4], sizeof(algorithms[3]));
	if (!(found & EFI_TCG2_BOOT_HASH_ALG_SHA384))
		memcpy(&algorithms[2], &algorithms[3], sizeof(algorithms[3])*2);
	if (!(found & EFI_TCG2_BOOT_HASH_ALG_SHA256))
		memcpy(&algorithms[1], &algorithms[2], sizeof(algorithms[3])*3);
	if (!(found & EFI_TCG2_BOOT_HASH_ALG_SHA1))
		memcpy(&algorithms[0], &algorithms[1], sizeof(algorithms[3])*4);

	tcg2_event_log_first_entry = (phys_addr_t)((u8 *)event_log_header_pa
						   + structure_size);

	ret = 0;
unmap:
	early_memunmap(id_event_struct, PAGE_SIZE);
	return ret;
}

efi_status_t __init
efi_setup_tpm(efi_system_table_t *sys_table_arg)
{
	efi_tcg2_protocol_t *tcg2;
	efi_guid_t tcg2_proto = EFI_TCG2_PROTOCOL_GUID;
	efi_status_t status;
	efi_physical_addr_t event_log_address;
	efi_physical_addr_t event_log_last_entry;
	efi_bool_t event_log_truncated = 0;
	size_t last_entry_size;
	int rc;

	status = efi_call_early(locate_protocol, &tcg2_proto, NULL,
				(void **)&tcg2);
	if (status != EFI_SUCCESS) {
		pr_info("No EFI TPM2 protocol installed\n");
		return status;
	}

	memset(&bs_cap, '\0', sizeof (bs_cap));
	status = __efi_call_early(tcg2->get_capability, tcg2, &bs_cap);
	if (status != EFI_SUCCESS) {
		pr_err("EFI TPM2->GetCapability failed\n");
		return status;
	}

	status = __efi_call_early(tcg2->get_event_log, tcg2,
				  EFI_TCG2_EVENT_LOG_FORMAT_TCG_2,
				  &event_log_address,
				  &event_log_last_entry,
				  &event_log_truncated);
	if (status != EFI_SUCCESS)
		return status;

	tcg2_event_log_truncated = event_log_truncated ? true : false;
	/* check if there's no tpm present */
	if (event_log_address == 0 &&
	    event_log_last_entry == 0 &&
	    event_log_truncated == 0)
		return EFI_UNSUPPORTED;

	tcg2_event_log_last_entry = (phys_addr_t)event_log_last_entry;

	rc = tcg2_get_header_info(event_log_address);
	if (rc < 0)
		return EFI_UNSUPPORTED;

	last_entry_size = tcg2_get_entry_size(event_log_last_entry);
	if (last_entry_size < 0)
		return EFI_UNSUPPORTED;

	tcg2_event_log_size = (event_log_last_entry - event_log_address)
		+ last_entry_size;

	efi_mem_reserve(tcg2_event_log, tcg2_event_log_size);

	tpm2_boot_service_capability = &bs_cap;
	have_log = true;
	return EFI_SUCCESS;
}
