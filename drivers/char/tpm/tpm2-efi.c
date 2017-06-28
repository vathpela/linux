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

#include "tpm.h"
#include "tpm_eventlog.h"
#include "tpm2-efi.h"

static phys_addr_t tcg2_event_log;
static phys_addr_t tcg2_event_log_first_entry;
static phys_addr_t tcg2_event_log_last_entry;
static size_t tcg2_event_log_size;
static bool tcg2_event_log_truncated;
static efi_tcg2_boot_service_capability_t bs_caps;
static bool old_caps;

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
	struct tcg_event_field *event_field;
	size_t event2_size, aligned;
	u32 tmp_size = 0;
	ssize_t ret = -EINVAL;

	event2_size = offsetof(struct tcg_pcr_event2, digests);

	aligned = PAGE_ALIGN(event2_size
			     + sizeof (struct tpm2_digest) * 10
			     + sizeof (struct tcg_event_field));

	event = early_memremap(event_log_entry_pa, aligned);
	if (!event)
		return -ENOMEM;

	if (event->count == 0) {
		ret = 0;
		goto err_unmap;
	}

	if (SIZE_MAX / event->count <= sizeof(struct tpm2_digest))
		goto err_unmap;

	tmp_size = event->count * sizeof(struct tpm2_digest);
	if (SIZE_MAX - event2_size <= tmp_size)
		goto err_unmap;

	event2_size += tmp_size;
	tmp_size = sizeof (event_field->event_size);
	if (SIZE_MAX - event2_size <= tmp_size)
		goto err_unmap;

	if (event->count > 10) {
		early_memunmap(event, aligned);
		aligned = PAGE_ALIGN(event2_size + tmp_size);
		event = early_memremap(event_log_entry_pa, aligned);
		if (!event)
			return -ENOMEM;
	}

	event_field = (struct tcg_event_field *)((u8 *)event + event2_size);
	event2_size += tmp_size;
	if (SIZE_MAX / event_field->event_size >= SIZE_MAX - event2_size)
		goto err_unmap;

	event2_size += event_field->event_size;
	if (SIZE_MAX >> 1 < event2_size)
		goto err_unmap;

	ret = event2_size;
err_unmap:
	early_memunmap(event, aligned);
	return ret;
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

static efi_status_t __init
tpm2_get_caps(efi_tcg2_protocol_t *tcg2)
{
	efi_status_t status;

	memset(&bs_caps, '\0', sizeof (bs_caps));
	bs_caps.size = (u8)sizeof(bs_caps);

	status = __efi_call_early(tcg2->get_capability, tcg2, &bs_caps);
	if (status != EFI_SUCCESS) {
		pr_err("EFI TPM2->GetCapability failed\n");
		return status;
	}

	if (bs_caps.structure_version.major == 1 &&
	    bs_caps.structure_version.minor == 0)
		old_caps = true;
	else
		old_caps = false;

	return EFI_SUCCESS;
}

bool
efi_tpm2_present(void)
{
	if (old_caps) {
		tree_boot_service_capability_t *caps_1_0;

		caps_1_0 = (tree_boot_service_capability_t *)&bs_caps;
		if (caps_1_0->tpm_present_flag)
			return true;
	} else {
		if (bs_caps.tpm_present_flag)
			return true;
	}

	return false;
}

static void
save_efi_tpm2_config_table(void)
{
	void *va;
	

}

void
efi_tpm2_init(void)
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
	if (status != EFI_SUCCESS)
		pr_info("No EFI TPM2 protocol installed\n");

	status = tpm2_get_caps(tcg2);
	if (status != EFI_SUCCESS)
		return;

	if (!efi_tpm2_present())
		return;

	status = __efi_call_early(tcg2->get_event_log, tcg2,
				  EFI_TCG2_EVENT_LOG_FORMAT_TCG_2,
				  &event_log_address,
				  &event_log_last_entry,
				  &event_log_truncated);
	if (status != EFI_SUCCESS)
		return;

	tcg2_event_log_truncated = event_log_truncated ? true : false;
	/* check if there's no tpm present */
	if (event_log_address == 0 &&
	    event_log_last_entry == 0 &&
	    event_log_truncated == 0)
		return;

	tcg2_event_log_last_entry = (phys_addr_t)event_log_last_entry;

	rc = tcg2_get_header_info(event_log_address);
	if (rc < 0)
		return;

	last_entry_size = tcg2_get_entry_size(event_log_last_entry);
	if (last_entry_size < 0)
		return;

	tcg2_event_log_size = (event_log_last_entry - event_log_address)
		+ last_entry_size;

	efi_mem_reserve(tcg2_event_log, tcg2_event_log_size);

	save_efi_tpm2_config_table();

	have_log = true;
	return;
}
