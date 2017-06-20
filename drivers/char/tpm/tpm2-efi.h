/*
 * tpm2-efi.h
 * Copyright 2017 Peter Jones <Peter Jones@trillian.uncooperative.org>
 *
 * Distributed under terms of the GPLv3 license.
 */

#ifndef __TPM2_EFI_H__
#define __TPM2_EFI_H__

typedef u32 efi_tcg2_event_log_bitmap_t;
typedef u32 efi_tcg2_event_algorithm_bitmap_t;
typedef struct {
	u8 major;
	u8 minor;
} efi_tcg2_version_t;

#define EFI_TCG2_BOOT_HASH_ALG_LIST_END	0x0
#define EFI_TCG2_BOOT_HASH_ALG_SHA1	0x01
#define EFI_TCG2_BOOT_HASH_ALG_SHA256	0x02
#define EFI_TCG2_BOOT_HASH_ALG_SHA384	0x04
#define EFI_TCG2_BOOT_HASH_ALG_SHA512	0x08
#define EFI_TCG2_BOOT_HASH_ALG_SM3_256	0x10
#define EFI_TCG2_BOOT_HASH_ALGORITHMS	5

struct efi_tcg2_protocol;

/*
 * This is not packed, as per the spec.
 */
typedef struct tree_boot_service_capability {
	u8 size;
	efi_tcg2_version_t structure_version;
	efi_tcg2_version_t protocol_version;
	u32 hash_algorithm_bitmap;
	efi_tcg2_event_log_bitmap_t supported_event_logs;
	efi_bool_t tpm_present_flag;
	u16 max_command_size;
	u16 max_response_size;
	u32 manufacturer_id;
	u32 number_of_pcr_banks;
} tree_boot_service_capability_t;

typedef struct efi_tcg2_boot_service_capability {
	u8 size;
	efi_tcg2_version_t structure_version;
	efi_tcg2_version_t protocol_version;
	efi_tcg2_event_algorithm_bitmap_t hash_algorithm_bitmap;
	efi_tcg2_event_log_bitmap_t supported_event_logs;
	efi_bool_t tpm_present_flag;
	u16 max_command_size;
	u16 max_response_size;
	u32 manufacturer_id;
	u32 number_of_pcr_banks;
	efi_tcg2_event_algorithm_bitmap_t active_pcr_banks;
} efi_tcg2_boot_service_capability_t;

extern efi_tcg2_boot_service_capability_t *tpm2_boot_service_capability;

typedef efi_status_t (*efi_tcg2_get_capability)(
	struct efi_tcg2_protocol *this,
	efi_tcg2_boot_service_capability_t *boot_service_cap);

#define EFI_TCG2_EVENT_LOG_FORMAT_TCG_1_2	0x1
#define EFI_TCG2_EVENT_LOG_FORMAT_TCG_2		0x2

typedef u32 efi_tcg2_event_log_format_t;

typedef efi_status_t (*efi_tcg2_get_event_log)(
	struct efi_tcg2_protocol *this,
	efi_tcg2_event_log_format_t event_log_format,
	efi_physical_addr_t *event_log_location,
	efi_physical_addr_t *event_log_last_entry,
	efi_bool_t *event_log_truncated);

typedef u32 tcg_pcrindex_t;
typedef u32 tcg_eventtype_t;

typedef struct {
	u32 header_size;
	u16 header_version;
	tcg_pcrindex_t pcr_index;
	tcg_eventtype_t event_type;
} efi_tcg2_event_header_t;

typedef struct {
	u32 size;
	efi_tcg2_event_header_t header;
	u8 event[];
} efi_tcg2_event_t;

#define EFI_TCG2_EXTEND_ONLY		0x01
#define EFI_TCG2_EXTEND_PE_COFF_IMAGE	0x10

typedef efi_status_t (*efi_tcg2_hash_log_extend_event)(
	struct efi_tcg2_protocol *this,
	u64 flags,
	efi_physical_addr_t data_to_hash,
	u64 data_to_hash_len,
	efi_tcg2_event_t *efi_tcg_event);

typedef efi_status_t (*efi_tcg2_submit_command)(
	struct efi_tcg2_protocol *this,
	u32 input_parameter_block_size,
	u8 *input_parameter_block,
	u32 output_parameter_block_size,
	u8 *output_parameter_block);

typedef efi_status_t (*efi_tcg2_get_active_pcr_banks)(
	struct efi_tcg2_protocol *this,
	u32 *active_pcr_banks);

typedef efi_status_t (*efi_tcg2_set_active_pcr_banks)(
	struct efi_tcg2_protocol *this,
	u32 active_pcr_banks);

typedef efi_status_t (*efi_tcg2_get_result_of_set_active_pcr_banks)(
	struct efi_tcg2_protocol *this,
	u32 *operation_present,
	u32 *response);

typedef struct {
	efi_tcg2_get_capability get_capability;
	efi_tcg2_get_event_log get_event_log;
	efi_tcg2_hash_log_extend_event hash_log_extend_event;
	efi_tcg2_submit_command submit_command;
	efi_tcg2_get_active_pcr_banks get_active_pcr_banks;
	efi_tcg2_set_active_pcr_banks set_active_pcr_banks;
	efi_tcg2_get_result_of_set_active_pcr_banks
					get_result_of_set_active_pcr_banks;
} efi_tcg2_protocol_t;

typedef struct {
	u16 algorithm_id;
	u8 digest[];
} tpmt_ha_t;

typedef struct {
	u64 version;
	u64 number_of_events;
	// struct tcg_pcr_event2 event[];
} efi_tcg2_final_events_table_t;

typedef struct {
	u16 algorithm_id;
	u16 digest_size;
} tcg_efi_spec_id_event_algorithm_size_t;

#define TCG_EFI_SPEC_ID_UINTN_32BITS	0x01
#define TCG_EFI_SPEC_ID_UINTN_64BITS	0x02

#endif /* !__TPM2_EFI_H__ */
