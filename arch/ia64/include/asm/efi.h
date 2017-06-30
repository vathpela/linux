#ifndef _IA64_ASM_EFI_H
#define _IA64_ASM_EFI_H

struct efi_arch_priv {
	efi_config_table_info_t sal_systab;
	efi_config_table_info_t hcdp;
	efi_config_table_info_t palo;
};

#endif _IA64_ASM_EFI_H
