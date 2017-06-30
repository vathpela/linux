#ifndef _IA64_ASM_EFI_H
#define _IA64_ASM_EFI_H

struct efi_arch_priv {
	unsigned long sal_systab;
	unsigned long hcdp;
	unsigned long palo_phys;
};

#endif _IA64_ASM_EFI_H
