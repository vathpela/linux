/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __PARISC_SPECIAL_INSNS_H
#define __PARISC_SPECIAL_INSNS_H

#define lpa(va)	({					\
	unsigned long pa;				\
	__asm__ __volatile__(				\
		"copy %%r0,%0\n"			\
		"8:\tlpa %%r0(%1),%0\n"			\
		"9:\n"					\
		ASM_EXCEPTIONTABLE_ENTRY(8b, 9b,	\
				"or %%r0,%%r0,%%r0")	\
		: "=&r" (pa)				\
		: "r" (va)				\
		: "memory"				\
	);						\
	pa;						\
})

#define lpa_user(va)	({				\
	unsigned long pa;				\
	__asm__ __volatile__(				\
		"copy %%r0,%0\n"			\
		"8:\tlpa %%r0(%%sr3,%1),%0\n"		\
		"9:\n"					\
		ASM_EXCEPTIONTABLE_ENTRY(8b, 9b,	\
				"or %%r0,%%r0,%%r0")	\
		: "=&r" (pa)				\
		: "r" (va)				\
		: "memory"				\
	);						\
	pa;						\
})

/**
 * prober_user() - Probe user read access
 * @sr:		Space regster.
 * @va:		Virtual address.
 *
 * Return: Non-zero if address is accessible.
 *
 * Due to the way _PAGE_READ is handled in TLB entries, we need
 * a special check to determine whether a user address is accessible.
 * The ldb instruction does the initial access check. If it is
 * successful, the probe instruction checks user access rights.
 */
#define prober_user(sr, va)	({			\
	unsigned long read_allowed;			\
	__asm__ __volatile__(				\
		"copy %%r0,%0\n"			\
		"8:\tldb 0(%%sr%1,%2),%%r0\n"		\
		"\tproberi (%%sr%1,%2),%3,%0\n"		\
		"9:\n"					\
		ASM_EXCEPTIONTABLE_ENTRY(8b, 9b,	\
				"or %%r0,%%r0,%%r0")	\
		: "=&r" (read_allowed)			\
		: "i" (sr), "r" (va), "i" (PRIV_USER)	\
		: "memory"				\
	);						\
	read_allowed;					\
})

#define CR_EIEM 15	/* External Interrupt Enable Mask */
#define CR_CR16 16	/* CR16 Interval Timer */
#define CR_EIRR 23	/* External Interrupt Request Register */

#define mfctl(reg)	({		\
	unsigned long cr;		\
	__asm__ __volatile__(		\
		"mfctl %1,%0" :		\
		 "=r" (cr) : "i" (reg)	\
	);				\
	cr;				\
})

#define mtctl(gr, cr) \
	__asm__ __volatile__("mtctl %0,%1" \
		: /* no outputs */ \
		: "r" (gr), "i" (cr) : "memory")

#define get_eiem()	mfctl(CR_EIEM)
#define set_eiem(val)	mtctl(val, CR_EIEM)

#define mfsp(reg)	({		\
	unsigned long cr;		\
	__asm__ __volatile__(		\
		"mfsp %%sr%1,%0"	\
		: "=r" (cr) : "i"(reg)	\
	);				\
	cr;				\
})

#define mtsp(val, cr) \
	{ if (__builtin_constant_p(val) && ((val) == 0)) \
	 __asm__ __volatile__("mtsp %%r0,%0" : : "i" (cr) : "memory"); \
	else \
	 __asm__ __volatile__("mtsp %0,%1" \
		: /* no outputs */ \
		: "r" (val), "i" (cr) : "memory"); }

#endif /* __PARISC_SPECIAL_INSNS_H */
