// SPDX-License-Identifier: GPL-2.0
#ifndef ARCH_PERF_RISCV_TRAP_TYPES_H
#define ARCH_PERF_RISCV_TRAP_TYPES_H

/* Exception cause high bit - is an interrupt if set */
#define CAUSE_IRQ_FLAG		(_AC(1, UL) << (__riscv_xlen - 1))

/* Interrupt causes (minus the high bit) */
#define IRQ_S_SOFT 1
#define IRQ_VS_SOFT 2
#define IRQ_M_SOFT 3
#define IRQ_S_TIMER 5
#define IRQ_VS_TIMER 6
#define IRQ_M_TIMER 7
#define IRQ_S_EXT 9
#define IRQ_VS_EXT 10
#define IRQ_M_EXT 11
#define IRQ_S_GEXT 12
#define IRQ_PMU_OVF 13

/* Exception causes */
#define EXC_INST_MISALIGNED 0
#define EXC_INST_ACCESS 1
#define EXC_INST_ILLEGAL 2
#define EXC_BREAKPOINT 3
#define EXC_LOAD_MISALIGNED 4
#define EXC_LOAD_ACCESS 5
#define EXC_STORE_MISALIGNED 6
#define EXC_STORE_ACCESS 7
#define EXC_SYSCALL 8
#define EXC_HYPERVISOR_SYSCALL 9
#define EXC_SUPERVISOR_SYSCALL 10
#define EXC_INST_PAGE_FAULT 12
#define EXC_LOAD_PAGE_FAULT 13
#define EXC_STORE_PAGE_FAULT 15
#define EXC_INST_GUEST_PAGE_FAULT 20
#define EXC_LOAD_GUEST_PAGE_FAULT 21
#define EXC_VIRTUAL_INST_FAULT 22
#define EXC_STORE_GUEST_PAGE_FAULT 23

#define TRAP(x) { x, #x }

#define kvm_riscv_trap_class \
	TRAP(IRQ_S_SOFT), TRAP(IRQ_VS_SOFT), TRAP(IRQ_M_SOFT), \
	TRAP(IRQ_S_TIMER), TRAP(IRQ_VS_TIMER), TRAP(IRQ_M_TIMER), \
	TRAP(IRQ_S_EXT), TRAP(IRQ_VS_EXT), TRAP(IRQ_M_EXT), \
	TRAP(IRQ_S_GEXT), TRAP(IRQ_PMU_OVF), \
	TRAP(EXC_INST_MISALIGNED), TRAP(EXC_INST_ACCESS), TRAP(EXC_INST_ILLEGAL), \
	TRAP(EXC_BREAKPOINT), TRAP(EXC_LOAD_MISALIGNED), TRAP(EXC_LOAD_ACCESS), \
	TRAP(EXC_STORE_MISALIGNED), TRAP(EXC_STORE_ACCESS), TRAP(EXC_SYSCALL), \
	TRAP(EXC_HYPERVISOR_SYSCALL), TRAP(EXC_SUPERVISOR_SYSCALL), \
	TRAP(EXC_INST_PAGE_FAULT), TRAP(EXC_LOAD_PAGE_FAULT), \
	TRAP(EXC_STORE_PAGE_FAULT), TRAP(EXC_INST_GUEST_PAGE_FAULT), \
	TRAP(EXC_LOAD_GUEST_PAGE_FAULT), TRAP(EXC_VIRTUAL_INST_FAULT), \
	TRAP(EXC_STORE_GUEST_PAGE_FAULT)

#endif /* ARCH_PERF_RISCV_TRAP_TYPES_H */
