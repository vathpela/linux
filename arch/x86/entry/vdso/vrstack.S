/*
 * rstack.S
 * Copyright 2017 Peter Jones <pjones@redhat.com>
 */
#include <linux/linkage.h>

#if 0
	.text
	.code64
ENTRY(vdso_rstack_push)
	/* 0 - save some space to work */
	// push rax
	pushq %rax
	// stack is now: caller-ret,our-ret,caller-rax
	/* 1 - get our rstack pointer ready */
	// find the address of the rstack pointer
	movq vvar_vdso_rstack(%rip), %rax
	// read the rstack pointer
	movq (%rax), %r11
	/* 2 - get a new position on the rstack */
	// decrement the rstack pointer
	subq $8, %r11
	/* 3 - store the return pointer */
	// find our caller's return address
	movq 16(%rbp), %rax
	// save our caller's return address to the rstack
	movq %rax, (%r11)
	/* 4 - store the new rstack address */
	// save the new rstack position - after this don't care about r11 or rax
	movq %r11, (%rax)
	/* 5 - save /our/ return address */
	// stash vdso_rstack_push's return addr in %r11
	movq 8(%rbp), %r11
	// stash vdso_rstack_push's return address over the caller's return address
	movq %r11, 16(%rbp)
	// stack is now our-ret,our-ret,caller-rax
	/* 6 - fix the caller's registers */
	// pop our temp space
	popq %rax
	// stack is now our-ret,our-ret
	// pop vdso_rstack_push's return
	popq %rax
	// stack is now our-ret
	/* get out */
	ret
ENDPROC(vdso_rstack_push)
.previous

	.text
	.code64
ENTRY(vdso_rstack_pop)
	/* 0 - save some stuff */
	pushq %rax
	pushq %rdi
	// stack is now our-ret,caller-rax,caller-rdi
	/* 1 - get our rstack pointer ready */
	// find the address of the rstack pointer
	movq vvar_vdso_rstack(%rip), %rax
	// read the rstack pointer
	movq (%rax), %r11
	/* 2 - get our caller's new return */
	// read from the rstack into r11
	movq (%r11), %rdi
	/* 3 - pop the rstack */
	// update the rstack pointer
	addq $8, %r11
	// save the rstack pointer
	movq %r11, (%rax)
	/* 3 - fix the return addresses in our local call stack */
	// put the caller's new return back onto the stack
	movq %rdi, 16(%rbp)
	// stack is now caller-ret,caller-rax,caller-rdi
	/* 4 - fix our caller's registers */
	popq %rdi
	// stack is now caller-ret,caller-rax
	popq %rax
	// stack is now caller-ret
	/* 4 - return to our caller's caller */
	ret
ENDPROC(vdso_rstack_pop)
.previous
#else
	.text
	.code64
ENTRY(vdso_rstack_push)
	// stack is now: caller-ret
	/* 0 - save some space to work */
	// push rax
	pushq %rax
	// stack is now: caller-ret,caller-rax
	/* 1 - get our rstack pointer ready */
	// find the address of the rstack pointer
	movq vvar_vdso_rstack(%rip), %rax
	// read the rstack pointer
	movq (%rax), %r11
	/* 2 - get a new position on the rstack */
	// decrement the rstack pointer
	subq $8, %r11
	/* 3 - store the return pointer */
	// find our caller's return address
	movq 16(%rbp), %rax
	// save our caller's return address to the rstack
	movq %rax, (%r11)
	/* 4 - store the new rstack address */
	// save the new rstack position - after this don't care about r11 or rax
	movq %r11, (%rax)
	/* 5 - save /our/ return address */
	// stash vdso_rstack_push's return addr in %r11
	movq 8(%rbp), %r11
	// stash vdso_rstack_push's return address over the caller's return address
	movq %r11, 8(%rbp)
	// stack is now our-ret,caller-rax
	/* 6 - fix the caller's registers */
	// pop our temp space
	popq %rax
	// stack is now our-ret
	/* get out */
	ret
ENDPROC(vdso_rstack_push)
.previous

	.text
	.code64
ENTRY(vdso_rstack_pop)
	/* 0 - save some stuff */
	pushq %rax
	pushq %rdi
	// stack is now caller-rax,caller-rdi
	/* 1 - get our rstack pointer ready */
	// find the address of the rstack pointer
	movq vvar_vdso_rstack(%rip), %rax
	// read the rstack pointer
	movq (%rax), %rdi
	/* 2 - get our caller's new return */
	// read from the rstack into r11
	movq (%rdi), %r11
	/* 3 - pop the rstack */
	// update the rstack pointer
	addq $8, %rdi
	// save the rstack pointer
	movq %rdi, (%rax)
	/* 3 - fix our caller's registers */
	popq %rdi
	// stack is now caller-rax
	popq %rax
	// stack is now empty
	/* 4 - fix the return address in our local call stack */
	pushq %r11
	// stack is now caller-ret
	/* 5 - return to our caller's caller */
	ret
ENDPROC(vdso_rstack_pop)
.previous
#endif
