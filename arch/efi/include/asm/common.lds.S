/* SPDX-License-Identifier: GPL-2.0 */
#include <asm-generic/vmlinux.lds.h>

  .fini      : { *(.fini)    } =0x9090
  _etext = .;
  PROVIDE (etext = .);

  . = ALIGN(4096);
  _sdata = .;
  PROVIDE (sdata = .);

  RO_DATA(4096)

  .unprotected : { *(.unprotected) }
  . = ALIGN(4096);
  PROVIDE (_unprotected_end = .);

  . = ALIGN(4096);
  EXCEPTION_TABLE(0)

  BUG_TABLE

  .eml.setup.init : {
	__eml_setup_start = .;
	*(.eml.setup.init)
	__eml_setup_end = .;
  }
	
  .eml.help.init : {
	__eml_help_start = .;
	*(.eml.help.init)
	__eml_help_end = .;
  }
	
  .eml.postsetup.init : {
	__eml_postsetup_start = .;
	*(.eml.postsetup.init)
	__eml_postsetup_end = .;
  }
	
  .init.setup : {
	INIT_SETUP(0)
  }

  PERCPU_SECTION(32)
	
  .initcall.init : {
	INIT_CALLS
  }

  .con_initcall.init : {
	CON_INITCALL
  }

  .exitcall : {
	__exitcall_begin = .;
	*(.exitcall.exit)
	__exitcall_end = .;
  }

  .eml.exitcall : {
	__eml_exitcall_begin = .;
	*(.eml.exitcall.exit)
	__eml_exitcall_end = .;
  }

  . = ALIGN(4);
  .altinstructions : {
	__alt_instructions = .;
	*(.altinstructions)
	__alt_instructions_end = .;
  }
  .altinstr_replacement : { *(.altinstr_replacement) }
  /* .exit.text is discard at runtime, not link time, to deal with references
     from .altinstructions and .eh_frame */
  .exit.text : { EXIT_TEXT }
  .exit.data : { *(.exit.data) }

  .preinit_array : {
	__preinit_array_start = .;
	*(.preinit_array)
	__preinit_array_end = .;
  }
  .init_array : {
	__init_array_start = .;
	*(.init_array)
	__init_array_end = .;
  }
  .fini_array : {
	__fini_array_start = .;
	*(.fini_array)
	__fini_array_end = .;
  }

   . = ALIGN(4096);
  .init.ramfs : {
	INIT_RAM_FS
  }

