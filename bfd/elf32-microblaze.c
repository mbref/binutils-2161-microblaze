/* Xilinx MicroBlaze specific support for 32-bit ELF
   Copyright 1994, 1995, 1999 Free Software Foundation, Inc.

This file is part of BFD, the Binary File Descriptor library.

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.  */

/* This file is based on a preliminary RCE ELF ABI.  The
   information may not match the final RCE ELF ABI.   */

/*
 * Copyright (c) 2001 Xilinx, Inc.  All rights reserved. 
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that the above copyright notice and this paragraph are
 * duplicated in all such forms and that any documentation,
 * advertising materials, and other materials related to such
 * distribution and use acknowledge that the software was developed
 * by Xilinx, Inc.  The name of the Company may not be used to endorse 
 * or promote products derived from this software without specific prior 
 * written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 *
 *	Xilinx, Inc.
 */

int dbg = 0;

#include "bfd.h"
#include "sysdep.h"
#include "bfdlink.h"
#include "libbfd.h"
#include "elf-bfd.h"
#include "elf/microblaze.h"
#include <assert.h>

#define	USE_RELA	/* Only USE_REL is actually significant, but this is
                     here are a reminder... */
#define INST_WORD_SIZE 4

static void microblaze_elf_howto_init
  PARAMS ((void));
static reloc_howto_type * microblaze_elf_reloc_type_lookup
  PARAMS ((bfd *, bfd_reloc_code_real_type));
static bfd_boolean microblaze_elf_relocate_section
  PARAMS ((bfd *, struct bfd_link_info *, bfd *, asection *, bfd_byte *,
          Elf_Internal_Rela *, Elf_Internal_Sym *, asection **));
static bfd_boolean microblaze_elf_is_local_label_name
  PARAMS ((bfd *, const char *));
static void microblaze_elf_final_sdp 
  PARAMS (( struct bfd_link_info * ));
static void
microblaze_adjust_debug_loc (bfd *, asection *, struct bfd_link_info *, bfd_vma *, int);
static bfd_boolean 
microblaze_elf_finish_dynamic_symbol 
  PARAMS ((bfd *, struct bfd_link_info *, struct elf_link_hash_entry *,
          Elf_Internal_Sym *sym));
static bfd_boolean 
microblaze_elf_size_dynamic_sections PARAMS((bfd *, struct bfd_link_info *));
static bfd_boolean 
microblaze_elf_finish_dynamic_sections PARAMS((bfd *, struct bfd_link_info *));
static bfd_boolean 
create_got_section PARAMS((bfd *, struct bfd_link_info *));

static int ro_small_data_pointer = 0;
static int rw_small_data_pointer = 0;


static reloc_howto_type * microblaze_elf_howto_table [(int) R_MICROBLAZE_max];

static reloc_howto_type microblaze_elf_howto_raw[] =
{
   /* This reloc does nothing.  */
   HOWTO (R_MICROBLAZE_NONE,		/* type */
          0,			/* rightshift */
          2,			/* size (0 = byte, 1 = short, 2 = long) */
          32,			/* bitsize */
          FALSE,			/* pc_relative */
          0,			/* bitpos */
          complain_overflow_bitfield,  /* complain_on_overflow */
          NULL,                  /* special_function */
          "R_MICROBLAZE_NONE", 	/* name */
          FALSE,			/* partial_inplace */
          0,			/* src_mask */
          0,			/* dst_mask */
          FALSE),		/* pcrel_offset */

   /* A standard 32 bit relocation.  */
   HOWTO (R_MICROBLAZE_32,     	/* type */
          0,			/* rightshift */
          2,			/* size (0 = byte, 1 = short, 2 = long) */
          32,			/* bitsize */
          FALSE,			/* pc_relative */
          0,			/* bitpos */
          complain_overflow_bitfield, /* complain_on_overflow */
          bfd_elf_generic_reloc,	/* special_function */
          "R_MICROBLAZE_32",   	/* name *//* For compatability with coff/pe port.  */
          FALSE,			/* partial_inplace */
          0,			/* src_mask */
          0xffffffff,		/* dst_mask */
          FALSE), 		/* pcrel_offset */

   /* A standard PCREL 32 bit relocation.  */
   HOWTO (R_MICROBLAZE_32_PCREL,     	/* type */
          0,			/* rightshift */
          2,			/* size (0 = byte, 1 = short, 2 = long) */
          32,			/* bitsize */
          TRUE,			/* pc_relative */
          0,			/* bitpos */
          complain_overflow_bitfield, /* complain_on_overflow */
          bfd_elf_generic_reloc,	/* special_function */
          "R_MICROBLAZE_32_PCREL",   	/* name *//* For compatability with coff/pe port.  */
          TRUE,			/* partial_inplace */
          0,			/* src_mask */
          0xffffffff,		/* dst_mask */
          TRUE), 		/* pcrel_offset */

   /* A 64 bit PCREL relocation.  Table-entry not really used */
   HOWTO (R_MICROBLAZE_64_PCREL,   	/* type */
          0,			/* rightshift */
          2,			/* size (0 = byte, 1 = short, 2 = long) */
          16,			/* bitsize */
          TRUE,			/* pc_relative */
          0,			/* bitpos */
          complain_overflow_dont, /* complain_on_overflow */
          bfd_elf_generic_reloc,	/* special_function */
          "R_MICROBLAZE_64_PCREL", 	/* name *//* For compatability with coff/pe port.  */
          FALSE,			/* partial_inplace */
          0,			/* src_mask */
          0x0000ffff,		/* dst_mask */
          TRUE), 		/* pcrel_offset */

   /* The low half of a PCREL 32 bit relocation.  */
   HOWTO (R_MICROBLAZE_32_PCREL_LO,   	/* type */
          0,			/* rightshift */
          2,			/* size (0 = byte, 1 = short, 2 = long) */
          16,			/* bitsize */
          TRUE,			/* pc_relative */
          0,			/* bitpos */
          complain_overflow_signed, /* complain_on_overflow */
          bfd_elf_generic_reloc,	/* special_function */
          "R_MICROBLAZE_32_PCREL_LO", 	/* name *//* For compatability with coff/pe port.  */
          FALSE,			/* partial_inplace */
          0,			/* src_mask */
          0x0000ffff,		/* dst_mask */
          TRUE), 		/* pcrel_offset */

   /* A 64 bit relocation.  Table entry not really used */
   HOWTO (R_MICROBLAZE_64,     	/* type */
          0,			/* rightshift */
          2,			/* size (0 = byte, 1 = short, 2 = long) */
          16,			/* bitsize */
          FALSE,			/* pc_relative */
          0,			/* bitpos */
          complain_overflow_dont, /* complain_on_overflow */
          bfd_elf_generic_reloc,	/* special_function */
          "R_MICROBLAZE_64",   	/* name *//* For compatability with coff/pe port.  */
          FALSE,			/* partial_inplace */
          0,			/* src_mask */
          0x0000ffff,		/* dst_mask */
          FALSE), 		/* pcrel_offset */

   /* The low half of a 32 bit relocation.  */
   HOWTO (R_MICROBLAZE_32_LO,   	/* type */
          0,			/* rightshift */
          2,			/* size (0 = byte, 1 = short, 2 = long) */
          16,			/* bitsize */
          FALSE,			/* pc_relative */
          0,			/* bitpos */
          complain_overflow_signed, /* complain_on_overflow */
          bfd_elf_generic_reloc,	/* special_function */
          "R_MICROBLAZE_32_LO", 	/* name *//* For compatability with coff/pe port.  */
          FALSE,			/* partial_inplace */
          0,			/* src_mask */
          0x0000ffff,		/* dst_mask */
          FALSE), 		/* pcrel_offset */

   /* Read-only small data section relocation */
   HOWTO (R_MICROBLAZE_SRO32,     	/* type */
          0,			/* rightshift */
          2,			/* size (0 = byte, 1 = short, 2 = long) */
          16,			/* bitsize */
          FALSE,			/* pc_relative */
          0,			/* bitpos */
          complain_overflow_bitfield, /* complain_on_overflow */
          bfd_elf_generic_reloc,	/* special_function */
          "R_MICROBLAZE_SRO32",   	/* name *//* For compatability with coff/pe port.  */
          FALSE,			/* partial_inplace */
          0,			/* src_mask */
          0x0000ffff,		/* dst_mask */
          FALSE), 		/* pcrel_offset */

   /* Read-write small data area relocation */
   HOWTO (R_MICROBLAZE_SRW32,     	/* type */
          0,			/* rightshift */
          2,			/* size (0 = byte, 1 = short, 2 = long) */
          16,			/* bitsize */
          FALSE,			/* pc_relative */
          0,			/* bitpos */
          complain_overflow_bitfield, /* complain_on_overflow */
          bfd_elf_generic_reloc,	/* special_function */
          "R_MICROBLAZE_SRW32",   	/* name *//* For compatability with coff/pe port.  */
          FALSE,			/* partial_inplace */
          0,			/* src_mask */
          0x0000ffff,		/* dst_mask */
          FALSE), 		/* pcrel_offset */

   /* This reloc does nothing.  Used for relax */
   HOWTO (R_MICROBLAZE_64_NONE,		/* type */
          0,			/* rightshift */
          2,			/* size (0 = byte, 1 = short, 2 = long) */
          32,			/* bitsize */
          TRUE,			/* pc_relative */
          0,			/* bitpos */
          complain_overflow_bitfield,  /* complain_on_overflow */
          NULL,                  /* special_function */
          "R_MICROBLAZE_64_NONE",/* name */
          FALSE,			/* partial_inplace */
          0,			/* src_mask */
          0,			/* dst_mask */
          FALSE),		/* pcrel_offset */
   
   /* Symbol Op Symbol relocation */
   HOWTO (R_MICROBLAZE_32_SYM_OP_SYM,     	/* type */
          0,			/* rightshift */
          2,			/* size (0 = byte, 1 = short, 2 = long) */
          32,			/* bitsize */
          FALSE,			/* pc_relative */
          0,			/* bitpos */
          complain_overflow_bitfield, /* complain_on_overflow */
          bfd_elf_generic_reloc,	/* special_function */
          "R_MICROBLAZE_32_SYM_OP_SYM",   	/* name *//* For compatability with coff/pe port.  */
          FALSE,			/* partial_inplace */
          0,			/* src_mask */
          0xffffffff,		/* dst_mask */
          FALSE), 		/* pcrel_offset */

   /* GNU extension to record C++ vtable hierarchy */
   HOWTO (R_MICROBLAZE_GNU_VTINHERIT, /* type */
          0,                     /* rightshift */
          2,                     /* size (0 = byte, 1 = short, 2 = long) */
          0,                     /* bitsize */
          FALSE,                 /* pc_relative */
          0,                     /* bitpos */
          complain_overflow_dont, /* complain_on_overflow */
          NULL,                  /* special_function */
          "R_MICROBLAZE_GNU_VTINHERIT", /* name */
          FALSE,                 /* partial_inplace */
          0,                     /* src_mask */
          0,                     /* dst_mask */
          FALSE),                /* pcrel_offset */
   
   /* GNU extension to record C++ vtable member usage */
   HOWTO (R_MICROBLAZE_GNU_VTENTRY,   /* type */
          0,                     /* rightshift */
          2,                     /* size (0 = byte, 1 = short, 2 = long) */
          0,                     /* bitsize */
          FALSE,                 /* pc_relative */
          0,                     /* bitpos */
          complain_overflow_dont,/* complain_on_overflow */
          _bfd_elf_rel_vtable_reloc_fn,  /* special_function */
          "R_MICROBLAZE_GNU_VTENTRY", /* name */
          FALSE,                 /* partial_inplace */
          0,                     /* src_mask */
          0,                     /* dst_mask */
          FALSE),                /* pcrel_offset */

   /* A 64 bit GOTPC relocation.  Table-entry not really used */
   HOWTO (R_MICROBLAZE_GOTPC_64,   	/* type */
          0,			/* rightshift */
          2,			/* size (0 = byte, 1 = short, 2 = long) */
          16,			/* bitsize */
          TRUE,			/* pc_relative */
          0,			/* bitpos */
          complain_overflow_dont, /* complain_on_overflow */
          bfd_elf_generic_reloc,	/* special_function */
          "R_MICROBLAZE_GOTPC_64", 	/* name *//* For compatability with coff/pe port.  */
          FALSE,			/* partial_inplace */
          0,			/* src_mask */
          0x0000ffff,		/* dst_mask */
          TRUE), 		/* pcrel_offset */

   /* A 64 bit GOT relocation.  Table-entry not really used */
   HOWTO (R_MICROBLAZE_GOT_64,   	/* type */
          0,			/* rightshift */
          2,			/* size (0 = byte, 1 = short, 2 = long) */
          16,			/* bitsize */
          FALSE,			/* pc_relative */
          0,			/* bitpos */
          complain_overflow_dont, /* complain_on_overflow */
          bfd_elf_generic_reloc,	/* special_function */
          "R_MICROBLAZE_GOT_64", 	/* name *//* For compatability with coff/pe port.  */
          FALSE,			/* partial_inplace */
          0,			/* src_mask */
          0x0000ffff,		/* dst_mask */
          FALSE), 		/* pcrel_offset */

   /* A 64 bit PLT relocation.  Table-entry not really used */
   HOWTO (R_MICROBLAZE_PLT_64,   	/* type */
          0,			/* rightshift */
          2,			/* size (0 = byte, 1 = short, 2 = long) */
          16,			/* bitsize */
          TRUE,			/* pc_relative */
          0,			/* bitpos */
          complain_overflow_dont, /* complain_on_overflow */
          bfd_elf_generic_reloc,	/* special_function */
          "R_MICROBLAZE_PLT_64", 	/* name *//* For compatability with coff/pe port.  */
          FALSE,			/* partial_inplace */
          0,			/* src_mask */
          0x0000ffff,		/* dst_mask */
          TRUE), 		/* pcrel_offset */

   /*  Table-entry not really used */
   HOWTO (R_MICROBLAZE_REL,   	/* type */
          0,			/* rightshift */
          2,			/* size (0 = byte, 1 = short, 2 = long) */
          16,			/* bitsize */
          TRUE,			/* pc_relative */
          0,			/* bitpos */
          complain_overflow_dont, /* complain_on_overflow */
          bfd_elf_generic_reloc,	/* special_function */
          "R_MICROBLAZE_REL", 	/* name *//* For compatability with coff/pe port.  */
          FALSE,			/* partial_inplace */
          0,			/* src_mask */
          0x0000ffff,		/* dst_mask */
          TRUE), 		/* pcrel_offset */

   /*  Table-entry not really used */
   HOWTO (R_MICROBLAZE_JUMP_SLOT,   	/* type */
          0,			/* rightshift */
          2,			/* size (0 = byte, 1 = short, 2 = long) */
          16,			/* bitsize */
          TRUE,			/* pc_relative */
          0,			/* bitpos */
          complain_overflow_dont, /* complain_on_overflow */
          bfd_elf_generic_reloc,	/* special_function */
          "R_MICROBLAZE_JUMP_SLOT", 	/* name *//* For compatability with coff/pe port.  */
          FALSE,			/* partial_inplace */
          0,			/* src_mask */
          0x0000ffff,		/* dst_mask */
          TRUE), 		/* pcrel_offset */

   /*  Table-entry not really used */
   HOWTO (R_MICROBLAZE_GLOB_DAT,   	/* type */
          0,			/* rightshift */
          2,			/* size (0 = byte, 1 = short, 2 = long) */
          16,			/* bitsize */
          TRUE,			/* pc_relative */
          0,			/* bitpos */
          complain_overflow_dont, /* complain_on_overflow */
          bfd_elf_generic_reloc,	/* special_function */
          "R_MICROBLAZE_GLOB_DAT", 	/* name *//* For compatability with coff/pe port.  */
          FALSE,			/* partial_inplace */
          0,			/* src_mask */
          0x0000ffff,		/* dst_mask */
          TRUE), 		/* pcrel_offset */

   /* A 64 bit GOT relative relocation.  Table-entry not really used */
   HOWTO (R_MICROBLAZE_GOTOFF_64,   	/* type */
          0,			/* rightshift */
          2,			/* size (0 = byte, 1 = short, 2 = long) */
          16,			/* bitsize */
          FALSE,			/* pc_relative */
          0,			/* bitpos */
          complain_overflow_dont, /* complain_on_overflow */
          bfd_elf_generic_reloc,	/* special_function */
          "R_MICROBLAZE_GOTOFF_64", 	/* name *//* For compatability with coff/pe port.  */
          FALSE,			/* partial_inplace */
          0,			/* src_mask */
          0x0000ffff,		/* dst_mask */
          FALSE), 		/* pcrel_offset */

   /* A 32 bit GOT relative relocation.  Table-entry not really used */
   HOWTO (R_MICROBLAZE_GOTOFF_32,   	/* type */
          0,			/* rightshift */
          2,			/* size (0 = byte, 1 = short, 2 = long) */
          16,			/* bitsize */
          FALSE,			/* pc_relative */
          0,			/* bitpos */
          complain_overflow_dont, /* complain_on_overflow */
          bfd_elf_generic_reloc,	/* special_function */
          "R_MICROBLAZE_GOTOFF_32", 	/* name *//* For compatability with coff/pe port.  */
          FALSE,			/* partial_inplace */
          0,			/* src_mask */
          0x0000ffff,		/* dst_mask */
          FALSE), 		/* pcrel_offset */

   /* COPY relocation.  Table-entry not really used */
   HOWTO (R_MICROBLAZE_COPY,   	/* type */
          0,			/* rightshift */
          2,			/* size (0 = byte, 1 = short, 2 = long) */
          16,			/* bitsize */
          FALSE,			/* pc_relative */
          0,			/* bitpos */
          complain_overflow_dont, /* complain_on_overflow */
          bfd_elf_generic_reloc,	/* special_function */
          "R_MICROBLAZE_COPY", 	/* name *//* For compatability with coff/pe port.  */
          FALSE,			/* partial_inplace */
          0,			/* src_mask */
          0x0000ffff,		/* dst_mask */
          FALSE), 		/* pcrel_offset */

};

#ifndef NUM_ELEM
#define NUM_ELEM(a) (sizeof (a) / sizeof (a)[0])
#endif

/* Initialize the microblaze_elf_howto_table, so that linear accesses can be done.  */
static void
microblaze_elf_howto_init ()
{
   unsigned int i;

   for (i = NUM_ELEM (microblaze_elf_howto_raw); i--;)
   {
      unsigned int type;
      
      type = microblaze_elf_howto_raw[i].type;
      
      BFD_ASSERT (type < NUM_ELEM (microblaze_elf_howto_table));
      
      microblaze_elf_howto_table [type] = & microblaze_elf_howto_raw [i];
   }
}


static reloc_howto_type *
microblaze_elf_reloc_type_lookup (abfd, code)
   bfd * abfd ATTRIBUTE_UNUSED;
bfd_reloc_code_real_type code;
{
   enum elf_microblaze_reloc_type microblaze_reloc = R_MICROBLAZE_NONE;

   switch (code)
   {
   case BFD_RELOC_NONE:		    microblaze_reloc = R_MICROBLAZE_NONE; break;
   case BFD_RELOC_MICROBLAZE_64_NONE:	    microblaze_reloc = R_MICROBLAZE_64_NONE; break;
   case BFD_RELOC_32:                      microblaze_reloc = R_MICROBLAZE_32; break;
      /* RVA is treated the same as 32 */
   case BFD_RELOC_RVA:                     microblaze_reloc = R_MICROBLAZE_32; break;
   case BFD_RELOC_32_PCREL:                microblaze_reloc = R_MICROBLAZE_32_PCREL; break;
   case BFD_RELOC_64_PCREL:                microblaze_reloc = R_MICROBLAZE_64_PCREL; break;
   case BFD_RELOC_MICROBLAZE_32_LO_PCREL:  microblaze_reloc = R_MICROBLAZE_32_PCREL_LO; break;
   case BFD_RELOC_64:                      microblaze_reloc = R_MICROBLAZE_64; break;
   case BFD_RELOC_MICROBLAZE_32_LO:        microblaze_reloc = R_MICROBLAZE_32_LO; break;
   case BFD_RELOC_MICROBLAZE_32_ROSDA:     microblaze_reloc = R_MICROBLAZE_SRO32; break;
   case BFD_RELOC_MICROBLAZE_32_RWSDA:     microblaze_reloc = R_MICROBLAZE_SRW32; break;
   case BFD_RELOC_MICROBLAZE_32_SYM_OP_SYM:     microblaze_reloc = R_MICROBLAZE_32_SYM_OP_SYM; break;
   case BFD_RELOC_VTABLE_INHERIT:           microblaze_reloc = R_MICROBLAZE_GNU_VTINHERIT; break;
   case BFD_RELOC_VTABLE_ENTRY:             microblaze_reloc = R_MICROBLAZE_GNU_VTENTRY; break;
   case BFD_RELOC_MICROBLAZE_64_GOTPC:     microblaze_reloc = R_MICROBLAZE_GOTPC_64; break;
   case BFD_RELOC_MICROBLAZE_64_GOT:       microblaze_reloc = R_MICROBLAZE_GOT_64; break;
   case BFD_RELOC_MICROBLAZE_64_PLT:       microblaze_reloc = R_MICROBLAZE_PLT_64; break;
   case BFD_RELOC_MICROBLAZE_64_GOTOFF:    microblaze_reloc = R_MICROBLAZE_GOTOFF_64; break;
   case BFD_RELOC_MICROBLAZE_32_GOTOFF:    microblaze_reloc = R_MICROBLAZE_GOTOFF_32; break;
   case BFD_RELOC_MICROBLAZE_COPY:         microblaze_reloc = R_MICROBLAZE_COPY; break;
  default:
      return (reloc_howto_type *)NULL;
   }

   if (! microblaze_elf_howto_table [R_MICROBLAZE_32])	/* Initialize howto table if needed */
      microblaze_elf_howto_init ();

   return microblaze_elf_howto_table [(int) microblaze_reloc];
};

/* Set the howto pointer for a RCE ELF reloc.  */
static void
microblaze_elf_info_to_howto (bfd * abfd ATTRIBUTE_UNUSED,
			      arelent * cache_ptr,
			      Elf_Internal_Rela * dst)
{
   if (! microblaze_elf_howto_table [R_MICROBLAZE_32])	/* Initialize howto table if needed */
      microblaze_elf_howto_init ();

   BFD_ASSERT (ELF32_R_TYPE (dst->r_info) < (unsigned int) R_MICROBLAZE_max);
  
   cache_ptr->howto = microblaze_elf_howto_table [ELF32_R_TYPE (dst->r_info)];
}

/* Microblaze ELF local labels start with 'L.' or '$L', not '.L'.  */

/*ARGSUSED*/
static bfd_boolean
microblaze_elf_is_local_label_name (bfd *abfd, const char *name)
{
   if (name[0] == 'L' && name[1] == '.')
      return TRUE;

   if (name[0] == '$' && name[1] == 'L')
      return TRUE;

   /* With gcc, the labels go back to starting with '.', so we accept
      the generic ELF local label syntax as well.  */
   return _bfd_elf_is_local_label_name (abfd, name);
}

/* The microblaze linker (like many others) needs to keep track of
   the number of relocs that it decides to copy as dynamic relocs in
   check_relocs for each symbol. This is so that it can later discard
   them if they are found to be unnecessary.  We store the information
   in a field extending the regular ELF linker hash table.  */

struct elf32_mb_dyn_relocs
{
  struct elf32_mb_dyn_relocs *next;

  /* The input section of the reloc.  */
  asection *sec;

  /* Total number of relocs copied for the input section.  */
  bfd_size_type count;

  /* Number of pc-relative relocs copied for the input section.  */
  bfd_size_type pc_count;
};

/* ELF linker hash entry.  */

struct elf32_mb_link_hash_entry
{
  struct elf_link_hash_entry elf;

  /* Track dynamic relocs copied for this symbol.  */
  struct elf32_mb_dyn_relocs *dyn_relocs;

};

#define elf32_mb_hash_entry(ent) ((struct elf32_mb_link_hash_entry *)(ent))

/* ELF linker hash table.  */

struct elf32_mb_link_hash_table
{
  struct elf_link_hash_table elf;

  /* Short-cuts to get to dynamic linker sections.  */
  asection *sgot;
  asection *sgotplt;
  asection *srelgot;
  asection *splt;
  asection *srelplt;
  asection *sdynbss;
  asection *srelbss;

  /* Small local sym to section mapping cache.  */
  struct sym_sec_cache sym_sec;
};

/* Get the ELF linker hash table from a link_info structure.  */

#define elf32_mb_hash_table(p) \
  ((struct elf32_mb_link_hash_table *) ((p)->hash))

/* Create an entry in a microblaze ELF linker hash table.  */

static struct bfd_hash_entry *
link_hash_newfunc (struct bfd_hash_entry *entry,
     struct bfd_hash_table *table,
     const char *string)
{
  /* Allocate the structure if it has not already been allocated by a
     subclass.  */
  if (entry == NULL)
    {
      entry = bfd_hash_allocate (table,
				 sizeof (struct elf32_mb_link_hash_entry));
      if (entry == NULL)
	return entry;
    }

  /* Call the allocation method of the superclass.  */
  entry = _bfd_elf_link_hash_newfunc (entry, table, string);
  if (entry != NULL)
    {
      struct elf32_mb_link_hash_entry *eh;

      eh = (struct elf32_mb_link_hash_entry *) entry;
      eh->dyn_relocs = NULL;
    }

  return entry;
}

/* Create a mb ELF linker hash table.  */

static struct bfd_link_hash_table *
microblaze_elf_link_hash_table_create (bfd *abfd)
{
  struct elf32_mb_link_hash_table *ret;
  bfd_size_type amt = sizeof (struct elf32_mb_link_hash_table);

  ret = (struct elf32_mb_link_hash_table *) bfd_zmalloc (amt);
  if (ret == NULL)
    return NULL;

  if (! _bfd_elf_link_hash_table_init (&ret->elf, abfd, link_hash_newfunc))
    {
      free (ret);
      return NULL;
    }

  return &ret->elf.root;
}


/* This code is taken from elf32-m32r.c
   There is some attempt to make this function usable for many architectures,
   both USE_REL and USE_RELA ['twould be nice if such a critter existed],
   if only to serve as a learning tool.

   The RELOCATE_SECTION function is called by the new ELF backend linker
   to handle the relocations for a section.

   The relocs are always passed as Rela structures; if the section
   actually uses Rel structures, the r_addend field will always be
   zero.

   This function is responsible for adjust the section contents as
   necessary, and (if using Rela relocs and generating a
   relocatable output file) adjusting the reloc addend as
   necessary.

   This function does not have to worry about setting the reloc
   address or the reloc symbol index.

   LOCAL_SYMS is a pointer to the swapped in local symbols.

   LOCAL_SECTIONS is an array giving the section in the input file
   corresponding to the st_shndx field of each local symbol.

   The global hash table entry for the global symbols can be found
   via elf_sym_hashes (input_bfd).

   When generating relocatable output, this function must handle
   STB_LOCAL/STT_SECTION symbols specially.  The output symbol is
   going to be the section symbol corresponding to the output
   section, which means that the addend must be adjusted
   accordingly.  */

static bfd_boolean
microblaze_elf_relocate_section (bfd *output_bfd,
			         struct bfd_link_info *info,
			         bfd *input_bfd,
			         asection *input_section,
			         bfd_byte *contents,
			         Elf_Internal_Rela *relocs,
			         Elf_Internal_Sym *local_syms,
			         asection **local_sections)
{
   struct elf32_mb_link_hash_table *htab;
   Elf_Internal_Shdr *symtab_hdr = &elf_tdata (input_bfd)->symtab_hdr;
   struct elf_link_hash_entry **sym_hashes = elf_sym_hashes (input_bfd);
   Elf_Internal_Rela *rel, *relend;
   int endian = !bfd_little_endian (output_bfd) * 2;

   /* Assume success.  */
   bfd_boolean ret = TRUE;
   asection *sreloc;
   bfd_vma *local_got_offsets;

   if (!microblaze_elf_howto_table[R_MICROBLAZE_max-1])
      microblaze_elf_howto_init();

   htab = elf32_mb_hash_table (info);
   local_got_offsets = elf_local_got_offsets (input_bfd);

   sreloc = elf_section_data (input_section)->sreloc;

   rel = relocs;
   relend = relocs + input_section->reloc_count;
   for (; rel < relend; rel++)
   {
      int r_type;
      reloc_howto_type *howto;
      unsigned long r_symndx;
      bfd_vma addend = rel->r_addend;
      bfd_vma offset = rel->r_offset;
      struct elf_link_hash_entry *h;
      Elf_Internal_Sym *sym;
      asection *sec;
      const char *sym_name;
      bfd_reloc_status_type r = bfd_reloc_ok;
      const char *errmsg = NULL;
      bfd_boolean unresolved_reloc = FALSE;

      h = NULL;
      r_type = ELF32_R_TYPE (rel->r_info);
      if (r_type < 0 || r_type >= (int) R_MICROBLAZE_max)
      {
         (*_bfd_error_handler) (_("%s: unknown relocation type %d"),
                                bfd_get_filename (input_bfd),
                                (int) r_type);
         bfd_set_error (bfd_error_bad_value);
         ret = FALSE;
         continue;
      }

      howto = microblaze_elf_howto_table[r_type];
      r_symndx = ELF32_R_SYM (rel->r_info);

      if (info->relocatable)
      {
         /* This is a relocatable link.  We don't have to change
            anything, unless the reloc is against a section symbol,
            in which case we have to adjust according to where the
            section symbol winds up in the output section.  */
         sec = NULL;
         if (r_symndx >= symtab_hdr->sh_info)
         {
            /* External symbol.  */
            continue;
         }

         /* Local symbol.  */
         sym = local_syms + r_symndx;
         sym_name = "<local symbol>";
         /* STT_SECTION: symbol is associated with a section.  */
         if (ELF_ST_TYPE (sym->st_info) != STT_SECTION)
         {
            /* Symbol isn't associated with a section.  Nothing to do.  */
            continue;
         }

         sec = local_sections[r_symndx];
         addend += sec->output_offset + sym->st_value;
#ifndef USE_REL
         /* This can't be done for USE_REL because it doesn't mean anything
            and elf_link_input_bfd asserts this stays zero.  */
         //rel->r_addend = addend;
#endif

#ifndef USE_REL
         /* Addends are stored with relocs.  We're done.  */
         continue;
#else /* USE_REL */
         /* If partial_inplace, we need to store any additional addend
            back in the section.  */
         if (! howto->partial_inplace)
            continue;
         /* ??? Here is a nice place to call a special_function
            like handler.  */
         r = _bfd_relocate_contents (howto, input_bfd,
                                     addend, contents + offset);
#endif /* USE_REL */
      }
      else
      {
         bfd_vma relocation;

         /* This is a final link.  */
         sym = NULL;
         sec = NULL;
	 unresolved_reloc = FALSE;

         if (r_symndx < symtab_hdr->sh_info)
         {
            /* Local symbol.  */
            sym = local_syms + r_symndx;
            sec = local_sections[r_symndx];
	    if (sec == 0) 
	      continue;
            sym_name = "<local symbol>";
	    relocation = _bfd_elf_rela_local_sym (output_bfd, sym, &sec, rel);
	    /* r_addend may have changed if the reference section was
	       a merge section.  */
	    addend = rel->r_addend;
         }
         else
         {
            /* External symbol. */
            bfd_boolean warned ATTRIBUTE_UNUSED;
      
            RELOC_FOR_GLOBAL_SYMBOL (info, input_bfd, input_section, rel,
                                     r_symndx, symtab_hdr, sym_hashes,
                                     h, sec, relocation,
                                     unresolved_reloc, warned);
            sym_name = h->root.root.string;
         }

         /* Sanity check the address.  */
         if (offset > bfd_get_section_limit (output_bfd, input_section))
         {
            r = bfd_reloc_outofrange;
            goto check_reloc;
         }

         switch ((int) r_type)
         {
         case (int) R_MICROBLAZE_SRO32 :
         {
            const char *name;

            BFD_ASSERT (sec != NULL);
            name = bfd_get_section_name (abfd, sec);

            if (strcmp (name, ".sdata2") == 0
                || strcmp (name, ".sbss2") == 0)
            {
               if (ro_small_data_pointer == 0)
                  microblaze_elf_final_sdp (info);
               if (ro_small_data_pointer == 0)
               {
                  ret = FALSE;
                  r = bfd_reloc_undefined;
                  goto check_reloc;
               }

               /* At this point `relocation' contains the object's
                  address.  */
               relocation -= ro_small_data_pointer;
               /* Now it contains the offset from _SDA2_BASE_.  */
               r = _bfd_final_link_relocate (howto, input_bfd, input_section,
                                             contents, offset,
                                             relocation, addend);
            }
            else
            {
               (*_bfd_error_handler) (_("%s: The target (%s) of an %s relocation is in the wrong section (%s)"),
                                      bfd_get_filename (input_bfd),
                                      sym_name,
                                      microblaze_elf_howto_table[(int) r_type]->name,
                                      bfd_get_section_name (abfd, sec));
               /*bfd_set_error (bfd_error_bad_value); ??? why? */
               ret = FALSE;
               continue;
            }
         }
         break;

         case (int) R_MICROBLAZE_SRW32 :
         {
            const char *name;

            BFD_ASSERT (sec != NULL);
            name = bfd_get_section_name (abfd, sec);

            if (strcmp (name, ".sdata") == 0
                || strcmp (name, ".sbss") == 0)
            {
               if (rw_small_data_pointer == 0)
                  microblaze_elf_final_sdp (info);
               if (rw_small_data_pointer == 0)
               {
                  ret = FALSE;
                  r = bfd_reloc_undefined;
                  goto check_reloc;
               }

               /* At this point `relocation' contains the object's
                  address.  */
               relocation -= rw_small_data_pointer;
               /* Now it contains the offset from _SDA_BASE_.  */
               r = _bfd_final_link_relocate (howto, input_bfd, input_section,
                                             contents, offset,
                                             relocation, addend);
            }
            else
            {
               (*_bfd_error_handler) (_("%s: The target (%s) of an %s relocation is in the wrong section (%s)"),
                                      bfd_get_filename (input_bfd),
                                      sym_name,
                                      microblaze_elf_howto_table[(int) r_type]->name,
                                      bfd_get_section_name (abfd, sec));
               /*bfd_set_error (bfd_error_bad_value); ??? why? */
               ret = FALSE;
               continue;
            }
         }
         break;

         case (int) R_MICROBLAZE_32_SYM_OP_SYM:
            break; // do nothing
            
         case (int) R_MICROBLAZE_GOTPC_64:
            relocation = htab->sgotplt->output_section->vma
                         + htab->sgotplt->output_offset;
            relocation -= (input_section->output_section->vma
                           + input_section->output_offset
                           + offset + INST_WORD_SIZE);
            relocation += addend;
            bfd_put_16 (input_bfd, (relocation >> 16) & 0xffff, contents + offset + endian);
            bfd_put_16 (input_bfd, relocation & 0xffff, contents + offset + endian + INST_WORD_SIZE);
            break;

         case (int) R_MICROBLAZE_PLT_64:
         {
            bfd_vma immediate;
            if (htab->splt != NULL && h != NULL && h->plt.offset != (bfd_vma) -1)
            {
               relocation = (htab->splt->output_section->vma
                            + htab->splt->output_offset
                            + h->plt.offset);
               unresolved_reloc = FALSE;
               immediate = relocation - (input_section->output_section->vma
                           + input_section->output_offset
                           + offset + INST_WORD_SIZE);
               bfd_put_16 (input_bfd, (immediate >> 16) & 0xffff, contents + offset + endian);
               bfd_put_16 (input_bfd, immediate & 0xffff, contents + offset + endian + INST_WORD_SIZE);
           }
           else
           {
               relocation -= (input_section->output_section->vma
                              + input_section->output_offset
                              + offset + INST_WORD_SIZE);
               immediate = relocation;
               bfd_put_16 (input_bfd, (immediate >> 16) & 0xffff, contents + offset + endian);
               bfd_put_16 (input_bfd, immediate & 0xffff, contents + offset + endian + INST_WORD_SIZE);
           }
           break;
        }

        case (int) R_MICROBLAZE_GOT_64:
        {
           if (htab->sgot == NULL)
              abort();
           if (h == NULL)
           {
              bfd_vma off;
              if (local_got_offsets == NULL)
                 abort ();
              off = local_got_offsets[r_symndx];
              /* The LSB indicates whether we've already created relocation */
              if (off & 1)
                 off &= ~1;
              else
              {
                 bfd_put_32 (output_bfd, relocation + addend,
                             htab->sgot->contents + off);
                     
                 if (info->shared)
                 {
                    Elf_Internal_Rela outrel;
                    bfd_byte *loc;
                    if (htab->srelgot == NULL)
                       abort ();
                    outrel.r_offset = (htab->sgot->output_section->vma
                                      + htab->sgot->output_offset + off);
                    outrel.r_info = ELF32_R_INFO (0, R_MICROBLAZE_REL);
                    outrel.r_addend = relocation + addend;
                    loc = htab->srelgot->contents;
                    loc += htab->srelgot->reloc_count++ * sizeof (Elf32_External_Rela);
                    bfd_elf32_swap_reloca_out (output_bfd, &outrel, loc);
                 }
                 local_got_offsets[r_symndx] |= 1;
              }
              relocation = htab->sgot->output_section->vma
                           + htab->sgot->output_offset + off
                           - htab->sgotplt->output_section->vma
                           - htab->sgotplt->output_offset;
              unresolved_reloc = FALSE;
           }
           else
           {
              if (htab->sgotplt != NULL && h != NULL && h->got.offset != (bfd_vma) -1)
              {
                 bfd_put_32 (output_bfd, relocation + addend,
                             htab->sgot->contents + h->got.offset);
                 relocation = htab->sgot->output_section->vma
                              + htab->sgot->output_offset + h->got.offset
                              - htab->sgotplt->output_section->vma
                              - htab->sgotplt->output_offset;
                 unresolved_reloc = FALSE;
              } else
                 abort(); /* ??? */
          }
          bfd_put_16 (input_bfd, (relocation >> 16) & 0xffff, contents + offset + endian);
          bfd_put_16 (input_bfd, relocation & 0xffff, contents + offset + endian + INST_WORD_SIZE);
          break;
        }
	 
        case (int) R_MICROBLAZE_GOTOFF_64:
        {
          bfd_vma immediate;
          unsigned short lo, high;
          relocation += addend;
          relocation -= htab->sgotplt->output_section->vma
                        + htab->sgotplt->output_offset;
          /* Write this value into correct location */
          immediate = relocation;
          lo = immediate & 0x0000ffff;
          high = (immediate >> 16) & 0x0000ffff;
          bfd_put_16 ( input_bfd, high, contents + offset + endian);
          bfd_put_16 ( input_bfd, lo, contents + offset + INST_WORD_SIZE + endian);
          break;
        }
	 
        case (int) R_MICROBLAZE_GOTOFF_32:
        {
          relocation += addend;
          relocation -= htab->sgotplt->output_section->vma
                        + htab->sgotplt->output_offset;
          /* Write this value into correct location */
          bfd_put_32 ( input_bfd, relocation, contents + offset);
          break;
        }
	 
        case (int) R_MICROBLAZE_64_PCREL :
        case (int) R_MICROBLAZE_64:
        case (int) R_MICROBLAZE_32:
        {
	  /* r_symndx will be zero only for relocs against symbols
	     from removed linkonce sections, or sections discarded by
	     a linker script.  */
	  if (r_symndx == 0
	      || (input_section->flags & SEC_ALLOC) == 0) {
            relocation += addend;
            if (r_type == R_MICROBLAZE_32) {
              bfd_put_32 ( input_bfd, relocation, contents + offset);
            } else {
              if (r_type == R_MICROBLAZE_64_PCREL)
                relocation -= (input_section->output_section->vma
                               + input_section->output_offset
                               + offset + INST_WORD_SIZE);
                bfd_put_16 (input_bfd, (relocation >> 16) & 0xffff, contents + offset + endian);
                bfd_put_16 (input_bfd, relocation & 0xffff, contents + offset + endian + INST_WORD_SIZE);
            }
	    break;
	  }

	  if ((info->shared
	       && (h == NULL
		   || ELF_ST_VISIBILITY (h->other) == STV_DEFAULT
		   || h->root.type != bfd_link_hash_undefweak)
	       && (! howto->pc_relative
		   || (h != NULL
		       && h->dynindx != -1
		       && (! info->symbolic
			   || !h->def_regular))))
	      || (!info->shared
		  && h != NULL
		  && h->dynindx != -1
		  && !h->non_got_ref
		  && ((h->def_dynamic
		       && !h->def_regular)
		      || h->root.type == bfd_link_hash_undefweak
		      || h->root.type == bfd_link_hash_undefined)))
	    {
              Elf_Internal_Rela outrel;
              bfd_byte *loc;
	      bfd_boolean skip, relocate = FALSE;

	      /* When generating a shared object, these relocations
		 are copied into the output file to be resolved at run
		 time.  */

	      BFD_ASSERT (sreloc != NULL);

	      skip = FALSE;

	      outrel.r_offset =
		_bfd_elf_section_offset (output_bfd, info, input_section,
					 rel->r_offset);
	      if (outrel.r_offset == (bfd_vma) -1)
		skip = TRUE;
	      else if (outrel.r_offset == (bfd_vma) -2)
		skip = TRUE, relocate = TRUE;
	      outrel.r_offset += (input_section->output_section->vma
				  + input_section->output_offset);

	      if (skip)
		memset (&outrel, 0, sizeof outrel);
	      /* h->dynindx may be -1 if the symbol was marked to
		 become local.  */
	      else if (h != NULL
		       && ((! info->symbolic && h->dynindx != -1)
			   || !h->def_regular))
		{
		  BFD_ASSERT (h->dynindx != -1);
		  outrel.r_info = ELF32_R_INFO (h->dynindx, r_type);
		  outrel.r_addend = addend;
		}
	      else
		{
		  if (r_type == R_MICROBLAZE_32)
		    {
		      outrel.r_info = ELF32_R_INFO (0, R_MICROBLAZE_REL);
		      outrel.r_addend = relocation + addend;
		    }
		  else
		    {
		      BFD_FAIL ();
		      (*_bfd_error_handler)
			(_("%B: probably compiled without -fPIC?"),
			 input_bfd);
		      bfd_set_error (bfd_error_bad_value);
		      return FALSE;
		    }
		}

            loc = sreloc->contents;
            loc += sreloc->reloc_count++ * sizeof (Elf32_External_Rela);
            bfd_elf32_swap_reloca_out (output_bfd, &outrel, loc);
            break;
          } else {
            relocation += addend;
            if (r_type == R_MICROBLAZE_32) {
              bfd_put_32 ( input_bfd, relocation, contents + offset);
            } else {
              if (r_type == R_MICROBLAZE_64_PCREL)
                relocation -= (input_section->output_section->vma
                               + input_section->output_offset
                               + offset + INST_WORD_SIZE);
                bfd_put_16 (input_bfd, (relocation >> 16) & 0xffff, contents + offset + endian);
                bfd_put_16 (input_bfd, relocation & 0xffff, contents + offset + endian + INST_WORD_SIZE);
            }
	    break;
          }
        }

        default :
           r = _bfd_final_link_relocate (howto, input_bfd, input_section,
                                         contents, offset,
                                         relocation, addend);
           break;
        }
     }

     check_reloc:

      if (r != bfd_reloc_ok)
      {
         /* FIXME: This should be generic enough to go in a utility.  */
         const char *name;

         if (h != NULL)
            name = h->root.root.string;
         else
         {
            name = (bfd_elf_string_from_elf_section
                    (input_bfd, symtab_hdr->sh_link, sym->st_name));
            if (name == NULL || *name == '\0')
               name = bfd_section_name (input_bfd, sec);
         }

         if (errmsg != NULL)
            goto common_error;

         switch (r)
         {
         case bfd_reloc_overflow:
            if (! ((*info->callbacks->reloc_overflow)
                   (info, (h ? &h->root : NULL), name, howto->name, (bfd_vma) 0,
                    input_bfd, input_section, offset)))
               return FALSE;
            break;

         case bfd_reloc_undefined:
            if (! ((*info->callbacks->undefined_symbol)
                   (info, name, input_bfd, input_section,
                    offset, TRUE)))
               return FALSE;
            break;

         case bfd_reloc_outofrange:
            errmsg = _("internal error: out of range error");
            goto common_error;

         case bfd_reloc_notsupported:
            errmsg = _("internal error: unsupported relocation error");
            goto common_error;

         case bfd_reloc_dangerous:
            errmsg = _("internal error: dangerous error");
            goto common_error;

         default:
            errmsg = _("internal error: unknown error");
            /* fall through */

           common_error:
            if (!((*info->callbacks->warning)
                  (info, errmsg, name, input_bfd, input_section,
                   offset)))
               return FALSE;
            break;
         }
      }
   }

   return ret;
}

/* Merge backend specific data from an object file to the output
   object file when linking.  

   Note: We only use this hook to catch endian mismatches */
static bfd_boolean
microblaze_elf_merge_private_bfd_data (bfd * ibfd, bfd * obfd)
{
  /* Check if we have the same endianess.  */
  if (! _bfd_generic_verify_endian_match (ibfd, obfd))
    return FALSE;

  return TRUE;
}

/* Set the values of the small data pointers */
static void
microblaze_elf_final_sdp (info)
   struct bfd_link_info *info;
{
   struct bfd_link_hash_entry *h;

   h = bfd_link_hash_lookup (info->hash, RO_SDA_ANCHOR_NAME, FALSE, FALSE, TRUE);
   if (h != (struct bfd_link_hash_entry *) NULL
       && h->type == bfd_link_hash_defined)
      ro_small_data_pointer = (h->u.def.value
                               + h->u.def.section->output_section->vma
                               + h->u.def.section->output_offset);

   h = bfd_link_hash_lookup (info->hash, RW_SDA_ANCHOR_NAME, FALSE, FALSE, TRUE);
   if (h != (struct bfd_link_hash_entry *) NULL
       && h->type == bfd_link_hash_defined)
      rw_small_data_pointer = (h->u.def.value
                               + h->u.def.section->output_section->vma
                               + h->u.def.section->output_offset);

}

static bfd_boolean
microblaze_elf_relax_section (bfd *abfd, asection *sec,
			      struct bfd_link_info *link_info,
			      bfd_boolean *again)
{
   Elf_Internal_Shdr *symtab_hdr;
   Elf_Internal_Rela *internal_relocs;
   Elf_Internal_Rela *free_relocs = NULL;
   Elf_Internal_Rela *irel, *irelend;
   bfd_byte *contents = NULL;
   bfd_byte *free_contents = NULL;
   bfd_vma *deleted_addresses = NULL;
   int delete_count;
   int *changed_relocs = NULL;
   int rel_count;
   unsigned int shndx;
   int handled_relocs;
   int i,j,index;
   asection *o;
   struct elf_link_hash_entry *sym_hash;
   Elf_Internal_Sym *isymbuf, *isymend;
   Elf_Internal_Sym *isym;
   int symcount;
   int endian = !bfd_little_endian (abfd) * 2;

   /* We only do this once per section.  We may be able to delete some code 
      by running multiple passes, but it is not worth it */
   *again = FALSE;

   /* Only do this for a text section */
   if (link_info->relocatable
       || (sec->flags & SEC_RELOC) == 0
       || (sec->reloc_count == 0))
      return TRUE;

#if 0
   if (bfd_little_endian (abfd))
      return TRUE;
#endif

   BFD_ASSERT((sec->size > 0) || (sec->rawsize > 0));

   /* If this is the first time we have been called for this section,
      initialize the cooked size.  */
   if (sec->size == 0)
      sec->size = sec->rawsize;

   /* Get symbols for this section. */
   symtab_hdr = &elf_tdata (abfd)->symtab_hdr;
   isymbuf = (Elf_Internal_Sym *) symtab_hdr->contents;
   symcount =  symtab_hdr->sh_size / sizeof (Elf32_External_Sym);
   if (isymbuf == NULL) 
     isymbuf = bfd_elf_get_elf_syms (abfd, symtab_hdr, symcount, 
	 			     0, NULL, NULL, NULL);
   BFD_ASSERT(isymbuf != NULL);

   internal_relocs = _bfd_elf_link_read_relocs
                      (abfd, sec, (PTR) NULL, (Elf_Internal_Rela *) NULL,
                       link_info->keep_memory);
   if (internal_relocs == NULL)
      goto error_return;
   if (! link_info->keep_memory)
      free_relocs = internal_relocs;

   deleted_addresses = (bfd_vma *) bfd_malloc((sec->reloc_count+1) * sizeof(bfd_vma));
   if (deleted_addresses == NULL)
      goto error_return;
   changed_relocs = (int *) bfd_malloc(sec->reloc_count * sizeof(int));
   if (changed_relocs == NULL)
      goto error_return;
   delete_count = 0;

   irelend = internal_relocs + sec->reloc_count;
   rel_count = 0;
   for (irel = internal_relocs; irel < irelend; irel++, rel_count++)
     {
       bfd_vma symval;

       //printf("irel[%d] = {r_info = %d}\n", irel-internal_relocs, (int)irel->r_info);
       if ((ELF32_R_TYPE (irel->r_info) != (int) R_MICROBLAZE_64_PCREL)
	   && (ELF32_R_TYPE (irel->r_info) != (int) R_MICROBLAZE_64 ))
	 continue; /* Can't delete this reloc */
       
       /* Get the section contents.  */
       if (contents == NULL)
	 {
	   if (elf_section_data (sec)->this_hdr.contents != NULL)
	     contents = elf_section_data (sec)->this_hdr.contents;
	   else
	     {
	       contents = (bfd_byte *) bfd_malloc (sec->size);
	       if (contents == NULL)
		 goto error_return;
	       free_contents = contents;
	       
	       if (! bfd_get_section_contents (abfd, sec, contents,
					       (file_ptr) 0, sec->size))
		 goto error_return;
               elf_section_data (sec)->this_hdr.contents = contents;
	     }
	 }
       
       /* Get the value of the symbol referred to by the reloc.  */
       if (ELF32_R_SYM (irel->r_info) < symtab_hdr->sh_info)
	 {
	   /* A local symbol.  */
	   Elf_Internal_Sym *isym;
	   asection *sym_sec;

	   isym = isymbuf + ELF32_R_SYM (irel->r_info);
	   if (isym->st_shndx == SHN_UNDEF)
	     sym_sec = bfd_und_section_ptr;
	   else if (isym->st_shndx == SHN_ABS)
	     sym_sec = bfd_abs_section_ptr;
	   else if (isym->st_shndx == SHN_COMMON)
	     sym_sec = bfd_com_section_ptr;
	   else
	    sym_sec = bfd_section_from_elf_index (abfd, isym->st_shndx);

	   symval = _bfd_elf_rela_local_sym (abfd, isym, &sym_sec, irel);
	 }
       else
	 {
	   unsigned long indx;
	   struct elf_link_hash_entry *h;

	   indx = ELF32_R_SYM (irel->r_info) - symtab_hdr->sh_info;
	   h = elf_sym_hashes (abfd)[indx];
	   BFD_ASSERT (h != NULL);
	   if (h->root.type != bfd_link_hash_defined
	       && h->root.type != bfd_link_hash_defweak)
	     {
	       /* This appears to be a reference to an undefined
		  symbol.  Just ignore it--it will be caught by the
		  regular reloc processing.  */
	       continue;
	     }
	 
	   symval = (h->root.u.def.value
		     + h->root.u.def.section->output_section->vma
		     + h->root.u.def.section->output_offset);
	 }
      
       /* If this is a PC-relative reloc, subtract the instr offset from the symbol value */
       if (ELF32_R_TYPE (irel->r_info) == (int) R_MICROBLAZE_64_PCREL) {
	 symval = symval + irel->r_addend
	   		 - (irel->r_offset
			    + sec->output_section->vma
			    + sec->output_offset);
       } else {
         symval += irel->r_addend;
       }

       if ((symval & 0xffff8000) == 0 
	   || (symval & 0xffff8000) == 0xffff8000) {
         /* We can delete this instruction */
         deleted_addresses[delete_count] = irel->r_offset;
         /* Save the reloc number */
         changed_relocs[delete_count] = rel_count;
         delete_count++;
       }
     } /* Loop through all relocations */

   //printf("Total Reloc count : %d \n", rel_count);
   //printf("Total Delete count : %d \n", delete_count);

   /* Loop through the relocs again, and see if anything needs to change */
   if (delete_count > 0) {
     shndx = _bfd_elf_section_from_bfd_section (abfd, sec);
     rel_count = 0;
     handled_relocs = 0;
     deleted_addresses[delete_count] = sec->size;
     for (irel = internal_relocs; irel < irelend; irel++, rel_count++)
       {
	 bfd_vma nraddr;
         /* Get the new reloc address.  */
	 nraddr = irel->r_offset;
	 for (i = 0; i < delete_count; i++) {
	   if (deleted_addresses[i] >= nraddr)
	     break;
         }
	 nraddr -= INST_WORD_SIZE * i;
         switch ((enum elf_microblaze_reloc_type) ELF32_R_TYPE (irel->r_info)) 
	   {
	   default:
	     break;
	   case R_MICROBLAZE_64_PCREL:
	     /* Check if this is the deleted reloc */
	     if (handled_relocs < delete_count && 
		 rel_count == changed_relocs[handled_relocs]) {
               /* Change the reloc type */
               irel->r_info = ELF32_R_INFO (ELF32_R_SYM (irel->r_info),
                                            (int) R_MICROBLAZE_32_PCREL_LO);
               handled_relocs++;
	     }
	     break;
	   case R_MICROBLAZE_64:
	     /* Check if this is the deleted reloc */
	     if (handled_relocs < delete_count && 
		 rel_count == changed_relocs[handled_relocs]) {
               /* Change the reloc type */
               irel->r_info = ELF32_R_INFO (ELF32_R_SYM (irel->r_info),
                                            (int) R_MICROBLAZE_32_LO);
               handled_relocs++;
	     }
	     /* If this reloc is against a symbol defined in this
		section, we
		must check the addend to see it will put the value in
		range to be adjusted, and hence must be changed.  */
	     if (ELF32_R_SYM (irel->r_info) < symtab_hdr->sh_info)
	       {
		 Elf_Internal_Sym *isym;
		 isym = isymbuf + ELF32_R_SYM(irel->r_info);
		 /* Only handle relocs against .text */
		 if (isym->st_shndx == shndx &&
		     ELF32_ST_TYPE (isym->st_info) == STT_SECTION) {
		   for (i = 0; i < delete_count; i++) {
                     if (deleted_addresses[i] >= irel->r_addend)
		       break;
		   }
		   if (i > 0) {
		     irel->r_addend -= i * INST_WORD_SIZE;
		   }
		 }
	       }
	     break;
	   case R_MICROBLAZE_NONE:
	     {
	       /* This was a PC-relative instruction that was completely resolved. */
	       bfd_vma target_address;
	       target_address = irel->r_addend + irel->r_offset;
	       for (i = 0; i < delete_count; i++) {
		 if (deleted_addresses[i] >= irel->r_offset)
		   break;
	       }
	       for (j = 0; j < delete_count; j++) {
		 if (deleted_addresses[j] >= target_address)
		   break;
	       }
	       i = j-i;
	       if (i != 0) {
		 irel->r_addend -= i * INST_WORD_SIZE;
		 /* Should use HOWTO. */
		 bfd_put_16 (abfd, irel->r_addend, contents + irel->r_offset + endian);
	       }
	     }
	     break;
	   case R_MICROBLAZE_64_NONE:
	     {
	       /* This was a PC-relative 64-bit instruction that was completely resolved. */
	       bfd_vma target_address;
	       target_address = irel->r_addend + irel->r_offset + INST_WORD_SIZE;
	       for (i = 0; i < delete_count; i++) {
		 if (deleted_addresses[i] >= (irel->r_offset + INST_WORD_SIZE))
		   break;
	       }
	       for (j = 0; j < delete_count; j++) {
		 if (deleted_addresses[j] >= target_address)
		   break;
	       }
	       i = j-i;
	       if (i != 0) {
		 irel->r_addend -= i * INST_WORD_SIZE;
	       }
	     }
	     break;
	   }
         irel->r_offset = nraddr;
       } /* Change all relocs in this section */
     
     /* Look through all other sections */
     for (o = abfd->sections; o != NULL; o = o->next)
     {
        Elf_Internal_Rela *internal_relocs;
        Elf_Internal_Rela *irelscan, *irelscanend;
        bfd_byte *ocontents;
        
        if (o == sec
             || (o->flags & SEC_RELOC) == 0
            || o->reloc_count == 0)
           continue;

        /* We always cache the relocs.  Perhaps, if info->keep_memory is
           FALSE, we should free them, if we are permitted to. */
        
        internal_relocs = _bfd_elf_link_read_relocs (abfd, o, (PTR) NULL, 
	    				(Elf_Internal_Rela *) NULL, TRUE);
        if (internal_relocs == NULL)
           goto error_return;
        
         ocontents = NULL;
         irelscanend = internal_relocs + o->reloc_count;
         for (irelscan = internal_relocs; irelscan < irelscanend; irelscan++)
         {
            if (ELF32_R_TYPE (irelscan->r_info) == (int) R_MICROBLAZE_32)
            {
	       isym = isymbuf + ELF32_R_SYM(irelscan->r_info);
               
               /* Look at the reloc only if the value has been resolved */
               if (isym->st_shndx == shndx 
                   && (ELF32_ST_TYPE(isym->st_info) == STT_SECTION))
               {
                  if (ocontents == NULL)
                  {
                     if (elf_section_data (o)->this_hdr.contents != NULL)
                        ocontents = elf_section_data (o)->this_hdr.contents;
                     else
                     {
                        /* We always cache the section contents.
                           Perhaps, if info->keep_memory is FALSE, we
                           should free them, if we are permitted to. */
                        
		        if (o->rawsize == 0) 
			  o->rawsize = o->size;
                        ocontents = (bfd_byte *) bfd_malloc (o->rawsize);
                        if (ocontents == NULL)
                           goto error_return;
                        if (! bfd_get_section_contents (abfd, o, ocontents,
                                                        (file_ptr) 0,
                                                        o->rawsize))
                           goto error_return;
                        elf_section_data (o)->this_hdr.contents = ocontents;
                     }
                  }
                  
                  for (i = 0; i < delete_count; i++) {
                     if (deleted_addresses[i] >= irelscan->r_addend)
                        break;
                  }
                  if (i > 0) {
                     irelscan->r_addend -= i * INST_WORD_SIZE;
                  }
                  
               }
            }	     
            else if (ELF32_R_TYPE (irelscan->r_info) == (int) R_MICROBLAZE_32_SYM_OP_SYM)
            {
               int count = 0;
               
	       isym = isymbuf + ELF32_R_SYM(irelscan->r_info);
               
               /* Look at the reloc only if the value has been resolved */
               {
                  if (ocontents == NULL)
                  {
                     if (elf_section_data (o)->this_hdr.contents != NULL)
                        ocontents = elf_section_data (o)->this_hdr.contents;
                     else
                     {
                        /* We always cache the section contents.
                           Perhaps, if info->keep_memory is FALSE, we
                           should free them, if we are permitted to. */
                        
		        if (o->rawsize == 0) 
			  o->rawsize = o->size;
                        ocontents = (bfd_byte *) bfd_malloc (o->rawsize);
                        if (ocontents == NULL)
                           goto error_return;
                        if (! bfd_get_section_contents (abfd, o, ocontents,
                                                        (file_ptr) 0,
                                                        o->rawsize))
                           goto error_return;
                        elf_section_data (o)->this_hdr.contents = ocontents;
                     }
                  }
                  
                  for (i = 0; i < delete_count; i++) {
                     if (deleted_addresses[i] >= (irelscan->r_addend + isym->st_value))
                        break;
                     else if (deleted_addresses[i] >= isym->st_value) 
                        count++;
                  }
                  if (count > 0) {
                     irelscan->r_addend -= count * INST_WORD_SIZE;
                  }
                  
               }
            }
	    else if ((ELF32_R_TYPE (irelscan->r_info) == (int) R_MICROBLAZE_32_PCREL_LO) ||
		     (ELF32_R_TYPE (irelscan->r_info) == (int) R_MICROBLAZE_32_LO))
	      {
	        isym = isymbuf + ELF32_R_SYM(irelscan->r_info);
               
		/* Look at the reloc only if the value has been resolved */
		if (isym->st_shndx == shndx 
		    && (ELF32_ST_TYPE(isym->st_info) == STT_SECTION))
		  {
		    bfd_vma immediate;
		    bfd_vma target_address;
		    
		    if (ocontents == NULL)
		      {
			if (elf_section_data (o)->this_hdr.contents != NULL)
			  ocontents = elf_section_data (o)->this_hdr.contents;
			else
			  {
			    /* We always cache the section contents.
			       Perhaps, if info->keep_memory is FALSE, we
			       should free them, if we are permitted to. */
			    
		            if (o->rawsize == 0) 
			      o->rawsize = o->size;
			    ocontents = (bfd_byte *) bfd_malloc (o->rawsize);
			    if (ocontents == NULL)
			      goto error_return;
			    if (! bfd_get_section_contents (abfd, o, ocontents,
							    (file_ptr) 0,
							    o->rawsize))
			      goto error_return;
			    elf_section_data (o)->this_hdr.contents = ocontents;
			  }
		      }
		    
		    immediate = (unsigned short) bfd_get_16 (abfd, ocontents + irelscan->r_offset + endian);
		    target_address = immediate;
		    for (i = 0; i < delete_count; i++) {
		      if (deleted_addresses[i] >= target_address)
                        break;
		    }
		    if (i > 0) {
		      immediate -= i * INST_WORD_SIZE;
		      irelscan->r_addend -= i * INST_WORD_SIZE;
	//	      BFD_ASSERT (immediate == irelscan->r_addend);
       if (dbg) printf("MICROBLAZE_32_PCREL_LO: filename = %s, section = %s, reloc = 0x%8.8x, immediate = 0x%8.8x, r_offset = 0x%8.8x, r_addend = 0x%8.8x\n",
	   abfd->filename, sec->name, (int) (irelscan-internal_relocs), 
	   (int) immediate, 
	   (int) irelscan->r_offset,
	   (int) irelscan->r_addend);
		      bfd_put_16 (abfd, immediate, ocontents + irelscan->r_offset + endian);
		    }
		  }
	      }
            if (ELF32_R_TYPE (irelscan->r_info) == (int) R_MICROBLAZE_64)
            {
	       isym = isymbuf + ELF32_R_SYM(irelscan->r_info);
               
               /* Look at the reloc only if the value has been resolved */
               if (isym->st_shndx == shndx 
                   && (ELF32_ST_TYPE(isym->st_info) == STT_SECTION))
               {
                  bfd_vma immediate;
                  
                  if (ocontents == NULL)
                  {
                     if (elf_section_data (o)->this_hdr.contents != NULL)
                        ocontents = elf_section_data (o)->this_hdr.contents;
                     else
                     {
                        /* We always cache the section contents.
                           Perhaps, if info->keep_memory is FALSE, we
                           should free them, if we are permitted to. */
                        
		        if (o->rawsize == 0) o->rawsize = o->size;
                        ocontents = (bfd_byte *) bfd_malloc (o->rawsize);
                        if (ocontents == NULL)
                           goto error_return;
                        if (! bfd_get_section_contents (abfd, o, ocontents,
                                                        (file_ptr) 0,
                                                        o->rawsize))
                           goto error_return;
                        elf_section_data (o)->this_hdr.contents = ocontents;
                     }
                  }
		  immediate = (unsigned short) (bfd_get_16 (abfd, ocontents + irelscan->r_offset + endian) << 16) & 0xffff0000;
		  immediate += (unsigned short) (bfd_get_16 (abfd, ocontents + irelscan->r_offset + INST_WORD_SIZE + endian)) & 0x0000ffff;

                  for (i = 0; i < delete_count; i++) {
                     if (deleted_addresses[i] >= irelscan->r_addend)
                        break;
                  }
                  if (i > 0) {
                     immediate -= i * INST_WORD_SIZE;
                     irelscan->r_addend -= i * INST_WORD_SIZE;
                  }
                  
               }
            }
	    else if (ELF32_R_TYPE (irelscan->r_info) == (int) R_MICROBLAZE_64_PCREL)
	      {
	        isym = isymbuf + ELF32_R_SYM(irelscan->r_info);
               
		/* Look at the reloc only if the value has been resolved */
		if (isym->st_shndx == shndx 
		    && (ELF32_ST_TYPE(isym->st_info) == STT_SECTION))
		  {
		    bfd_vma immediate;
		    bfd_vma target_address;
		    
		    if (ocontents == NULL)
		      {
			if (elf_section_data (o)->this_hdr.contents != NULL)
			  ocontents = elf_section_data (o)->this_hdr.contents;
			else
			  {
			    /* We always cache the section contents.
			       Perhaps, if info->keep_memory is FALSE, we
			       should free them, if we are permitted to. */
			    
		            if (o->rawsize == 0) 
			      o->rawsize = o->size;
			    ocontents = (bfd_byte *) bfd_malloc (o->rawsize);
			    if (ocontents == NULL)
			      goto error_return;
			    if (! bfd_get_section_contents (abfd, o, ocontents,
							    (file_ptr) 0,
							    o->rawsize))
			      goto error_return;
			    elf_section_data (o)->this_hdr.contents = ocontents;
			  }
		      }
		    
		    immediate = (unsigned short) (bfd_get_16 (abfd, ocontents + irelscan->r_offset + endian) << 16) & 0xffff0000;
		    immediate += (unsigned short) (bfd_get_16 (abfd, ocontents + irelscan->r_offset + INST_WORD_SIZE + endian)) & 0x0000ffff;
		    target_address = immediate;
		    for (i = 0; i < delete_count; i++) {
		      if (deleted_addresses[i] >= target_address)
                        break;
		    }
		    if (i > 0) {
		    //  BFD_ASSERT (immediate == irelscan->r_addend);
		      immediate -= i * INST_WORD_SIZE;
		      irelscan->r_addend -= i * INST_WORD_SIZE;
       if (dbg) printf("MICROBLAZE_64_PCREL: filename = %s, section = %s, immediate = 0x%8.8x, r_addend = 0x%8.8x\n",
	   abfd->filename, sec->name, (int) immediate, (int) irelscan->r_addend);
		      bfd_put_16 (abfd, ((immediate >> 16) & 0x0000ffff), ocontents + irelscan->r_offset + endian);
		      bfd_put_16 (abfd, (immediate & 0x0000ffff), ocontents + irelscan->r_offset + INST_WORD_SIZE + endian);
		    }
		    
		  }
	      }
         }
     } /* Look through all other sections */
     
     /* Adjust the local symbols defined in this section.  */
     isymend = isymbuf + symtab_hdr->sh_info;
     for (isym = isymbuf; isym < isymend; isym++)
       {
         if (isym->st_shndx == shndx) {
	   for (i = 0; i < delete_count; i++) {
	     if (deleted_addresses[i] >= isym->st_value)
	       break;
	   }
	   if (i > 0) 
	     {
               isym->st_value -= INST_WORD_SIZE * i;
	     }
         }
       }

     /* Now adjust the global symbols defined in this section.  */
     isym = isymbuf + symtab_hdr->sh_info;
     isymend = isymbuf + (symtab_hdr->sh_size / sizeof (Elf32_External_Sym));
     for (index = 0; isym < isymend; isym++, index++)
       {
	 sym_hash = elf_sym_hashes (abfd)[index];
	 if (isym->st_shndx == shndx
             && (sym_hash->root.type == bfd_link_hash_defined
                 || sym_hash->root.type == bfd_link_hash_defweak)
             && sym_hash->root.u.def.section == sec)
	   {
	     for (i = 0; i < delete_count; i++) {
               if (deleted_addresses[i] >= sym_hash->root.u.def.value)
		 break;
	     }
	     if (i > 0) {
               sym_hash->root.u.def.value -= i * INST_WORD_SIZE;
	     }
	   }
       }

     /* Fix location list entries. */
     microblaze_adjust_debug_loc (abfd, sec, link_info, deleted_addresses, delete_count);

     /* Physically move the code and change the cooked size */
     for (i = 0, index=deleted_addresses[0]; i < delete_count; i++) {
       memmove (contents + index, 
		contents + deleted_addresses[i] + INST_WORD_SIZE,
		deleted_addresses[i+1] - deleted_addresses[i] - INST_WORD_SIZE);
       index += deleted_addresses[i+1] - deleted_addresses[i] - INST_WORD_SIZE;
     }
     sec->size -= INST_WORD_SIZE*delete_count;

     elf_section_data (sec)->relocs = internal_relocs;
     free_relocs = NULL;
    
     elf_section_data (sec)->this_hdr.contents = contents;
     free_contents = NULL;

     symtab_hdr->contents = (bfd_byte *) isymbuf;
   } /* delete_count > 0 */


   if (free_relocs != NULL)
   {
      free (free_relocs);
      free_relocs = NULL;
   }

   if (free_contents != NULL)
   {
      if (! link_info->keep_memory) {
         free (free_contents);
      }
      else
      {
         /* Cache the section contents for elf_link_input_bfd.  */
         elf_section_data (sec)->this_hdr.contents = contents;
      }
      free_contents = NULL;
   }

   if (deleted_addresses != NULL) {
      free(deleted_addresses);
      deleted_addresses = NULL;
   }
   if (changed_relocs != NULL) {
      free(changed_relocs);
      changed_relocs = NULL;
   }
   return TRUE;
   
  error_return:
   if (free_relocs != NULL)
      free (free_relocs);
   if (free_contents != NULL)
      free (free_contents);
   if (deleted_addresses != NULL)
      free(deleted_addresses);
   if (changed_relocs != NULL)
      free(changed_relocs);
   return FALSE;
}

/* Fix up location list offsets to correct for deleted instructions. 
   deleted_addresses is a list of delete_count instruction addresses
   which have been removed from the .text section.  delete_addresses[delete_count+1]
   must have a sentinal value greater than the highest possible offset.
 */
static void
microblaze_adjust_debug_loc (bfd *abfd, asection *text_sec, struct bfd_link_info *link_info,
    bfd_vma *deleted_addresses, int delete_count ATTRIBUTE_UNUSED)
{
   asection *debug_loc_sec = bfd_get_section_by_name (abfd, ".debug_loc");
   bfd_byte *contents, *dloc, *dloc_end = 0;
   Elf_Internal_Rela *relocs, *irel, *irelend;
   Elf_Internal_Shdr *symtab_hdr;
   Elf_Internal_Sym *isymbuf;
   int symcount;
   unsigned long r_symndx, r_sect;
   asection *map_sec = 0;
   bfd_vma *next_del = deleted_addresses;
   int delete_size = 0;
   unsigned long saved_r_sect = 0;

   if (debug_loc_sec == NULL)
     return; 

#if 0
   printf ("microblaze_adjust_debug_loc (%s, %s, ...)\n", abfd->filename, text_sec->name);
   printf ("deleted_addresses @ 0x%8.8x\n", (int) deleted_addresses);
   for (i = 0; i < delete_count; i++)
   {
      printf ("deleted_addresses[%d] = 0x%8.8x\n", i, (int) deleted_addresses[i]);
   }
   printf("\n");
#endif
   
   /* Get location table contents. */
   if (elf_section_data (debug_loc_sec)->this_hdr.contents != NULL)
	     contents = elf_section_data (debug_loc_sec)->this_hdr.contents;
   else 
   {
     contents = (bfd_byte *) bfd_malloc (debug_loc_sec->size);
     BFD_ASSERT (contents != NULL);
     if (! bfd_get_section_contents (abfd, debug_loc_sec, contents, 0, debug_loc_sec->size))
     {
       free (contents);
       return;   /* Quit silently. */
     }
     elf_section_data (debug_loc_sec)->this_hdr.contents = contents;
   }

   /* Get relocation table contents. */
   relocs = _bfd_elf_link_read_relocs (abfd, debug_loc_sec, (PTR) NULL, (Elf_Internal_Rela *) NULL,
                       link_info->keep_memory);
   if (relocs == NULL)
   { 
     /* If no relocations, search entire .debug_loc section. */
     dloc = contents;
     dloc_end = contents + debug_loc_sec->size;
   } else {
     /* Find portion of .debug_loc which applies to this text section. */
     /* Get symbols for this file. */
     symtab_hdr = &elf_tdata (abfd)->symtab_hdr;
     isymbuf = (Elf_Internal_Sym *) symtab_hdr->contents;
     symcount =  symtab_hdr->sh_size / sizeof (Elf32_External_Sym);
     if (isymbuf == NULL) 
       isymbuf = bfd_elf_get_elf_syms (abfd, symtab_hdr, symcount, 
	 			     0, NULL, NULL, NULL);
     BFD_ASSERT(isymbuf != NULL);

     /* Find first matching relocation entry. */
     for (irel = relocs; irel < relocs + debug_loc_sec->reloc_count; irel++) {
       r_symndx = ELF32_R_SYM (irel->r_info);
       r_sect = isymbuf[r_symndx].st_shndx;
       if (r_sect != saved_r_sect) {
         map_sec = bfd_section_from_elf_index (abfd, r_sect);
         saved_r_sect = r_sect;
       }
       if (text_sec == map_sec) break;
     }

     /* If we didn't find any relocations, skip the rest. */
     if (text_sec != map_sec) 
       return;

     /* Find starting location list entry. */
     dloc = contents + irel->r_offset;

     /* Find last matching relocation entry and location list entry. */
     for (irelend = irel; irelend < relocs + debug_loc_sec->reloc_count; irelend++) {
       if (r_symndx != ELF32_R_SYM (irelend->r_info)) break;
       dloc_end = contents + irelend->r_offset;  
     }
   }

   // printf ("location lists:\n");
   while (dloc < dloc_end)
   {
     bfd_vma soffset, eoffset;
     int blklen;

     soffset = bfd_get_32 (abfd, dloc);
     eoffset = bfd_get_32 (abfd, dloc+4);
     // printf ("%8.8x %8.8x %8.8x\n", (int) (dloc-contents), (int) soffset, (int) eoffset);

     if (soffset == 0 && eoffset == 0) 
     {
       /* End of location list. */
       dloc += 8;
        // printf("         ======== ========\n");
       delete_size = 0;
       next_del = deleted_addresses;
       continue;
     }

     while (soffset > *next_del)
     {
       next_del++;
       delete_size += INST_WORD_SIZE;
     }
     soffset -= delete_size;

     while (eoffset > *next_del)
     {
       next_del++;
       delete_size += INST_WORD_SIZE;
     }
     eoffset -= delete_size;

     if (delete_size) 
     {
       // printf("replaced %8.8x %8.8x\n", (int) soffset, (int) eoffset);
       bfd_put_32 (abfd, soffset, dloc);
       bfd_put_32 (abfd, eoffset, dloc+4);
     }

     blklen = bfd_get_16 (abfd, dloc+8);

     /* Fix up loc list offsets. */

     
     dloc += (4 + 4 + 2) + blklen;
   }
   // printf("\n");

}


/* Return the section that should be marked against GC for a given
   relocation.  */

static asection *
microblaze_elf_gc_mark_hook (asection *sec,
			     struct bfd_link_info * info ATTRIBUTE_UNUSED,
     			     Elf_Internal_Rela * rel,
     			     struct elf_link_hash_entry * h,
     			     Elf_Internal_Sym * sym)
{
  if (h != NULL)
    {
      switch (ELF32_R_TYPE (rel->r_info))
	{
	case R_MICROBLAZE_GNU_VTINHERIT:
	case R_MICROBLAZE_GNU_VTENTRY:
	  break;

	default:
	  switch (h->root.type)
	    {
	    case bfd_link_hash_defined:
	    case bfd_link_hash_defweak:
	      return h->root.u.def.section;
	      
	    case bfd_link_hash_common:
	      return h->root.u.c.p->section;

	    default:
	      break;
	    }
	}
    }
  else
    return bfd_section_from_elf_index (sec->owner, sym->st_shndx);

  return NULL;
}

/* Update the got entry reference counts for the section being removed.  */

static bfd_boolean
microblaze_elf_gc_sweep_hook (bfd * abfd ATTRIBUTE_UNUSED,
     			      struct bfd_link_info * info ATTRIBUTE_UNUSED,
     			      asection * sec ATTRIBUTE_UNUSED,
     			      const Elf_Internal_Rela * relocs ATTRIBUTE_UNUSED)
{
  return TRUE;
}

/* Look through the relocs for a section during the first phase. */
 
static bfd_boolean
microblaze_elf_check_relocs (bfd * abfd, struct bfd_link_info * info,
     			     asection * sec, const Elf_Internal_Rela * relocs)
{
  Elf_Internal_Shdr *           symtab_hdr;
  struct elf_link_hash_entry ** sym_hashes;
  struct elf_link_hash_entry ** sym_hashes_end;
  const Elf_Internal_Rela *     rel;
  const Elf_Internal_Rela *     rel_end;
  struct elf32_mb_link_hash_table *htab;
  bfd_vma *local_got_offsets;
  asection *sreloc = NULL;
 
  if (info->relocatable)
    return TRUE;

  htab = elf32_mb_hash_table (info);
  local_got_offsets = elf_local_got_offsets (abfd);
  symtab_hdr = & elf_tdata (abfd)->symtab_hdr;
  sym_hashes = elf_sym_hashes (abfd);
  sym_hashes_end = sym_hashes + symtab_hdr->sh_size / sizeof (Elf32_External_Sym);
  if (!elf_bad_symtab (abfd))
    sym_hashes_end -= symtab_hdr->sh_info;
 
  rel_end = relocs + sec->reloc_count;
  
  for (rel = relocs; rel < rel_end; rel++)
    {
      unsigned int r_type;
      struct elf_link_hash_entry * h;
      unsigned long r_symndx;
 
      r_symndx = ELF32_R_SYM (rel->r_info);
      r_type = ELF32_R_TYPE (rel->r_info);
      
      if (r_symndx < symtab_hdr->sh_info)
        h = NULL;
      else
        h = sym_hashes [r_symndx - symtab_hdr->sh_info];
 
      switch (r_type)
        {
        /* This relocation describes the C++ object vtable hierarchy.
           Reconstruct it for later use during GC.  */
        case R_MICROBLAZE_GNU_VTINHERIT:
          if (!bfd_elf_gc_record_vtinherit (abfd, sec, h, rel->r_offset))
            return FALSE;
          break;
	  
        /* This relocation describes which C++ vtable entries are actually
           used.  Record for later use during GC.  */
        case R_MICROBLAZE_GNU_VTENTRY:
          if (!bfd_elf_gc_record_vtentry (abfd, sec, h, rel->r_addend))
            return FALSE;
          break;

        /* This relocation requires .plt entry */
        case R_MICROBLAZE_PLT_64:
          if (h != NULL)
          {
            h->needs_plt = 1;
            h->plt.refcount += 1;
          }
          break;

        /* This relocation requires .got entry */
        case R_MICROBLAZE_GOT_64:
          if (htab->sgot == NULL)
            {
              /* fprintf(stderr ,"check_relocs: creating .got section\n"); */
              if (htab->elf.dynobj == NULL)
                htab->elf.dynobj = abfd;
              if (!create_got_section(htab->elf.dynobj, info))
                return FALSE;
            }
          if (h != NULL)
          {
            h->got.refcount += 1;
          }
          else
          {
            bfd_signed_vma *local_got_refcounts;

            /* This is a global offset table entry for a local symbol.  */
            local_got_refcounts = elf_local_got_refcounts (abfd);
            if (local_got_refcounts == NULL)
            {
              bfd_size_type size;

              size = symtab_hdr->sh_info;
              size *= sizeof (bfd_signed_vma);
              local_got_refcounts = bfd_zalloc (abfd, size);
              if (local_got_refcounts == NULL)
                return FALSE;
              elf_local_got_refcounts (abfd) = local_got_refcounts;
            }
            local_got_refcounts[r_symndx] += 1;
          }
          break;

        case R_MICROBLAZE_64:
        case R_MICROBLAZE_64_PCREL:
        case R_MICROBLAZE_32:
          {
            if (h != NULL && !info->shared) {
              /* we may need a copy reloc */
              h->non_got_ref = 1;

              /* we may also need a .plt entry */
              h->plt.refcount += 1;
              if (ELF32_R_TYPE (rel->r_info) != R_MICROBLAZE_64_PCREL)
                h->pointer_equality_needed = 1;
            }


            /* If we are creating a shared library, and this is a reloc
               against a global symbol, or a non PC relative reloc
               against a local symbol, then we need to copy the reloc
               into the shared library.  However, if we are linking with
               -Bsymbolic, we do not need to copy a reloc against a
               global symbol which is defined in an object we are
               including in the link (i.e., DEF_REGULAR is set).  At
               this point we have not seen all the input files, so it is
               possible that DEF_REGULAR is not set now but will be set
               later (it is never cleared).  In case of a weak definition,
               DEF_REGULAR may be cleared later by a strong definition in
               a shared library.  We account for that possibility below by
               storing information in the relocs_copied field of the hash
               table entry.  A similar situation occurs when creating
               shared libraries and symbol visibility changes render the
               symbol local.

               If on the other hand, we are creating an executable, we
               may need to keep relocations for symbols satisfied by a
               dynamic library if we manage to avoid copy relocs for the
               symbol.  */

            if ((info->shared
                 && (sec->flags & SEC_ALLOC) != 0
                 && (r_type != R_MICROBLAZE_64_PCREL
                     || (h != NULL
                   && (! info->symbolic
                       || h->root.type == bfd_link_hash_defweak
                       || !h->def_regular))))
                || (!info->shared
                    && (sec->flags & SEC_ALLOC) != 0
                    && h != NULL
                    && (h->root.type == bfd_link_hash_defweak
                        || !h->def_regular)))
              {
                struct elf32_mb_dyn_relocs *p;
                struct elf32_mb_dyn_relocs **head;

                /* When creating a shared object, we must copy these
                   relocs into the output file.  We create a reloc
                   section in dynobj and make room for the reloc.  */

	      if (sreloc == NULL)
		{
		  const char *name;
		  bfd *dynobj;
		  unsigned int strndx = elf_elfheader (abfd)->e_shstrndx;
		  unsigned int shnam = elf_section_data (sec)->rel_hdr.sh_name;

		  name = bfd_elf_string_from_elf_section (abfd, strndx, shnam);
		  if (name == NULL)
		    return FALSE;

		  if (strncmp (name, ".rela", 5) != 0
		      || strcmp (bfd_get_section_name (abfd, sec),
				 name + 5) != 0)
		    {
		      (*_bfd_error_handler)
			(_("%B: bad relocation section name `%s\'"),
			 abfd, name);
		    }

                  if (htab->elf.dynobj == NULL)
                    htab->elf.dynobj = abfd;
                  dynobj = htab->elf.dynobj;

                  sreloc = bfd_get_section_by_name (dynobj, name);
		  if (sreloc == NULL)
		    {
		      flagword flags;

		      sreloc = bfd_make_section (dynobj, name);
		      flags = (SEC_HAS_CONTENTS | SEC_READONLY
			       | SEC_IN_MEMORY | SEC_LINKER_CREATED);
		      if ((sec->flags & SEC_ALLOC) != 0)
			flags |= SEC_ALLOC | SEC_LOAD;
		      if (sreloc == NULL
			  || ! bfd_set_section_flags (dynobj, sreloc, flags)
			  || ! bfd_set_section_alignment (dynobj, sreloc, 2))
			return FALSE;
		    }
		  elf_section_data (sec)->sreloc = sreloc;
		}

              /* If this is a global symbol, we count the number of
                 relocations we need for this symbol.  */
              if (h != NULL)
                head = &((struct elf32_mb_link_hash_entry *) h)->dyn_relocs;
              else
                {
                  /* Track dynamic relocs needed for local syms too.
                     We really need local syms available to do this
                     easily.  Oh well.  */

                  asection *s;
                  s = bfd_section_from_r_symndx (abfd, &htab->sym_sec,
                                                 sec, r_symndx);
                  if (s == NULL)
                    return FALSE;

                  head = ((struct elf32_mb_dyn_relocs **)
                          &elf_section_data (s)->local_dynrel);
                }

              p = *head;
              if (p == NULL || p->sec != sec)
                {
                  bfd_size_type amt = sizeof *p;
                  p = ((struct elf32_mb_dyn_relocs *)
                       bfd_alloc (htab->elf.dynobj, amt));
                  if (p == NULL)
                    return FALSE;
                  p->next = *head;
                  *head = p;
                  p->sec = sec;
                  p->count = 0;
                  p->pc_count = 0;
                }

              p->count += 1;
              if (r_type == R_MICROBLAZE_64_PCREL)
                p->pc_count += 1;
            }
          }
          break;
        }
    }
  
  return TRUE;
}

/* PIC support */

#define PLT_ENTRY_SIZE 16

#define PLT_ENTRY_WORD_0  0xb0000000    /* "imm 0" */
#define PLT_ENTRY_WORD_1  0xe9940000    /* "lwi r12,r20,0" - relocated to lwi r12,r20,func@GOT */
#define PLT_ENTRY_WORD_1_NOPIC  0xe9800000    /* "lwi r12,r0,0" - non-PIC object */
#define PLT_ENTRY_WORD_2  0x98186000    /* "brad r12" */
#define PLT_ENTRY_WORD_3  0x80000000    /* "nop" */

/* Create .got, .gotplt, and .rela.got sections in DYNOBJ, and set up
   shortcuts to them in our hash table.  */

static bfd_boolean
create_got_section(bfd *dynobj, struct bfd_link_info *info)
{
  struct elf32_mb_link_hash_table *htab;

  if (! _bfd_elf_create_got_section (dynobj, info))
    return FALSE;
  htab = elf32_mb_hash_table (info);
  htab->sgot = bfd_get_section_by_name (dynobj, ".got");
  htab->sgotplt = bfd_get_section_by_name (dynobj, ".got.plt");
  if (!htab->sgot || !htab->sgotplt)
    return FALSE;

  htab->srelgot = bfd_make_section (dynobj, ".rela.got");
  if (htab->srelgot == NULL
      || ! bfd_set_section_flags (dynobj, htab->srelgot, SEC_ALLOC
                                  | SEC_LOAD
                                  | SEC_HAS_CONTENTS
                                  | SEC_IN_MEMORY
                                  | SEC_LINKER_CREATED
                                  | SEC_READONLY)
      || ! bfd_set_section_alignment (dynobj, htab->srelgot, 2))
    return FALSE;
  return TRUE;
}

static bfd_boolean
microblaze_elf_create_dynamic_sections (bfd *dynobj, struct bfd_link_info *info)
{
  struct elf32_mb_link_hash_table *htab;

  htab = elf32_mb_hash_table (info);
  if (!htab->sgot && !create_got_section (dynobj, info))
    return FALSE;

  if (!_bfd_elf_create_dynamic_sections (dynobj, info))
    return FALSE;

  htab->splt = bfd_get_section_by_name (dynobj, ".plt");
  htab->srelplt = bfd_get_section_by_name (dynobj, ".rela.plt");
  htab->sdynbss = bfd_get_section_by_name (dynobj, ".dynbss");
  if (!info->shared)
    htab->srelbss = bfd_get_section_by_name (dynobj, ".rela.bss");

  if (!htab->splt || !htab->srelplt || !htab->sdynbss
      || (!info->shared && !htab->srelbss))
    abort ();

  return TRUE;
}

/* Copy the extra info we tack onto an elf_link_hash_entry.  */

static void
microblaze_elf_copy_indirect_symbol (const struct elf_backend_data *bed,
     struct elf_link_hash_entry *dir,
     struct elf_link_hash_entry *ind)
{
  struct elf32_mb_link_hash_entry *edir, *eind;

  edir = (struct elf32_mb_link_hash_entry *) dir;
  eind = (struct elf32_mb_link_hash_entry *) ind;

  if (eind->dyn_relocs != NULL)
    {
      if (edir->dyn_relocs != NULL)
	{
	  struct elf32_mb_dyn_relocs **pp;
	  struct elf32_mb_dyn_relocs *p;

	  if (ind->root.type == bfd_link_hash_indirect)
	    abort ();

	  /* Add reloc counts against the weak sym to the strong sym
	     list.  Merge any entries against the same section.  */
	  for (pp = &eind->dyn_relocs; (p = *pp) != NULL; )
	    {
	      struct elf32_mb_dyn_relocs *q;

	      for (q = edir->dyn_relocs; q != NULL; q = q->next)
		if (q->sec == p->sec)
		  {
		    q->pc_count += p->pc_count;
		    q->count += p->count;
		    *pp = p->next;
		    break;
		  }
	      if (q == NULL)
		pp = &p->next;
	    }
	  *pp = edir->dyn_relocs;
	}

      edir->dyn_relocs = eind->dyn_relocs;
      eind->dyn_relocs = NULL;
    }

  _bfd_elf_link_hash_copy_indirect (bed, dir, ind);
}

static bfd_boolean
microblaze_elf_adjust_dynamic_symbol (struct bfd_link_info *info,
                struct elf_link_hash_entry *h)
{
  struct elf32_mb_link_hash_table *htab;
  struct elf32_mb_link_hash_entry * eh;
  struct elf32_mb_dyn_relocs *p;
  asection *sdynbss, *s;
  unsigned int power_of_two;
  bfd *dynobj;

  htab = elf32_mb_hash_table (info);

  /* If this is a function, put it in the procedure linkage table.  We
     will fill in the contents of the procedure linkage table later,
     when we know the address of the .got section.  */
  if (h->type == STT_FUNC
      || h->needs_plt)
    {
      if (h->plt.refcount <= 0
	  || SYMBOL_CALLS_LOCAL (info, h)
	  || (ELF_ST_VISIBILITY (h->other) != STV_DEFAULT
	      && h->root.type == bfd_link_hash_undefweak))
	{
	  /* This case can occur if we saw a PLT reloc in an input
	     file, but the symbol was never referred to by a dynamic
	     object, or if all references were garbage collected.  In
	     such a case, we don't actually need to build a procedure
	     linkage table, and we can just do a PC32 reloc instead.  */
	  h->plt.offset = (bfd_vma) -1;
	  h->needs_plt = 0;
	}

      return TRUE;
    }
  else
    /* It's possible that we incorrectly decided a .plt reloc was
       needed for an R_MICROBLAZE_64_PCREL reloc to a non-function sym in
       check_relocs.  We can't decide accurately between function and
       non-function syms in check-relocs;  Objects loaded later in
       the link may change h->type.  So fix it now.  */
    h->plt.offset = (bfd_vma) -1;

  /* If this is a weak symbol, and there is a real definition, the
     processor independent code will have arranged for us to see the
     real definition first, and we can just use the same value.  */
  if (h->u.weakdef != NULL)
    {
      BFD_ASSERT (h->u.weakdef->root.type == bfd_link_hash_defined
		  || h->u.weakdef->root.type == bfd_link_hash_defweak);
      h->root.u.def.section = h->u.weakdef->root.u.def.section;
      h->root.u.def.value = h->u.weakdef->root.u.def.value;
      return TRUE;
    }

  /* This is a reference to a symbol defined by a dynamic object which
     is not a function.  */

  /* If we are creating a shared library, we must presume that the
     only references to the symbol are via the global offset table.
     For such cases we need not do anything here; the relocations will
     be handled correctly by relocate_section.  */
  if (info->shared)
    return TRUE;

  /* If there are no references to this symbol that do not use the
     GOT, we don't need to generate a copy reloc.  */
  if (!h->non_got_ref)
    return TRUE;

  /* If -z nocopyreloc was given, we won't generate them either.  */
  if (info->nocopyreloc)
    {
      h->non_got_ref = 0;
      return TRUE;
    }

  eh = (struct elf32_mb_link_hash_entry *) h;
  for (p = eh->dyn_relocs; p != NULL; p = p->next)
    {
      s = p->sec->output_section;
      if (s != NULL && (s->flags & SEC_READONLY) != 0)
	break;
    }

  /* If we didn't find any dynamic relocs in read-only sections, then
     we'll be keeping the dynamic relocs and avoiding the copy reloc.  */
  if (p == NULL)
    {
      h->non_got_ref = 0;
      return TRUE;
    }

  /* We must allocate the symbol in our .dynbss section, which will
     become part of the .bss section of the executable.  There will be
     an entry for this symbol in the .dynsym section.  The dynamic
     object will contain position independent code, so all references
     from the dynamic object to this symbol will go through the global
     offset table.  The dynamic linker will use the .dynsym entry to
     determine the address it must put in the global offset table, so
     both the dynamic object and the regular object will refer to the
     same memory location for the variable.  */

  /* We must generate a R_MICROBLAZE_COPY reloc to tell the dynamic linker
     to copy the initial value out of the dynamic object and into the
     runtime process image.  */
  dynobj = elf_hash_table (info)->dynobj;
  BFD_ASSERT (dynobj != NULL);
  if ((h->root.u.def.section->flags & SEC_ALLOC) != 0)
    {
      htab->srelbss->size += sizeof (Elf32_External_Rela);
      h->needs_copy = 1;
    }

  /* We need to figure out the alignment required for this symbol.  I
     have no idea how ELF linkers handle this.  */
  power_of_two = bfd_log2 (h->size);
  if (power_of_two > 3)
    power_of_two = 3;

  sdynbss = htab->sdynbss;
  /* Apply the required alignment.  */
  sdynbss->size = BFD_ALIGN (sdynbss->size, (bfd_size_type) (1 << power_of_two));
  if (power_of_two > bfd_get_section_alignment (dynobj, sdynbss))
    {
      if (! bfd_set_section_alignment (dynobj, sdynbss, power_of_two))
	return FALSE;
    }

  /* Define the symbol as being at this point in the section.  */
  h->root.u.def.section = sdynbss;
  h->root.u.def.value = sdynbss->size;

  /* Increment the section size to make room for the symbol.  */
  sdynbss->size += h->size;
  return TRUE;
}

static bfd_boolean allocate_dynrelocs (struct elf_link_hash_entry *, PTR);

/* Allocate space in .plt, .got and associated reloc sections for
   dynamic relocs.  */

static bfd_boolean
allocate_dynrelocs (h, dat)
     struct elf_link_hash_entry *h;
     PTR dat;
{
  struct bfd_link_info *info;
  struct elf32_mb_link_hash_table *htab;
  struct elf32_mb_link_hash_entry *eh;
  struct elf32_mb_dyn_relocs *p;

  if (h->root.type == bfd_link_hash_indirect)
    return TRUE;

  if (h->root.type == bfd_link_hash_warning)
    /* When warning symbols are created, they **replace** the "real"
       entry in the hash table, thus we never get to see the real
       symbol in a hash traversal.  So look at it now.  */
    h = (struct elf_link_hash_entry *) h->root.u.i.link;

  info = (struct bfd_link_info *) dat;
  htab = elf32_mb_hash_table (info);

  if (htab->elf.dynamic_sections_created
      && h->plt.refcount > 0)
    {
      /* Make sure this symbol is output as a dynamic symbol.
	 Undefined weak syms won't yet be marked as dynamic.  */
      if (h->dynindx == -1
          && !h->forced_local)
        {
          if (! bfd_elf_link_record_dynamic_symbol (info, h))
            return FALSE;
        }

      if (WILL_CALL_FINISH_DYNAMIC_SYMBOL (1, info->shared, h))
        {
          asection *s = htab->splt;

          /* The first entry in .plt is reserved.  */
          if (s->size == 0)
            s->size = PLT_ENTRY_SIZE;

          h->plt.offset = s->size;

          /* If this symbol is not defined in a regular file, and we are
             not generating a shared library, then set the symbol to this
             location in the .plt.  This is required to make function
             pointers compare as equal between the normal executable and
             the shared library.  */
          if (! info->shared
              && !h->def_regular)
            {
              h->root.u.def.section = s;
              h->root.u.def.value = h->plt.offset;
            }

          /* Make room for this entry.  */
          s->size += PLT_ENTRY_SIZE;

          /* We also need to make an entry in the .got.plt section, which
             will be placed in the .got section by the linker script.  */
           htab->sgotplt->size += 4;
                     
          /* We also need to make an entry in the .rel.plt section.  */
          htab->srelplt->size += sizeof (Elf32_External_Rela);
        }
      else
        {
          h->plt.offset = (bfd_vma) -1;
          h->needs_plt = 0;
        }
    }
  else
    {
      h->plt.offset = (bfd_vma) -1;
      h->needs_plt = 0;
    }

  if (h->got.refcount > 0)
    {
      asection *s;

      /* Make sure this symbol is output as a dynamic symbol.
         Undefined weak syms won't yet be marked as dynamic.  */
      if (h->dynindx == -1
          && !h->forced_local)
        {
          if (! bfd_elf_link_record_dynamic_symbol (info, h))
            return FALSE;
        }

      s = htab->sgot;
      h->got.offset = s->size;
      s->size += 4;
      htab->srelgot->size += sizeof (Elf32_External_Rela);
    }
  else
    h->got.offset = (bfd_vma) -1;

  eh = (struct elf32_mb_link_hash_entry *) h;
  if (eh->dyn_relocs == NULL)
    return TRUE;

  /* In the shared -Bsymbolic case, discard space allocated for
     dynamic pc-relative relocs against symbols which turn out to be
     defined in regular objects.  For the normal shared case, discard
     space for pc-relative relocs that have become local due to symbol
     visibility changes.  */

  if (info->shared)
    {
      if (h->def_regular
	  && (h->forced_local
	      || info->symbolic))
	{
	  struct elf32_mb_dyn_relocs **pp;

	  for (pp = &eh->dyn_relocs; (p = *pp) != NULL; )
	    {
	      p->count -= p->pc_count;
	      p->pc_count = 0;
	      if (p->count == 0)
		*pp = p->next;
	      else
		pp = &p->next;
	    }
	}
    }
  else
    {
      /* For the non-shared case, discard space for relocs against
	 symbols which turn out to need copy relocs or are not
	 dynamic.  */

      if (!h->non_got_ref
	  && ((h->def_dynamic
	       && !h->def_regular)
	      || (htab->elf.dynamic_sections_created
		  && (h->root.type == bfd_link_hash_undefweak
		      || h->root.type == bfd_link_hash_undefined))))
	{
	  /* Make sure this symbol is output as a dynamic symbol.
	     Undefined weak syms won't yet be marked as dynamic.  */
	  if (h->dynindx == -1
	      && !h->forced_local)
	    {
	      if (! bfd_elf_link_record_dynamic_symbol (info, h))
		return FALSE;
	    }

	  /* If that succeeded, we know we'll be keeping all the
	     relocs.  */
	  if (h->dynindx != -1)
	    goto keep;
	}

      eh->dyn_relocs = NULL;

    keep: ;
    }

  /* Finally, allocate space.  */
  for (p = eh->dyn_relocs; p != NULL; p = p->next)
    {
      asection *sreloc = elf_section_data (p->sec)->sreloc;
      sreloc->size += p->count * sizeof (Elf32_External_Rela);
    }

  return TRUE;
}

/* Set the sizes of the dynamic sections.  */

static bfd_boolean
microblaze_elf_size_dynamic_sections (output_bfd, info)
     bfd *output_bfd ATTRIBUTE_UNUSED;
     struct bfd_link_info *info;
{
  struct elf32_mb_link_hash_table *htab;
  bfd *dynobj;
  asection *s;
  bfd *ibfd;

  htab = elf32_mb_hash_table (info);
  dynobj = htab->elf.dynobj;
  BFD_ASSERT (dynobj != NULL);

  /* Set up .got offsets for local syms, and space for local dynamic
     relocs.  */
  for (ibfd = info->input_bfds; ibfd != NULL; ibfd = ibfd->link_next)
    {
      bfd_signed_vma *local_got;
      bfd_signed_vma *end_local_got;
      bfd_size_type locsymcount;
      Elf_Internal_Shdr *symtab_hdr;
      asection *srel;

      if (bfd_get_flavour (ibfd) != bfd_target_elf_flavour)
        continue;

      for (s = ibfd->sections; s != NULL; s = s->next)
	{
	  struct elf32_mb_dyn_relocs *p;

	  for (p = *((struct elf32_mb_dyn_relocs **)
		     &elf_section_data (s)->local_dynrel);
	       p != NULL;
	       p = p->next)
	    {
	      if (!bfd_is_abs_section (p->sec)
		  && bfd_is_abs_section (p->sec->output_section))
		{
		  /* Input section has been discarded, either because
		     it is a copy of a linkonce section or due to
		     linker script /DISCARD/, so we'll be discarding
		     the relocs too.  */
		}
	      else if (p->count != 0)
		{
		  srel = elf_section_data (p->sec)->sreloc;
		  srel->size += p->count * sizeof (Elf32_External_Rela);
		  if ((p->sec->output_section->flags & SEC_READONLY) != 0)
		    info->flags |= DF_TEXTREL;
		}
	    }
	}

      local_got = elf_local_got_refcounts (ibfd);
      if (!local_got)
        continue;

      symtab_hdr = &elf_tdata (ibfd)->symtab_hdr;
      locsymcount = symtab_hdr->sh_info;
      end_local_got = local_got + locsymcount;
      s = htab->sgot;
      srel = htab->srelgot;

      for (; local_got < end_local_got; ++local_got)
        {
          if (*local_got > 0)
            {
              *local_got = s->size;
              s->size += 4;
              if (info->shared)
                srel->size += sizeof (Elf32_External_Rela);
            }
          else
            *local_got = (bfd_vma) -1;
        }
    }

  /* Allocate global sym .plt and .got entries, and space for global
     sym dynamic relocs.  */
  elf_link_hash_traverse (elf_hash_table(info), allocate_dynrelocs, (PTR) info);

  if (elf_hash_table (info)->dynamic_sections_created)
    {
      /* Make space for the trailing nop in .plt.  */
      if (htab->splt->size > 0)
        htab->splt->size += 4;

    }

  /* The check_relocs and adjust_dynamic_symbol entry points have
     determined the sizes of the various dynamic sections.  Allocate
     memory for them.  */
  for (s = dynobj->sections; s != NULL; s = s->next)
    {
      const char *name;
      bfd_boolean strip = FALSE;

      if ((s->flags & SEC_LINKER_CREATED) == 0)
        continue;

      /* It's OK to base decisions on the section name, because none
         of the dynobj section names depend upon the input files.  */
      name = bfd_get_section_name (dynobj, s);

      if (strncmp (name, ".rela", 5) == 0)
        {
          if (s->size == 0)
            {
              /* If we don't need this section, strip it from the
        	 output file.  This is to handle .rela.bss and
        	 .rela.plt.  We must create it in
        	 create_dynamic_sections, because it must be created
        	 before the linker maps input sections to output
        	 sections.  The linker does that before
        	 adjust_dynamic_symbol is called, and it is that
        	 function which decides whether anything needs to go
        	 into these sections.  */
              strip = TRUE;
            }
          else
            {
              /* We use the reloc_count field as a counter if we need
        	 to copy relocs into the output file.  */
              s->reloc_count = 0;
            }
        }
      else if (s != htab->splt && s != htab->sgot && s != htab->sgotplt)
        {
          /* It's not one of our sections, so don't allocate space.  */
          continue;
        }

      if (strip)
        {
          _bfd_strip_section_from_output (info, s);
          continue;
        }

      /* Allocate memory for the section contents.  */
      /* FIXME: This should be a call to bfd_alloc not bfd_zalloc.
         Unused entries should be reclaimed before the section's contents
         are written out, but at the moment this does not happen.  Thus in
         order to prevent writing out garbage, we initialise the section's
         contents to zero.  */
      s->contents = (bfd_byte *) bfd_zalloc (dynobj, s->size);
      if (s->contents == NULL && s->size != 0)
        return FALSE;
    }

  if (elf_hash_table (info)->dynamic_sections_created)
    {
      /* Add some entries to the .dynamic section.  We fill in the
	 values later, in microblaze_elf_finish_dynamic_sections, but we
	 must add the entries now so that we get the correct size for
	 the .dynamic section.  The DT_DEBUG entry is filled in by the
	 dynamic linker and used by the debugger.  */
#define add_dynamic_entry(TAG, VAL) \
  _bfd_elf_add_dynamic_entry (info, TAG, VAL)

      if (info->executable)
        {
          if (!add_dynamic_entry (DT_DEBUG, 0))
            return FALSE;
        }

      if (!add_dynamic_entry (DT_RELA, 0)
          || !add_dynamic_entry (DT_RELASZ, 0)
          || !add_dynamic_entry (DT_RELAENT, sizeof (Elf32_External_Rela)))
         return FALSE;

      if (htab->splt->size != 0)
        {
          if (!add_dynamic_entry (DT_PLTGOT, 0)
              || !add_dynamic_entry (DT_PLTRELSZ, 0)
              || !add_dynamic_entry (DT_PLTREL, DT_RELA)
              || !add_dynamic_entry (DT_JMPREL, 0)
              || !add_dynamic_entry (DT_BIND_NOW, 1))
            return FALSE;
        }
#if 0
      /* If any dynamic relocs apply to a read-only section,
         then we need a DT_TEXTREL entry.  */
      if ((info->flags & DF_TEXTREL) == 0)
        elf_link_hash_traverse (&htab->elf, readonly_dynrelocs,
                                (PTR) info);
#endif

      if (info->flags & DF_TEXTREL)
        {
          if (!add_dynamic_entry (DT_TEXTREL, 0))
            return FALSE;
        }
    }
#undef add_dynamic_entry
  return TRUE;
}

/* Finish up dynamic symbol handling.  We set the contents of various
   dynamic sections here.  */

static bfd_boolean
microblaze_elf_finish_dynamic_symbol (output_bfd, info, h, sym)
     bfd *output_bfd;
     struct bfd_link_info *info;
     struct elf_link_hash_entry *h;
     Elf_Internal_Sym *sym;
{
  bfd *dynobj;
  struct elf32_mb_link_hash_table *htab;

  htab = elf32_mb_hash_table (info);
  dynobj = htab->elf.dynobj;

  if (h->plt.offset != (bfd_vma) -1)
    {
      asection *splt;
      asection *srela;
      asection *sgotplt;
      Elf_Internal_Rela rela;
      bfd_byte *loc;
      bfd_vma plt_index;
      bfd_vma got_offset;
      bfd_vma got_addr;

      /* This symbol has an entry in the procedure linkage table.  Set
         it up.  */

      BFD_ASSERT (h->dynindx != -1);

      splt = htab->splt;
      srela = htab->srelplt;
      sgotplt = htab->sgotplt;
      BFD_ASSERT (splt != NULL && srela != NULL && sgotplt != NULL);

      plt_index = h->plt.offset / PLT_ENTRY_SIZE - 1; /* first entry reserved */
      got_offset = (plt_index + 3) * 4; /* 3 reserved ??? */
      got_addr = got_offset;

      /* For non-PIC objects we need absolute address of the GOT entry */
      if (!info->shared)
        got_addr += htab->sgotplt->output_section->vma + sgotplt->output_offset;

      /* Fill in the entry in the procedure linkage table.  */
      bfd_put_32 (output_bfd, PLT_ENTRY_WORD_0 + ((got_addr >> 16) & 0xffff),
                  splt->contents + h->plt.offset);
      if (info->shared)
        bfd_put_32 (output_bfd, PLT_ENTRY_WORD_1 + (got_addr & 0xffff),
                    splt->contents + h->plt.offset + 4);
      else
        bfd_put_32 (output_bfd, PLT_ENTRY_WORD_1_NOPIC + (got_addr & 0xffff),
                    splt->contents + h->plt.offset + 4);
      bfd_put_32 (output_bfd, (bfd_vma) PLT_ENTRY_WORD_2,
                  splt->contents + h->plt.offset + 8);
      bfd_put_32 (output_bfd, (bfd_vma) PLT_ENTRY_WORD_3,
                  splt->contents + h->plt.offset + 12);

      /* Any additions to the .got section??? */
/*      bfd_put_32 (output_bfd,
                  splt->output_section->vma + splt->output_offset + h->plt.offset + 4,
                  sgotplt->contents + got_offset); */

      /* Fill in the entry in the .rela.plt section.  */
      rela.r_offset = (sgotplt->output_section->vma
                       + sgotplt->output_offset
                       + got_offset);
      rela.r_info = ELF32_R_INFO (h->dynindx, R_MICROBLAZE_JUMP_SLOT);
      rela.r_addend = 0;
      loc = srela->contents;
      loc += plt_index * sizeof (Elf32_External_Rela);
      bfd_elf32_swap_reloca_out (output_bfd, &rela, loc);

      if (!h->def_regular)
        {
          /* Mark the symbol as undefined, rather than as defined in
             the .plt section.  Zero the value.  */
          sym->st_shndx = SHN_UNDEF;
          sym->st_value = 0;
        }
    }

  if (h->got.offset != (bfd_vma) -1)
    {
      asection *sgot;
      asection *srela;
      Elf_Internal_Rela rela;
      bfd_byte *loc;

      /* This symbol has an entry in the global offset table.  Set it
         up.  */

      sgot = htab->sgot;
      srela = htab->srelgot;
      BFD_ASSERT (sgot != NULL && srela != NULL);

      rela.r_offset = (sgot->output_section->vma
                       + sgot->output_offset
                       + (h->got.offset &~ (bfd_vma) 1));

      /* If this is a -Bsymbolic link, and the symbol is defined
         locally, we just want to emit a RELATIVE reloc.  Likewise if
         the symbol was forced to be local because of a version file.
         The entry in the global offset table will already have been
         initialized in the relocate_section function.  */
      if (info->shared
          && (info->symbolic || h->dynindx == -1)
          && h->def_regular)
        {
          asection *sec = h->root.u.def.section;
          rela.r_info = ELF32_R_INFO (0, R_MICROBLAZE_REL);
          rela.r_addend = (h->root.u.def.value
                           + sec->output_section->vma
                           + sec->output_offset);
        }
      else
        {
          rela.r_info = ELF32_R_INFO (h->dynindx, R_MICROBLAZE_GLOB_DAT);
          rela.r_addend = 0;
        }

      bfd_put_32 (output_bfd, (bfd_vma) 0,
                  sgot->contents + (h->got.offset &~ (bfd_vma) 1));
      loc = srela->contents;
      loc += srela->reloc_count++ * sizeof (Elf32_External_Rela);
      bfd_elf32_swap_reloca_out (output_bfd, &rela, loc);
    }

  if (h->needs_copy)
    {
      asection *s;
      Elf_Internal_Rela rela;
      bfd_byte *loc;

      /* This symbols needs a copy reloc.  Set it up.  */

      BFD_ASSERT (h->dynindx != -1);

      s = bfd_get_section_by_name (h->root.u.def.section->owner,
                                   ".rela.bss");
      BFD_ASSERT (s != NULL);

      rela.r_offset = (h->root.u.def.value
                       + h->root.u.def.section->output_section->vma
                       + h->root.u.def.section->output_offset);
      rela.r_info = ELF32_R_INFO (h->dynindx, R_MICROBLAZE_COPY);
      rela.r_addend = 0;
      loc = s->contents + s->reloc_count++ * sizeof (Elf32_External_Rela);
      bfd_elf32_swap_reloca_out (output_bfd, &rela, loc);
    }

  /* Mark some specially defined symbols as absolute.  */
  if (strcmp (h->root.root.string, "_DYNAMIC") == 0
      || strcmp (h->root.root.string, "_GLOBAL_OFFSET_TABLE_") == 0
      || strcmp (h->root.root.string, "_PROCEDURE_LINKAGE_TABLE_") == 0)
    sym->st_shndx = SHN_ABS;

  return TRUE;
}


/* Finish up the dynamic sections.  */

static bfd_boolean
microblaze_elf_finish_dynamic_sections (output_bfd, info)
     bfd *output_bfd;
     struct bfd_link_info *info;
{
  bfd *dynobj;
  asection *sdyn, *sgot;
  struct elf32_mb_link_hash_table *htab;

  htab = elf32_mb_hash_table (info);
  dynobj = htab->elf.dynobj;

  sdyn = bfd_get_section_by_name (dynobj, ".dynamic");

  if (htab->elf.dynamic_sections_created)
    {
      asection *splt;
      Elf32_External_Dyn *dyncon, *dynconend;

      splt = bfd_get_section_by_name (dynobj, ".plt");
      BFD_ASSERT (splt != NULL && sdyn != NULL);

      dyncon = (Elf32_External_Dyn *) sdyn->contents;
      dynconend = (Elf32_External_Dyn *) (sdyn->contents + sdyn->size);
      for (; dyncon < dynconend; dyncon++)
        {
          Elf_Internal_Dyn dyn;
          const char *name;
          bfd_boolean size;

          bfd_elf32_swap_dyn_in (dynobj, dyncon, &dyn);

          switch (dyn.d_tag)
            {
            case DT_PLTGOT:   name = ".got.plt"; size = FALSE; break;
            case DT_PLTRELSZ: name = ".rela.plt"; size = TRUE; break;
            case DT_JMPREL:   name = ".rela.plt"; size = FALSE; break;
            case DT_RELA:     name = ".rela.dyn"; size = FALSE; break;
            case DT_RELASZ:   name = ".rela.dyn"; size = TRUE; break;
            default:	  name = NULL; size = FALSE; break;
            }

          if (name != NULL)
            {
              asection *s;

              s = bfd_get_section_by_name (output_bfd, name);
              if (s == NULL)
                dyn.d_un.d_val = 0;
              else
                {
                  if (! size)
                    dyn.d_un.d_ptr = s->vma;
                  else
                    dyn.d_un.d_val = s->size;
                }
              bfd_elf32_swap_dyn_out (output_bfd, &dyn, dyncon);
            }
        }

      /* Clear the first entry in the procedure linkage table,
	 and put a nop in the last four bytes.  */
      if (splt->size > 0)
        {
          memset (splt->contents, 0, PLT_ENTRY_SIZE);
          bfd_put_32 (output_bfd, (bfd_vma) 0x80000000 /* nop */,
                      splt->contents + splt->size - 4);
        }

      elf_section_data (splt->output_section)->this_hdr.sh_entsize = 4;
    }

  /* Set the first entry in the global offset table to the address of
     the dynamic section.  */
  sgot = bfd_get_section_by_name (dynobj, ".got.plt");
  if (sgot && sgot->size > 0)
    {
      if (sdyn == NULL)
        bfd_put_32 (output_bfd, (bfd_vma) 0, sgot->contents);
      else
        bfd_put_32 (output_bfd,
                    sdyn->output_section->vma + sdyn->output_offset,
                    sgot->contents);
      elf_section_data (sgot->output_section)->this_hdr.sh_entsize = 4;
    }

  if (htab->sgot && htab->sgot->size > 0)
    elf_section_data (htab->sgot->output_section)->this_hdr.sh_entsize = 4;

  return TRUE;
}

/* Hook called by the linker routine which adds symbols from an object
   file.  We use it to put .comm items in .sbss, and not .bss.  */

static bfd_boolean
microblaze_elf_add_symbol_hook (bfd *abfd,
			        struct bfd_link_info *info,
			        Elf_Internal_Sym *sym,
			        const char **namep ATTRIBUTE_UNUSED,
			        flagword *flagsp ATTRIBUTE_UNUSED,
			        asection **secp,
			        bfd_vma *valp)
{
  if (sym->st_shndx == SHN_COMMON
      && !info->relocatable
      && sym->st_size <= elf_gp_size (abfd))
    {
      /* Common symbols less than or equal to -G nn bytes are automatically
	 put into .sbss.  */

      *secp = bfd_make_section_anyway (abfd, ".sbss");
      if (*secp == NULL
          || ! bfd_set_section_flags (abfd, *secp, SEC_IS_COMMON))
        return FALSE;

      *valp = sym->st_size;
    }

  return TRUE;
}


#define TARGET_LITTLE_SYM	bfd_elf32_microblazeel_vec
#define TARGET_LITTLE_NAME	"elf32-microblazeel"

#define TARGET_BIG_SYM          bfd_elf32_microblaze_vec
#define TARGET_BIG_NAME		"elf32-microblaze"

#define ELF_ARCH		bfd_arch_microblaze
#define ELF_MACHINE_CODE	EM_MICROBLAZE
#define ELF_MAXPAGESIZE		0x1000
#define elf_info_to_howto	microblaze_elf_info_to_howto
#define elf_info_to_howto_rel	NULL

#define bfd_elf32_bfd_reloc_type_lookup		microblaze_elf_reloc_type_lookup
#define bfd_elf32_bfd_is_local_label_name       microblaze_elf_is_local_label_name
#define elf_backend_relocate_section		microblaze_elf_relocate_section
#define bfd_elf32_bfd_relax_section             microblaze_elf_relax_section
#define bfd_elf32_bfd_merge_private_bfd_data    microblaze_elf_merge_private_bfd_data

/*#define bfd_elf32_bfd_set_private_flags		microblaze_elf_set_private_flags*/

#define elf_backend_gc_mark_hook		microblaze_elf_gc_mark_hook
#define elf_backend_gc_sweep_hook		microblaze_elf_gc_sweep_hook
#define elf_backend_check_relocs                microblaze_elf_check_relocs
#define elf_backend_copy_indirect_symbol        microblaze_elf_copy_indirect_symbol
#define bfd_elf32_bfd_link_hash_table_create    microblaze_elf_link_hash_table_create
#define elf_backend_can_gc_sections		1
#define elf_backend_can_refcount    		1
#define elf_backend_want_got_plt    		1
#define elf_backend_plt_readonly    		1
#define elf_backend_got_header_size 		12
#define elf_backend_rela_normal     		1

#define elf_backend_adjust_dynamic_symbol       microblaze_elf_adjust_dynamic_symbol
#define elf_backend_create_dynamic_sections     microblaze_elf_create_dynamic_sections
#define elf_backend_finish_dynamic_sections     microblaze_elf_finish_dynamic_sections
#define elf_backend_finish_dynamic_symbol       microblaze_elf_finish_dynamic_symbol
#define elf_backend_size_dynamic_sections       microblaze_elf_size_dynamic_sections
#define elf_backend_add_symbol_hook		microblaze_elf_add_symbol_hook


#include "elf32-target.h"
