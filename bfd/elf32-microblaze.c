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
   Elf_Internal_Shdr *symtab_hdr = &elf_tdata (input_bfd)->symtab_hdr;
   struct elf_link_hash_entry **sym_hashes = elf_sym_hashes (input_bfd);
   Elf_Internal_Rela *rel, *relend;
   /* Assume success.  */
   bfd_boolean ret = TRUE;
   bfd *dynobj;
   asection *sgot, *splt, *srelplt, *srelgot, *sgotplt;
   bfd_vma *local_got_offsets;

   if (!microblaze_elf_howto_table[R_MICROBLAZE_max-1])
      microblaze_elf_howto_init();

   dynobj = elf_hash_table (info)->dynobj;
   if (dynobj != NULL)
   {
      sgot = bfd_get_section_by_name (dynobj, ".got");
      splt = bfd_get_section_by_name (dynobj, ".plt");
      sgotplt = bfd_get_section_by_name (dynobj, ".got.plt");
      srelplt = bfd_get_section_by_name (dynobj, ".rela.plt");
      srelgot = bfd_get_section_by_name (dynobj, ".rela.got");
      local_got_offsets = elf_local_got_offsets (input_bfd);
   }
   else
   {
      sgot = splt = sgotplt = srelplt = srelgot = NULL;
      local_got_offsets = NULL;
   }

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
            /* External symbol.  */
            h = sym_hashes[r_symndx - symtab_hdr->sh_info];
            while (h->root.type == bfd_link_hash_indirect
                   || h->root.type == bfd_link_hash_warning)
               h = (struct elf_link_hash_entry *) h->root.u.i.link;
            sym_name = h->root.root.string;

            if (h->root.type == bfd_link_hash_defined
                || h->root.type == bfd_link_hash_defweak)
            {
               sec = h->root.u.def.section;
               if (sec->output_section == NULL)
                  relocation = 0;
               else
                  relocation = (h->root.u.def.value
                                + sec->output_section->vma
                                + sec->output_offset);
            }
            else if (h->root.type == bfd_link_hash_undefweak)
               relocation = 0;
            else
            {
	      if (info->shared)
                 unresolved_reloc = TRUE;
	      else if (! ((*info->callbacks->undefined_symbol)
                        (info, h->root.root.string, input_bfd,
                         input_section, offset, TRUE)))
                 return FALSE;
               relocation = 0;
            }
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
            relocation = sgotplt->output_section->vma
                         + sgotplt->output_offset;

         case (int) R_MICROBLAZE_64_PCREL :
            relocation -= (input_section->output_section->vma
                           + input_section->output_offset
                           + offset + INST_WORD_SIZE);
            /* fall through */
         case (int) R_MICROBLAZE_64 :
	 case (int) R_MICROBLAZE_64_NONE:
         {
            bfd_vma immediate;
            unsigned short lo, high;
            relocation += addend;
            /* Write this value into correct location */
            immediate = relocation;
            lo = immediate & 0x0000ffff;
            high = (immediate >> 16) & 0x0000ffff;
            bfd_put_16 ( input_bfd, high, contents + offset + 2);
            bfd_put_16 ( input_bfd, lo, contents + offset + INST_WORD_SIZE + 2);
            break;
         }
	 
         case (int) R_MICROBLAZE_PLT_64:
         {
            bfd_vma immediate;
            if (splt != NULL && h != NULL && h->plt.offset != (bfd_vma) -1)
            {
               relocation = (splt->output_section->vma
                            + splt->output_offset
                            + h->plt.offset);
               unresolved_reloc = FALSE;
               immediate = relocation - (input_section->output_section->vma
                           + input_section->output_offset
                           + offset + INST_WORD_SIZE);
               bfd_put_16 (input_bfd, (immediate >> 16) & 0xffff, contents + offset + 2);
               bfd_put_16 (input_bfd, immediate & 0xffff, contents + offset + 2 + INST_WORD_SIZE);
           }
           break;
        }

        case (int) R_MICROBLAZE_GOT_64:
        {
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
                             sgot->contents + off);
                     
                 if (info->shared)
                 {
                    Elf_Internal_Rela outrel;
                    bfd_byte *loc;
                    if (srelgot == NULL)
                       abort ();
                    outrel.r_offset = (sgot->output_section->vma
                                      + sgot->output_offset + off);
                    outrel.r_info = ELF32_R_INFO (0, R_MICROBLAZE_REL);
                    outrel.r_addend = 0;
                    loc = srelgot->contents;
                    loc += srelgot->reloc_count++ * sizeof (Elf32_External_Rela);
                    bfd_elf32_swap_reloca_out (output_bfd, &outrel, loc);
                 }
                 local_got_offsets[r_symndx] |= 1;
              }
              relocation = sgot->output_section->vma
                           + sgot->output_offset + off
                           - sgotplt->output_section->vma
                           - sgotplt->output_offset;
              unresolved_reloc = FALSE;
           }
           else
           {
              if (sgotplt != NULL && h != NULL && h->got.offset != (bfd_vma) -1)
              {
                 bfd_put_32 (output_bfd, relocation + addend,
                             sgot->contents + h->got.offset);
                 relocation = sgot->output_section->vma
                              + sgot->output_offset + h->got.offset
                              - sgotplt->output_section->vma
                              - sgotplt->output_offset;
                 unresolved_reloc = FALSE;
              }
          }
          bfd_put_16 (input_bfd, (relocation >> 16) & 0xffff, contents + offset + 2);
          bfd_put_16 (input_bfd, relocation & 0xffff, contents + offset + 2 + INST_WORD_SIZE);
          break;
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

   /* We only do this once per section.  We may be able to delete some code 
      by running multiple passes, but it is not worth it */
   *again = FALSE;

   /* Only do this for a text section */
   if (link_info->relocatable
       || (sec->flags & SEC_RELOC) == 0
       || (sec->reloc_count == 0))
      return TRUE;

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

	   symval = (isym->st_value
		     + sym_sec->output_section->vma
		     + sym_sec->output_offset);
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
	 for (i = 0; i <= delete_count; i++) {
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
		   for (i = 0; i <= delete_count; i++) {
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
	       for (i = 0; i <= delete_count; i++) {
		 if (deleted_addresses[i] >= irel->r_offset)
		   break;
	       }
	       for (j = 0; j <= delete_count; j++) {
		 if (deleted_addresses[j] >= target_address)
		   break;
	       }
	       i = j-i;
	       if (i != 0) {
		 irel->r_addend -= i * INST_WORD_SIZE;
		 /* Should use HOWTO. */
		 bfd_put_16 (abfd, irel->r_addend, contents + irel->r_offset + 2);
	       }
	     }
	     break;
	   case R_MICROBLAZE_64_NONE:
	     {
	       /* This was a PC-relative 64-bit instruction that was completely resolved. */
	       bfd_vma target_address;
	       target_address = irel->r_addend + irel->r_offset + INST_WORD_SIZE;
	       for (i = 0; i <= delete_count; i++) {
		 if (deleted_addresses[i] >= (irel->r_offset + INST_WORD_SIZE))
		   break;
	       }
	       for (j = 0; j <= delete_count; j++) {
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
                  
                  for (i = 0; i <= delete_count; i++) {
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
                  
                  for (i = 0; i <= delete_count; i++) {
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
		    
		    immediate = (unsigned short) bfd_get_16 (abfd, ocontents + irelscan->r_offset + 2);
		    target_address = immediate;
		    for (i = 0; i <= delete_count; i++) {
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
		      bfd_put_16 (abfd, immediate, ocontents + irelscan->r_offset + 2);
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
		  immediate = (unsigned short) (bfd_get_16 (abfd, ocontents + irelscan->r_offset + 2) << 16) & 0xffff0000;
		  immediate += (unsigned short) (bfd_get_16 (abfd, ocontents + irelscan->r_offset + INST_WORD_SIZE + 2)) & 0x0000ffff;

                  for (i = 0; i <= delete_count; i++) {
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
		    
		    immediate = (unsigned short) (bfd_get_16 (abfd, ocontents + irelscan->r_offset + 2) << 16) & 0xffff0000;
		    immediate += (unsigned short) (bfd_get_16 (abfd, ocontents + irelscan->r_offset + INST_WORD_SIZE + 2)) & 0x0000ffff;
		    target_address = immediate;
		    for (i = 0; i <= delete_count; i++) {
		      if (deleted_addresses[i] >= target_address)
                        break;
		    }
		    if (i > 0) {
		      BFD_ASSERT (immediate == irelscan->r_addend);
		      immediate -= i * INST_WORD_SIZE;
		      irelscan->r_addend -= i * INST_WORD_SIZE;
       if (dbg) printf("MICROBLAZE_64_PCREL: filename = %s, section = %s, immediate = 0x%8.8x, r_addend = 0x%8.8x\n",
	   abfd->filename, sec->name, (int) immediate, (int) irelscan->r_addend);
		      bfd_put_16 (abfd, ((immediate >> 16) & 0x0000ffff), ocontents + irelscan->r_offset + 2);
		      bfd_put_16 (abfd, (immediate & 0x0000ffff), ocontents + irelscan->r_offset + INST_WORD_SIZE + 2);
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
	   for (i = 0; i <= delete_count; i++) {
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
	     for (i = 0; i <= delete_count; i++) {
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
    bfd_vma *deleted_addresses, int delete_count)
{
   asection *debug_loc_sec = bfd_get_section_by_name (abfd, ".debug_loc");
   bfd_byte *contents, *dloc, *dloc_end;
   Elf_Internal_Rela *relocs, *irel, *irelend;
   Elf_Internal_Shdr *symtab_hdr;
   Elf_Internal_Sym *isymbuf;
   int symcount;
   unsigned long r_symndx, r_sect;
   asection *map_sec;
   bfd_vma *next_del = deleted_addresses;
   int delete_size = 0;
   int i;

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
       unsigned long saved_r_sect = 0;
       r_symndx = ELF32_R_SYM (irel->r_info);
       r_sect = isymbuf[r_symndx].st_shndx;
       if (r_sect != saved_r_sect) {
         map_sec = bfd_section_from_elf_index (abfd, r_sect);
         saved_r_sect = r_sect;
       }
       if (text_sec == map_sec) break;
     }
     BFD_ASSERT(text_sec == map_sec);

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
  asection *sgot;
 
  if (info->relocatable)
    return TRUE;

  if (elf_hash_table (info)->dynobj)
    sgot = bfd_get_section_by_name (elf_hash_table (info)->dynobj, ".got");
  else
    sgot = NULL;

  symtab_hdr = & elf_tdata (abfd)->symtab_hdr;
  sym_hashes = elf_sym_hashes (abfd);
  sym_hashes_end = sym_hashes + symtab_hdr->sh_size / sizeof (Elf32_External_Sym);
  if (!elf_bad_symtab (abfd))
    sym_hashes_end -= symtab_hdr->sh_info;
 
  rel_end = relocs + sec->reloc_count;
  
  for (rel = relocs; rel < rel_end; rel++)
    {
      struct elf_link_hash_entry * h;
      unsigned long r_symndx;
 
      r_symndx = ELF32_R_SYM (rel->r_info);
      
      if (r_symndx < symtab_hdr->sh_info)
        h = NULL;
      else
        h = sym_hashes [r_symndx - symtab_hdr->sh_info];
 
      switch (ELF32_R_TYPE (rel->r_info))
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
          if (sgot == NULL)
            {
              /* fprintf(stderr ,"check_relocs: creating .got section\n"); */
              if (elf_hash_table (info)->dynobj == NULL)
                elf_hash_table (info)->dynobj = abfd;
              create_got_section(elf_hash_table (info)->dynobj, info);
              sgot = bfd_get_section_by_name (elf_hash_table (info)->dynobj, ".got");
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
        }
    }
  
  return TRUE;
}

/* PIC support */

#define PLT_ENTRY_SIZE 16

#define PLT_ENTRY_WORD_0  0xb0000000    /* "imm 0" */
#define PLT_ENTRY_WORD_1  0xe9940000    /* "lwi r12,r20,0" - relocated to lwi r12,r20,func@GOT */
#define PLT_ENTRY_WORD_2  0x98186000    /* "brad r12" */
#define PLT_ENTRY_WORD_3  0x80000000    /* "nop" */

static bfd_boolean
create_got_section(bfd *dynobj, struct bfd_link_info *info)
{
  asection *srelgot;

  if (! _bfd_elf_create_got_section (dynobj, info))
    return FALSE;
  srelgot = bfd_make_section (dynobj, ".rela.got");
  if (srelgot == NULL
      || ! bfd_set_section_flags (dynobj, srelgot, SEC_ALLOC
                                  | SEC_LOAD
                                  | SEC_HAS_CONTENTS
                                  | SEC_IN_MEMORY
                                  | SEC_LINKER_CREATED
                                  | SEC_READONLY)
      || ! bfd_set_section_alignment (dynobj, srelgot, 2))
    return FALSE;
  return TRUE;
}

static bfd_boolean
microblaze_elf_create_dynamic_sections (bfd *dynobj, struct bfd_link_info *info)
{
  asection *s;

  if (!_bfd_elf_create_dynamic_sections (dynobj, info))
    return FALSE;
  if (!bfd_get_section_by_name(dynobj, ".rela.got")) {
    s = bfd_make_section (dynobj, ".rela.got");
    if (s == NULL
        || ! bfd_set_section_flags (dynobj, s,
                                    (SEC_ALLOC | SEC_LOAD | SEC_HAS_CONTENTS
                                     | SEC_IN_MEMORY | SEC_LINKER_CREATED
                                     | SEC_READONLY))
        || ! bfd_set_section_alignment (dynobj, s, 2))
      return FALSE;
  }
                                                                        
  return TRUE;
}

static bfd_boolean
microblaze_elf_adjust_dynamic_symbol (struct bfd_link_info *info,
                struct elf_link_hash_entry *h)
{
  return TRUE;
}

struct alloc_dynrel_arg {
  struct bfd_link_info *info;
  asection *sgot;
  asection *splt;
  asection *srelplt;
  asection *sgotplt;
  asection *srelgot;
};

static bfd_boolean allocate_dynrelocs (struct elf_link_hash_entry *, PTR);

/* Allocate space in .plt, .got and associated reloc sections for
   dynamic relocs.  */

static bfd_boolean
allocate_dynrelocs (h, dat)
     struct elf_link_hash_entry *h;
     PTR dat;
{
  struct bfd_link_info *info;
  struct alloc_dynrel_arg *arg;

  arg = (struct alloc_dynrel_arg *)dat;
  info = arg->info;

  if (h->root.type == bfd_link_hash_indirect)
    return TRUE;

  if (h->root.type == bfd_link_hash_warning)
    /* When warning symbols are created, they **replace** the "real"
       entry in the hash table, thus we never get to see the real
       symbol in a hash traversal.  So look at it now.  */
    h = (struct elf_link_hash_entry *) h->root.u.i.link;

  if (elf_hash_table (info)->dynamic_sections_created
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
          asection *s = arg->splt;

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
           arg->sgotplt->size += 4;
                     
          /* We also need to make an entry in the .rel.plt section.  */
          arg->srelplt->size += sizeof (Elf32_External_Rela);
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

      s = arg->sgot;
      h->got.offset = s->size;
      s->size += 4;
      arg->srelgot->size += sizeof (Elf32_External_Rela);
    }
  else
    h->got.offset = (bfd_vma) -1;

  return TRUE;
}

/* Set the sizes of the dynamic sections.  */

static bfd_boolean
microblaze_elf_size_dynamic_sections (output_bfd, info)
     bfd *output_bfd ATTRIBUTE_UNUSED;
     struct bfd_link_info *info;
{
  bfd *dynobj;
  asection *s, *sgot, *splt;
  bfd *ibfd;
  struct alloc_dynrel_arg dynrel_arg;

  dynobj = elf_hash_table (info)->dynobj;
  dynrel_arg.info = info;
  dynrel_arg.sgot = sgot = bfd_get_section_by_name (dynobj, ".got");
  dynrel_arg.splt = splt = bfd_get_section_by_name (dynobj, ".plt");
  dynrel_arg.srelgot = bfd_get_section_by_name (dynobj, ".rela.got");
  dynrel_arg.srelplt = bfd_get_section_by_name (dynobj, ".rela.plt");
  dynrel_arg.sgotplt = bfd_get_section_by_name (dynobj, ".got.plt");

  /* Set up .got offsets for local syms, and space for local dynamic
     relocs.  */
  for (ibfd = info->input_bfds; ibfd != NULL; ibfd = ibfd->link_next)
    {
      bfd_signed_vma *local_got;
      bfd_signed_vma *end_local_got;
      bfd_size_type locsymcount;
      Elf_Internal_Shdr *symtab_hdr;

      if (bfd_get_flavour (ibfd) != bfd_target_elf_flavour)
        continue;

      local_got = elf_local_got_refcounts (ibfd);
      if (!local_got)
        continue;

      symtab_hdr = &elf_tdata (ibfd)->symtab_hdr;
      locsymcount = symtab_hdr->sh_info;
      end_local_got = local_got + locsymcount;
      if (sgot == NULL)
        {
          /* fprintf(stderr, "creating .got section\n"); */
          create_got_section(output_bfd, dynobj);
          dynrel_arg.sgot = sgot = bfd_get_section_by_name (dynobj, ".got");
          dynrel_arg.srelgot = bfd_get_section_by_name (dynobj, ".rela.got");
        }
      for (; local_got < end_local_got; ++local_got)
        {
          if (*local_got > 0)
            {
              *local_got = sgot->size;
              sgot->size += 4;
              dynrel_arg.srelgot->size += sizeof (Elf32_External_Rela);
            }
          else
            *local_got = (bfd_vma) -1;
        }
    }

  /* Allocate global sym .plt and .got entries, and space for global
     sym dynamic relocs.  */
  elf_link_hash_traverse (elf_hash_table(info), allocate_dynrelocs, (PTR) &dynrel_arg);

  if (elf_hash_table (info)->dynamic_sections_created)
    {
      /* Make space for the trailing nop in .plt.  */
      if (splt->size > 0)
        splt->size += 4;

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
      else if (s != splt && s != sgot && s != dynrel_arg.sgotplt)
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

      if (splt->size != 0)
        {
          if (!add_dynamic_entry (DT_PLTGOT, 0)
              || !add_dynamic_entry (DT_PLTRELSZ, 0)
              || !add_dynamic_entry (DT_PLTREL, DT_REL)
              || !add_dynamic_entry (DT_JMPREL, 0))
            return FALSE;
        }
#if 0
      /* If any dynamic relocs apply to a read-only section,
         then we need a DT_TEXTREL entry.  */
      if ((info->flags & DF_TEXTREL) == 0)
        elf_link_hash_traverse (&htab->elf, readonly_dynrelocs,
                                (PTR) info);

      if (info->flags & DF_TEXTREL)
        {
          if (!add_dynamic_entry (DT_TEXTREL, 0))
            return FALSE;
        }
#endif
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
  struct elf_link_hash_table *htab;

  htab = elf_hash_table (info);
  dynobj = htab->dynobj;

  if (h->plt.offset != (bfd_vma) -1)
    {
      asection *splt;
      asection *srela;
      asection *sgotplt;
      splt = bfd_get_section_by_name (dynobj, ".plt");
      srela = bfd_get_section_by_name (dynobj, ".rela.plt");
      sgotplt = bfd_get_section_by_name (dynobj, ".got.plt");
      Elf_Internal_Rela rela;
      bfd_byte *loc;
      bfd_vma plt_index;
      bfd_vma got_offset;

      /* This symbol has an entry in the procedure linkage table.  Set
         it up.  */

      BFD_ASSERT (h->dynindx != -1);

      BFD_ASSERT (splt != NULL && srela != NULL);

      plt_index = h->plt.offset / PLT_ENTRY_SIZE - 1; /* first entry reserved */
      got_offset = (plt_index + 1) * 4; /* 1 reserved ??? */
      if (!info->shared)
        got_offset += sgotplt->output_section->vma + sgotplt->output_offset;

      /* Fill in the entry in the procedure linkage table.  */
      bfd_put_32 (output_bfd, PLT_ENTRY_WORD_0 + ((got_offset >> 16) & 0xffff),
                  splt->contents + h->plt.offset);
      bfd_put_32 (output_bfd, PLT_ENTRY_WORD_1 + (got_offset & 0xffff),
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
             the .plt section.  Leave the value alone.  */
          sym->st_shndx = SHN_UNDEF;
          /* If the symbol is weak, we do need to clear the value.
             Otherwise, the PLT entry would provide a definition for
             the symbol even if the symbol wasn't defined anywhere,
             and so the symbol would never be NULL.  */
          if (!h->ref_regular_nonweak)
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

      sgot = bfd_get_section_by_name (dynobj, ".got");
      srela = bfd_get_section_by_name (dynobj, ".rela.got");
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

#if 0
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
#endif

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
  struct elf_link_hash_table *htab;

  htab = elf_hash_table (info);
  dynobj = htab->dynobj;

  sdyn = bfd_get_section_by_name (dynobj, ".dynamic");

  if (htab->dynamic_sections_created)
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

  return TRUE;
}

#define TARGET_BIG_SYM          bfd_elf32_microblaze_vec
#define TARGET_BIG_NAME		"elf32-microblaze"

#define ELF_ARCH		bfd_arch_microblaze
#define ELF_MACHINE_CODE	EM_MICROBLAZE
#define ELF_MAXPAGESIZE		0x4   		/* 4k, if we ever have 'em */
#define elf_info_to_howto	microblaze_elf_info_to_howto
#define elf_info_to_howto_rel	NULL

#define bfd_elf32_bfd_reloc_type_lookup		microblaze_elf_reloc_type_lookup
#define bfd_elf32_bfd_is_local_label_name       microblaze_elf_is_local_label_name
#define elf_backend_relocate_section		microblaze_elf_relocate_section
#define bfd_elf32_bfd_relax_section             microblaze_elf_relax_section

/*#define bfd_elf32_bfd_set_private_flags		microblaze_elf_set_private_flags*/

#define elf_backend_gc_mark_hook		microblaze_elf_gc_mark_hook
#define elf_backend_gc_sweep_hook		microblaze_elf_gc_sweep_hook
#define elf_backend_check_relocs                microblaze_elf_check_relocs

#define elf_backend_can_gc_sections		1
#define elf_backend_can_refcount    		1
#define elf_backend_want_got_plt    		1
#define elf_backend_plt_readonly    		1
#define elf_backend_got_header_size 		4
#define elf_backend_rela_normal     		1

#define elf_backend_adjust_dynamic_symbol       microblaze_elf_adjust_dynamic_symbol
#define elf_backend_create_dynamic_sections     microblaze_elf_create_dynamic_sections
#define elf_backend_finish_dynamic_sections     microblaze_elf_finish_dynamic_sections
#define elf_backend_finish_dynamic_symbol       microblaze_elf_finish_dynamic_symbol
#define elf_backend_size_dynamic_sections       microblaze_elf_size_dynamic_sections

#include "elf32-target.h"
