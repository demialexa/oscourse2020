#ifndef JOS_INC_MEMLAYOUT_H
#define JOS_INC_MEMLAYOUT_H

#ifndef __ASSEMBLER__
#include <inc/types.h>
#include <inc/mmu.h>
#endif /* not __ASSEMBLER__ */

/*
 * This file contains definitions for memory management in our OS,
 * which are relevant to both the kernel and user-mode software.
 */

/* Global descriptor numbers */
#define GD_KT   0x08 /* kernel text */
#define GD_KD   0x10 /* kernel data */
#define GD_KT32 0x18 /* kernel text 32bit */
#define GD_KD32 0x20 /* kernel data 32bit */
#define GD_UT   0x28 /* user text */
#define GD_UD   0x30 /* user data */
#define GD_TSS0 0x38 /* Task segment selector for CPU 0 */

/*
 * Virtual memory map:                                Permissions
 *                                                    kernel/user
 *
 *     1 TB -------->  +------------------------------+
 *                     |                              | RW/--
 *                     ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *                     :              .               : 0x1
 *                     :              .               :
 *                     :              .               :
 *                     |~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~| RW/--
 *                     |                              | RW/--
 *                     |   Remapped Physical Memory   | RW/--
 *                     |                              | RW/--
 *    KERNBASE, ---->  +------------------------------+ 0x8040000000    --+
 *    KSTACKTOP        |     CPU0's Kernel Stack      | RW/--  KSTKSIZE   |
 *                     | - - - - - - - - - - - - - - -|                   |
 *                     |      Invalid Memory (*)      | --/--  KSTKGAP    |
 *                     +------------------------------+                   |
 *                     |     CPU1's Kernel Stack      | RW/--  KSTKSIZE   |
 *                     | - - - - - - - - - - - - - - -|                 HUGE_PAGE_SIZE
 *                     |      Invalid Memory (*)      | --/--  KSTKGAP    |
 *                     +------------------------------+                   |
 *                     :              .               :                   |
 *                     :              .               :                   |
 *    MMIOLIM ------>  +------------------------------+ 0x803fe00000    --+
 *                     |       Memory-mapped I/O      | RW/--  HUGE_PAGE_SIZE
 * ULIM, MMIOBASE -->  +------------------------------+ 0x803fc00000
 *                     |          RO PAGES            | R-/R-
 *                     .                              .
 *                     .                              .        400 * HUGE_PAGE_SIZE
 *                     .                              .
 *    UPAGES    ---->  +------------------------------+ 0x8000dc0000
 *                     |           RO ENVS            | R-/R-  HUGE_PAGE_SIZE
 * UENVS ----------->  +------------------------------+ 0x8000da0000
 *                     |                              |
 *                     |                              |
 *                     ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *                     .                              .
 *                     .                              .
 * UTOP,               .                              .
 * UXSTACKTOP ------>  +------------------------------+ 0x8000000000
 *                     |     User Exception Stack     | RW/RW  PAGE_SIZE
 *                     +------------------------------+ 0x7ffffff000
 *                     |       Empty Memory (*)       | --/--  PAGE_SIZE
 *    USTACKTOP  --->  +------------------------------+ 0x7fffffe000
 *                     |      Normal User Stack       | RW/RW  PAGE_SIZE
 *                     +------------------------------+ 0x7fffffd000
 *                     |                              |
 *                     |                              |
 *                     ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *                     .                              .
 *                     .                              .
 *                     .                              .
 *                     |~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~|
 *                     |     Program Data & Heap      |
 *    UTEXT -------->  +------------------------------+ 0x00800000
 *    PFTEMP ------->  |       Empty Memory (*)       |        2* HUGE_PAGE_SIZE
 *                     |                              |
 *    UTEMP -------->  +------------------------------+ 0x00400000      --+
 *                     |       Empty Memory (*)       |                   |
 *                     | - - - - - - - - - - - - - - -|                   |
 *                     |  User STAB Data (optional)   |                2* HUGE_PAGE_SIZE
 *    USTABDATA ---->  +------------------------------+ 0x00200000        |
 *                     |       Empty Memory (*)       |                   |
 *    0 ------------>  +------------------------------+                 --+
 *
 * (*) Note: The kernel ensures that "Invalid Memory" (ULIM) is *never*
 *     mapped.  "Empty Memory" is normally unmapped, but user programs may
 *     map pages there if desired.  JOS user programs map pages temporarily
 *     at UTEMP.
 */

/* All physical memory mapped at this address */
#define KERNBASE 0x8040000000

/* At IOPHYSMEM (640K) there is a 384K hole for I/O.  From the kernel,
 * IOPHYSMEM can be addressed at KERNBASE + IOPHYSMEM.  The hole ends
 * at physical address EXTPHYSMEM. */
#define IOPHYSMEM  0x0A0000
#define EXTPHYSMEM 0x100000

/* Amount of memory mapped by entrypgdir */
#define BOOTMEMSIZE (1024 * 1024 * 1024)

/* Kernel stack */
#define KSTACKTOP KERNBASE
#define PSTKSIZE  (2 * PAGE_SIZE)  /* size of a process stack */
#define KSTKSIZE  (16 * PAGE_SIZE) /* size of a kernel stack */
#define KSTKGAP   (8 * PAGE_SIZE)  /* size of a kernel stack guard */

/* Memory-mapped IO */
#define MMIOLIM  (KSTACKTOP - HUGE_PAGE_SIZE)
#define MMIOBASE (MMIOLIM - HUGE_PAGE_SIZE)

/* Memory-mapped FrameBuffer */
#define FBUFFBASE (MMIOBASE - FBUFF_SIZE)

#define ULIM (FBUFFBASE)

/*
 * User read-only mappings! Anything below here til UTOP are readonly to user.
 * They are global pages mapped in at env allocation time.
 */

/* User read-only virtual page table (see 'uvpt' below) */
#define UVPT_INDEX 2ULL
#define UVPT (UVPT_INDEX << PML4_SHIFT)
#define UVPD (UVPT + (UVPT_INDEX << PDP_SHIFT))
#define UVPDP (UVPD + (UVPT_INDEX << PD_SHIFT))
#define UVPML4 (UVPDP + (UVPT_INDEX << PT_SHIFT))

/* Read-only copies of the Page structures (sizeof == 400 * HUGE_PAGE_SIZE so that all
 * struct PageInfo of up to 512GiB pages can fit here). */
#define UPAGES (ULIM - UPAGES_SIZE)

/* Read-only copies of the global env structures */
#define UENVS (UPAGES - HUGE_PAGE_SIZE)

/*
 * Top of user VM. User can manipulate VA from UTOP-1 and down!
 */

/* Top of user-accessible VM */
#define UTOP 0x8000000000
/* Top of one-page user exception stack */
#define UXSTACKTOP UTOP
/* Size of exception stack (must be one page for now) */
#define UXSTACKSIZE (4 * PAGE_SIZE)
/* Top of normal user stack */
/* Next page left invalid to guard against exception stack overflow; then: */
#define USTACKTOP (UXSTACKTOP - UXSTACKSIZE - PAGE_SIZE)
/* Stack size (variable) */
#define USTACKSIZE (4 * PAGE_SIZE)
// Max number of open files in the file system at once
#define MAXOPEN 512
#define FILEVA  0xD0000000

#ifdef SANITIZE_USER_SHADOW_OFF
/* User stack and some other tables are located at higher addresses,
 * so we need to map a separate shadow for it. */
#define SANITIZE_USER_EXTRA_SHADOW_BASE (((UENVS >> 3) + SANITIZE_USER_SHADOW_OFF) & ~(PAGE_SIZE - 1))
#define SANITIZE_USER_EXTRA_SHADOW_SIZE ((ULIM - UENVS) >> 3)

#define SANITIZE_USER_STACK_SHADOW_BASE ((((USTACKTOP - USTACKSIZE) >> 3) + SANITIZE_USER_SHADOW_OFF) & ~(PAGE_SIZE - 1))
#define SANITIZE_USER_STACK_SHADOW_SIZE ((USTACKSIZE + UXSTACKSIZE + PAGE_SIZE) >> 3)

/* File system is located at another specific address space */
#define SANITIZE_USER_FS_SHADOW_BASE ((FILEVA >> 3) + SANITIZE_USER_SHADOW_OFF)
#define SANITIZE_USER_FS_SHADOW_SIZE ((((MAXOPEN * PAGE_SIZE) >> 3) + (PAGE_SIZE - 1)) & ~(PAGE_SIZE - 1))

/* UVPT is located at another specific address space */
#define SANITIZE_USER_VPT_SHADOW_BASE ((UVPT >> 3) + SANITIZE_USER_SHADOW_OFF)
#define SANITIZE_USER_VPT_SHADOW_SIZE ((((UVPT_SIZE + UVPD_SIZE + UVPDP_SIZE + UVPML4_SIZE) >> 3) + (PAGE_SIZE - 1)) & ~(PAGE_SIZE - 1))
#endif

/* Where user programs generally begin */
#define UTEXT (4 * HUGE_PAGE_SIZE)

/* Used for temporary page mappings.  Typed 'void*' for convenience */
#define UTEMP ((void *)(2 * HUGE_PAGE_SIZE))
/* Used for temporary page mappings for the user page-fault handler
 * (should not conflict with other temporary page mappings) */
#define PFTEMP (UTEMP + HUGE_PAGE_SIZE - PAGE_SIZE)
/* The location of the user-level STABS data structure */
#define USTABDATA (HUGE_PAGE_SIZE)

#ifndef __ASSEMBLER__

typedef uint64_t pml4e_t;
typedef uint64_t pdpe_t;
typedef uint64_t pde_t;
typedef uint64_t pte_t;

#ifndef JOS_PROG
/*
 * The page directory entry corresponding to the virtual address range
 * [UVPT, UVPT + HUGE_PAGE_SIZE) points to the page directory itself.  Thus, the page
 * directory is treated as a page table as well as a page directory.
 *
 * One result of treating the page directory as a page table is that all PTEs
 * can be accessed through a "virtual page table" at virtual address UVPT (to
 * which uvpt is set in entry.S).  The PTE for page number N is stored in
 * uvpt[N].  (It's worth drawing a diagram of this!)
 *
 * A second consequence is that the contents of the current page directory
 * will always be available at virtual address (UVPT + (UVPT >> PGSHIFT)), to
 * which uvpd is set in entry.S.
 */
extern volatile pte_t uvpt[];      /* VA of "virtual page table" */
extern volatile pde_t uvpd[];      /* VA of current page directory */
extern volatile pdpe_t uvpdp[];    /* VA of current page directory pointer */
extern volatile pml4e_t uvpml4[]; /* VA of current page map level 4 */
#endif

/*
 * Page descriptor structures, mapped at UPAGES.
 * Read/write to the kernel, read-only to user programs.
 *
 * Each struct PageInfo stores metadata for one physical page.
 * Is it NOT the physical page itself, but there is a one-to-one
 * correspondence between physical pages and struct PageInfo's.
 * You can map a struct PageInfo * to the corresponding physical address
 * with page2pa() in kern/pmap.h.
 */

struct PageInfo {
  /* Next page on the free list */
  struct PageInfo *pp_link;

  /* pp_ref is the count of pointers minus one (usually in page table entries)
   * to this page, for pages allocated using page_alloc.
   *
   * Pages allocated at boot time using pmap.c's
   * boot_alloc do not have valid reference count fields
   *
   * page_alloc sets pp_ref to 0 (i.e. 1 pointer)
   * so code that allocates a page and then inserts
   * it to the page table should call page_decref
   * after useage (or page_free if there is exactly once pointer left)
   */

  uint32_t pp_ref;
};

#endif /* !__ASSEMBLER__ */
#endif /* !JOS_INC_MEMLAYOUT_H */
