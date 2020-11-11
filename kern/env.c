/* See COPYRIGHT for copyright information. */

#include <inc/x86.h>
#include <inc/mmu.h>
#include <inc/error.h>
#include <inc/string.h>
#include <inc/assert.h>
#include <inc/elf.h>

#include <kern/env.h>
#include <kern/pmap.h>
#include <kern/trap.h>
#include <kern/monitor.h>
#include <kern/sched.h>
#include <kern/kdebug.h>
#include <kern/macro.h>
#include <kern/pmap.h>

/* Currently active environment */
struct Env *curenv = NULL;

#ifdef CONFIG_KSPACE
/* All environments */
struct Env env_array[NENV];
struct Env *envs   = env_array;
#else
/* All environments */
struct Env *envs   = NULL;
#endif

/* Free environment list
 * (linked by Env->env_link) */
static struct Env *env_free_list;


/* NOTE: Should be at least LOGNENV */
#define ENVGENSHIFT 12

/* Global descriptor table.
 *
 * Set up global descriptor table (GDT) with separate segments for
 * kernel mode and user mode.  Segments serve many purposes on the x86.
 * We don't use any of their memory-mapping capabilities, but we need
 * them to switch privilege levels.
 *
 * The kernel and user segments are identical except for the DPL.
 * To load the SS register, the CPL must equal the DPL.  Thus,
 * we must duplicate the segments for the user and the kernel.
 *
 * In particular, the last argument to the SEG macro used in the
 * definition of gdt specifies the Descriptor Privilege Level (DPL)
 * of that descriptor: 0 for kernel and 3 for user. */
struct Segdesc gdt[2 * NCPU + 7] = {
    /* 0x0 - unused (always faults -- for trapping NULL far pointers) */
    SEG_NULL,
    /* 0x8 - kernel code segment */
    [GD_KT >> 3] = SEG64(STA_X | STA_R, 0x0, 0xFFFFFFFF, 0),
    /* 0x10 - kernel data segment */
    [GD_KD >> 3] = SEG64(STA_W, 0x0, 0xFFFFFFFF, 0),
    /* 0x18 - kernel code segment 32bit */
    [GD_KT32 >> 3] = SEG(STA_X | STA_R, 0x0, 0xFFFFFFFF, 0),
    /* 0x20 - kernel data segment 32bit */
    [GD_KD32 >> 3] = SEG(STA_W, 0x0, 0xFFFFFFFF, 0),
    /* 0x28 - user code segment */
    [GD_UT >> 3] = SEG64(STA_X | STA_R, 0x0, 0xFFFFFFFF, 3),
    /* 0x30 - user data segment */
    [GD_UD >> 3] = SEG64(STA_W, 0x0, 0xFFFFFFFF, 3),
    /* Per-CPU TSS descriptors (starting from GD_TSS0) are initialized
     * in trap_init_percpu() */
    [GD_TSS0 >> 3] = SEG_NULL,

    [8] = SEG_NULL //last 8 bytes of the tss since tss is 16 bytes long
};

struct Pseudodesc gdt_pd = { sizeof(gdt) - 1, (unsigned long)gdt };

/* Converts an envid to an env pointer.
 * If checkperm is set, the specified environment must be either the
 * current environment or an immediate child of the current environment.
 *
 * RETURNS
 *     0 on success, -E_BAD_ENV on error.
 *   On success, sets *env_store to the environment.
 *   On error, sets *env_store to NULL. */
int
envid2env(envid_t envid, struct Env **env_store, bool need_check_perm) {
  struct Env *env;

  /* If envid is zero, return the current environment. */
  if (!envid) {
    *env_store = curenv;
    return 0;
  }

  /* Look up the Env structure via the index part of the envid,
   * then check the env_id field in that struct Env
   * to ensure that the envid is not stale
   * (i.e., does not refer to a _previous_ environment
   * that used the same slot in the envs[] array). */
  env = &envs[ENVX(envid)];
  if (env->env_status == ENV_FREE || env->env_id != envid) {
    *env_store = NULL;
    return -E_BAD_ENV;
  }

  /* Check that the calling environment has legitimate permission
   * to manipulate the specified environment.
   * If checkperm is set, the specified environment
   * must be either the current environment
   * or an immediate child of the current environment. */
  if (need_check_perm && env != curenv && env->env_parent_id != curenv->env_id) {
    *env_store = NULL;
    return -E_BAD_ENV;
  }

  *env_store = env;
  return 0;
}

/* Load GDT and segment descriptors. */
static void
env_init_percpu(void) {
  lgdt(&gdt_pd);

  /* The kernel never uses GS or FS,
   * so we leave those set to the user data segment
   *
   * For good measure, clear the local descriptor table (LDT),
   * since we don't use it */
  asm volatile("movw %%dx,%%gs\n\t"
               "movw %%dx,%%fs\n\t"
               "movw %%ax,%%es\n\t"
               "movw %%ax,%%ds\n\t"
               "movw %%ax,%%ss\n\t"
               "xorl %%eax,%%eax\n\t"
               "lldt %%ax\n\t"
               "pushq %%rcx\n\t"
               "movabs $1f,%%rax\n\t"
               "pushq %%rax\n\t"
               "lretq\n"
            "1:\n"
               :: "a"(GD_KD), "d"(GD_UD | 3), "c"(GD_KT)
               : "cc", "memory");
}

/* Mark all environments in 'envs' as free, set their env_ids to 0,
 * and insert them into the env_free_list.
 * Make sure the environments are in the free list in the same order
 * they are in the envs array (i.e., so that the first call to
 * env_alloc() returns envs[0]).
 */
void
env_init(void) {
  /* Set up envs array */

  // LAB 3: Your code here.
  env_free_list = NULL;
  for (int i = NENV - 1; i >= 0; i--) {
    envs[i].env_link = env_free_list;
    envs[i].env_id = 0;
    env_free_list = &envs[i];
  }

  /* Init CPU context */
  env_init_percpu();
}

/* Allocate len bytes of physical memory for environment env,
 * and map it at virtual address va in the environment's address space.
 * Does not zero or otherwise initialize the mapped pages in any way.
 * Pages should be writable by user and kernel.
 * Panic if any allocation attempt fails. */
static int
region_alloc(struct Env *env, void *va, size_t len) {
  // LAB 8: Your code here:
  /* (But only if you need it for load_icode.)
   *
   * Hint: It is easier to use region_alloc if the caller can pass
   *   'va' and 'len' values that are not page-aligned.
   *   You should round va down, and round (va + len) up.
   *   (Watch out for corner-cases!) */

  void *end = ROUNDUP(va + len, PGSIZE);
  va = ROUNDDOWN(va, PGSIZE);
  len = end - va;
  cprintf ("region: %p %lu -> %p\n", va, len, end);

  for (size_t i = 0; i < len; i += PGSIZE, va += PGSIZE) {
      struct PageInfo *pi = page_alloc(0);
      if (!pi) return -E_NO_MEM;
      page_insert(env->env_pml4e, pi, va, PTE_U | PTE_W);
      page_decref(pi);
  }

  return 0;
}

/* Initialize the kernel virtual memory layout for environment e.
 * Allocate a page directory, set e->env_pgdir accordingly,
 * and initialize the kernel portion of the new environment's address space.
 * Do NOT (yet) map anything into the user portion
 * of the environment's virtual address space.
 *
 * Returns 0 on success, < 0 on error.  Errors include:
 *  -E_NO_MEM if page directory or table could not be allocated. */
static int
env_setup_vm(struct Env *env) {

  /* Now, set e->env_pgdir and initialize the page directory.
   *
   * Hint:
   *    - The VA space of all envs is identical above UTOP
   *    (except at UVPT, which we've set below).
   *    See inc/memlayout.h for permissions and layout.
   *    Can you use kern_pgdir as a template?  Hint: Yes.
   *    (Make sure you got the permissions right in Lab 7.)
   *    - The initial VA below UTOP is empty.
   *    - You do not need to make any more calls to page_alloc.
   *    - Note: In general, pp_ref is not maintained for
   *    physical pages mapped only above UTOP, but env_pgdir
   *    is an exception -- you need to increment env_pgdir's
   *    pp_ref for env_free to work correctly.
   *    - The functions in kern/pmap.h are handy. */

  // LAB 8: Your code here:

  /* Allocate a page for the page directory */
  struct PageInfo *pi = page_alloc(ALLOC_ZERO);
  if (!pi) return -E_NO_MEM;

#define NUSERPML4 1

  /* page table pp_ref */
  for (size_t i = NUSERPML4; i < NPMLENTRIES; i++)
    if (kern_pml4e[i] & PTE_P && i != PML4(UVPT) && i != PML4(UVPD))
      pa2page(PTE_ADDR(kern_pml4e[i]))->pp_ref++;

  env->env_pml4e = page2kva(pi);
  env->env_cr3 = page2pa(pi);

  /* Share pages between kernel space and userspace */
  memcpy(env->env_pml4e + NUSERPML4, kern_pml4e + NUSERPML4,
          PGSIZE - NUSERPML4 * sizeof(pml4e_t));
  memset(env->env_pml4e, 0, NUSERPML4 * sizeof(pml4e_t));

  env->env_pml4e[PML4(UVPT)] = env->env_cr3 | PTE_P | PTE_U;

  return 0;
}

/* Allocates and initializes a new environment.
 * On success, the new environment is stored in *newenv_store.
 *
 * Returns
 *     0 on success, < 0 on failure.
 * Errors
 *    -E_NO_FREE_ENV if all NENVS environments are allocated
 *    -E_NO_MEM on memory exhaustion
 */
int
env_alloc(struct Env **newenv_store, envid_t parent_id, enum EnvType type) {

  struct Env *env;
  if (!(env = env_free_list))
    return -E_NO_FREE_ENV;

  /* Allocate and set up the page directory for this environment. */
  int res = env_setup_vm(env);
  if (res < 0) return res;

  /* Generate an env_id for this environment */
  int32_t generation = (env->env_id + (1 << ENVGENSHIFT)) & ~(NENV - 1);
  /* Don't create a negative env_id */
  if (generation <= 0) generation = 1 << ENVGENSHIFT;
  env->env_id = generation | (env - envs);

  /* Set the basic status variables */
  env->env_parent_id = parent_id;
#ifdef CONFIG_KSPACE
  env->env_type = ENV_TYPE_KERNEL;
#else
  env->env_type = type;
#endif
  env->env_status = ENV_RUNNABLE;
  env->env_runs = 0;

  /* Clear out all the saved register state,
   * to prevent the register values
   * of a prior environment inhabiting this Env structure
   * from "leaking" into our new environment */
  memset(&env->env_tf, 0, sizeof(env->env_tf));

  /* Set up appropriate initial values for the segment registers.
   * GD_UD is the user data (KD - kernel data) segment selector in the GDT, and
   * GD_UT is the user text (KT - kernel text) segment selector (see inc/memlayout.h).
   * The low 2 bits of each segment register contains the
   * Requestor Privilege Level (RPL); 3 means user mode, 0 - kernel mode.  When
   * we switch privilege levels, the hardware does various
   * checks involving the RPL and the Descriptor Privilege Level
   * (DPL) stored in the descriptors themselves */


#ifdef CONFIG_KSPACE
  e->env_tf.tf_ds = GD_KD | 0;
  e->env_tf.tf_es = GD_KD | 0;
  e->env_tf.tf_ss = GD_KD | 0;
  e->env_tf.tf_cs = GD_KT | 0;

  // LAB 3: Your code here:
  static uintptr_t stack_top = 0x2000000;
  env->env_tf.tf_rsp = stack_top;
  stack_top -= USTACKSIZE;
#else
  env->env_tf.tf_ds  = GD_UD | 3;
  env->env_tf.tf_es  = GD_UD | 3;
  env->env_tf.tf_ss  = GD_UD | 3;
  env->env_tf.tf_cs  = GD_UT | 3;
  env->env_tf.tf_rsp = USTACKTOP;
#endif

  /* For now init trapframe with IF set */
  env->env_tf.tf_rflags = FL_IF | FL_IOPL_0;

  /* Clear the page fault handler until user installs one. */
  env->env_pgfault_upcall = 0;

  /* Also clear the IPC receiving flag. */
  env->env_ipc_recving = 0;

  /* Commit the allocation */
  env_free_list = env->env_link;
  *newenv_store = env;

  cprintf("[%08x] new env %08x\n", curenv ? curenv->env_id : 0, env->env_id);
  return 0;
}

static int
bind_functions(struct Env *e, uint8_t *binary, size_t size, uintptr_t image_start, uintptr_t image_end) {
  // LAB 3: Your code here:

  /* NOTE: find_function from kdebug.c should be used */

  struct Elf *elf = (struct Elf *)binary;
  struct Secthdr *sh = (struct Secthdr *)(binary + elf->e_shoff);
  const char *shstr = (char *)binary + sh[elf->e_shstrndx].sh_offset;

  if ((uint8_t *)(shstr + sh[elf->e_shstrndx].sh_size) > binary + size) {
    cprintf("String table exceeds file contents: %lu > %lu\n",
            (unsigned long)((uint8_t *)shstr - binary), (unsigned long)size);
    return -E_INVALID_EXE;
  }

  /* Find string table */
  size_t strtab = -1UL;
  for (size_t i = 0; i < elf->e_shnum; i++) {
    if (sh[i].sh_name > sh[elf->e_shstrndx].sh_size) {
      cprintf("String table exceeds string table: %lu > %lu\n",
              (unsigned long)sh[i].sh_name, (unsigned long)sh[elf->e_shstrndx].sh_size);
      return -E_INVALID_EXE;
    }

    if (sh[i].sh_type == ELF_SHT_STRTAB && !strcmp(".strtab", shstr + sh[i].sh_name)) {
      strtab = i;
      break;
    }
  }

  if (strtab == -1UL) {
    cprintf("String table is absent\n");
    return 0;
  }

  const char *strings = (char *)binary + sh[strtab].sh_offset;

  if ((uint8_t *)(strings + sh[strtab].sh_size) > binary + size) {
    cprintf("String table exceeds file contents: %lu > %lu\n",
            (unsigned long)((uint8_t *)strings + sh[strtab].sh_size - binary), (unsigned long)size);
    return -E_INVALID_EXE;
  }

  if (!sh[strtab].sh_size) {
    cprintf("String table is empty\n");
    return -E_INVALID_EXE;
  }

  if (binary[sh[strtab].sh_offset + sh[strtab].sh_size - 1]) {
    cprintf("String table is not NUL-terminated\n");
    return -E_INVALID_EXE;
  }

  for (size_t i = 0; i < elf->e_shnum; i++) {
    if (sh[i].sh_type == ELF_SHT_SYMTAB) {

      struct Elf64_Sym *syms = (struct Elf64_Sym *)(binary + sh[i].sh_offset);

      if (sh[i].sh_offset + sh[i].sh_size > size) {
        cprintf("Symbol table exceeds file contents: %lu > %lu\n",
                (unsigned long)(sh[i].sh_offset + sh[i].sh_size), (unsigned long)size);
        return -E_INVALID_EXE;
      }

      if (sh[i].sh_entsize != sizeof(*syms)) {
        cprintf("Unexpected symbol size: %lu\nShould be: %lu\n",
                (unsigned long)sh[i].sh_entsize, (unsigned long)sizeof(*syms));
        return -E_INVALID_EXE;
      }

      size_t nsyms = sh[i].sh_size / sizeof(*syms);

      for (size_t j = 0; j < nsyms; j++) {
        /* Only handle symbols that we know how to bind */
        if (ELF64_ST_BIND(syms[j].st_info) == STB_GLOBAL &&
            ELF64_ST_TYPE(syms[j].st_info) == STT_OBJECT &&
            syms[j].st_other == STV_DEFAULT &&
            syms[j].st_size == sizeof(void *)) {

          const char *name = strings + syms[j].st_name;

          if (name > strings + sh[strtab].sh_size) {
            cprintf("String table exceeds string table: %lu > %lu\n",
                    (unsigned long)syms[j].st_name, (unsigned long)sh[strtab].sh_size);
            return -E_INVALID_EXE;
          }

          if (syms[j].st_value < image_start || syms[j].st_value > image_end) {
            cprintf("Symbol value points outside program image: %p\n",
                    (uint8_t *)syms[j].st_value);
            return -E_INVALID_EXE;
          }

          uintptr_t addr = find_function(name);
          if (addr) {
            cprintf("Bind function '%s' to %p\n", name, (void *)addr);
            memcpy((void *)syms[j].st_value, &addr, sizeof(void *));
          }
        }
      }
    }
  }
  return 0;
}

#ifdef SANITIZE_USER_SHADOW_BASE

/* Map UVP shadow memory and create pages if necessary */
struct PageInfo *uvpt_pages = NULL;
void
uvpt_shadow_map(struct Env *e) {
  uintptr_t va = ROUNDDOWN((uintptr_t)SANITIZE_USER_VPT_SHADOW_BASE, PGSIZE);
  uintptr_t vend = ROUNDUP((uintptr_t)SANITIZE_USER_VPT_SHADOW_BASE + SANITIZE_USER_VPT_SHADOW_SIZE, PGSIZE);

  for (struct PageInfo **link = &uvpt_pages; va < vend; va += PGSIZE) {
    if (!*link) *link = page_alloc(ALLOC_ZERO);

    int res = page_insert(e->env_pml4e, *link, (void *)va, PTE_U | PTE_W);
    if (res < 0) panic("Cannot allocate any memory for uvpt shadow mem");

    link = &(*link)->pp_link;
  }
}
#endif

/* Set up the initial program binary, stack, and processor flags
 * for a user process.
 * This function is ONLY called during kernel initialization,
 * before running the first environment.
 *
 * This function loads all loadable segments from the ELF binary image
 * into the environment's user memory, starting at the appropriate
 * virtual addresses indicated in the ELF program header.
 * At the same time it clears to zero any portions of these segments
 * that are marked in the program header as being mapped
 * but not actually present in the ELF file - i.e., the program's bss section.
 *
 * All this is very similar to what our boot loader does, except the boot
 * loader also needs to read the code from disk.  Take a look at
 * boot/main.c to get ideas.
 *
 * Finally, this function maps one page for the program's initial stack.
 *
 * load_icode returns -E_INVALID_EXE if it encounters problems.
 *  - How might load_icode fail?  What might be wrong with the given input?
 *
 * Hints:
 *   Load each program segment into memory
 *   at the address specified in the ELF section header.
 *   You should only load segments with ph->p_type == ELF_PROG_LOAD.
 *   Each segment's address can be found in ph->p_va
 *   and its size in memory can be found in ph->p_memsz.
 *   The ph->p_filesz bytes from the ELF binary, starting at
 *   'binary + ph->p_offset', should be copied to address
 *   ph->p_va.  Any remaining memory bytes should be cleared to zero.
 *   (The ELF header should have ph->p_filesz <= ph->p_memsz.)
 *   Use functions from the previous labs to allocate and map pages.
 *
 *   All page protection bits should be user read/write for now.
 *   ELF segments are not necessarily page-aligned, but you can
 *   assume for this function that no two segments will touch
 *   the same page.
 *
 *   You may find a function like region_alloc useful.
 *
 *   Loading the segments is much simpler if you can move data
 *   directly into the virtual addresses stored in the ELF binary.
 *   So which page directory should be in force during
 *   this function?
 *
 *   You must also do something with the program's entry point,
 *   to make sure that the environment starts executing there.
 *   What?  (See env_run() and env_pop_tf() below.) */
static int
load_icode(struct Env *env, uint8_t *binary, size_t size) {
  // LAB 3: Your code here:
  // LAB 8: Your code here:

  if (size < sizeof(struct Elf)) {
    cprintf("Elf file is too small: %lu\n", size);
    return -E_INVALID_EXE;
  }

  struct Elf *elf = (struct Elf *)binary;
  if (elf->e_magic != ELF_MAGIC ||
      elf->e_elf[0] != 2 /* 64-bit */ ||
      elf->e_elf[1] != 1 /* little endian */ ||
      elf->e_elf[2] != 1 /* version 1 */ ||
      elf->e_type != ET_EXEC /* executable */ ||
      elf->e_machine != 0x3E /* amd64 */) {
    cprintf("Unexpected ELF format\n");
    return -E_INVALID_EXE;
  }

  if (elf->e_ehsize < (sizeof(struct Elf))) {
    cprintf("ELF header is too smal: %u \nShould be at least %u\n",
            (unsigned)elf->e_ehsize, (unsigned)sizeof(struct Elf));
    return -E_INVALID_EXE;
  }

  if (elf->e_shentsize != sizeof(struct Secthdr)) {
    cprintf("Unexpected section header size %u\n Should be %u\n",
            (unsigned)elf->e_shentsize, (unsigned)sizeof(struct Secthdr));
    return -E_INVALID_EXE;
  }

  if (elf->e_phentsize != sizeof(struct Proghdr)) {
    cprintf("Unexpected program header size %u\n Should be %u\n",
            (unsigned)elf->e_phentsize, (unsigned)sizeof(struct Proghdr));
    return -E_INVALID_EXE;
  }

  if (elf->e_shstrndx >= elf->e_shnum) {
    cprintf("Unexpected string section %u overflows total number of sections %u\n",
            (unsigned)elf->e_shstrndx, (unsigned)elf->e_shnum);
    return -E_INVALID_EXE;
  }

  struct Secthdr *sh = (struct Secthdr *)(binary + elf->e_shoff);
  if ((uint8_t *)(sh + elf->e_shnum) > binary + size) {
    cprintf("Section table exceeds file contents: %lu > %lu\n",
            (unsigned long)((uint8_t *)(sh + elf->e_shnum) - binary), size);
    return -E_INVALID_EXE;
  }
  if (sh[elf->e_shstrndx].sh_type != ELF_SHT_STRTAB) {
    cprintf("String table section index points to section of other type %d\n",
            (unsigned)sh->sh_type);
    return -E_INVALID_EXE;
  }
  if (sh[elf->e_shstrndx].sh_offset + sh[elf->e_shstrndx].sh_size > size) {
    cprintf("String table size exceeds file size: %lu > %lu\n",
            (unsigned long)(sh[elf->e_shstrndx].sh_offset + sh[elf->e_shstrndx].sh_size), (unsigned long)size);
    return -E_INVALID_EXE;
  }
  if (!sh[elf->e_shstrndx].sh_size) {
    cprintf("String table is empty\n");
    return -E_INVALID_EXE;
  }
  if (binary[sh[elf->e_shstrndx].sh_offset + sh[elf->e_shstrndx].sh_size - 1]) {
    cprintf("String table is not NUL-terminated\n");
    return -E_INVALID_EXE;
  }

  struct Proghdr *ph = (struct Proghdr *)(binary + elf->e_phoff);
  if ((uint8_t *)(ph + elf->e_phnum) > binary + size) {
    cprintf("Program header table exceeds file contents: %lu > %lu\n",
            (unsigned long)((uint8_t *)(ph + elf->e_phnum) - binary), size);
    return -E_INVALID_EXE;
  }

  uintptr_t cr3 = rcr3();
  lcr3(env->env_cr3);

  uintptr_t min_addr = UTOP, max_addr = 0;
  for (size_t i = 0; i < elf->e_phnum; i++) {
    if (ph[i].p_type == ELF_PROG_LOAD) {

      min_addr = MIN(min_addr, ph[i].p_va);
      max_addr = MAX(max_addr, ph[i].p_va + ph[i].p_memsz);

      void *src = binary + ph[i].p_offset;
      void *dst = (void *)ph[i].p_va;

      size_t memsz  = ph[i].p_memsz;
      size_t filesz = MIN(ph[i].p_filesz, memsz);

      if ((uint8_t *)src + filesz > binary + size) {
        lcr3(cr3);
        cprintf("Section contents exceeds file size: %lu > %lu\n",
                (unsigned long)((uint8_t *)(src + filesz) - binary), size);
        return -E_INVALID_EXE;
      }

      if ((uintptr_t)dst + memsz > UTOP) {
        lcr3(cr3);
        cprintf("Section contents exceeds user memory: %p > %p\n", (dst + memsz), (void *)UTOP);
        return -E_INVALID_EXE;
      }

      cprintf("Loading section of size 0x%08lX/0x%08lX to %p...\n",
          (unsigned long)filesz, (unsigned long)memsz, dst);

      if (region_alloc(env, dst, memsz)) {
        lcr3(cr3);
        cprintf("Out of memory");
        return -E_NO_MEM;
      }

      memset(dst + filesz, 0, memsz - filesz);
      memcpy(dst, src, filesz);
    }
  }

  lcr3(cr3);

  if (max_addr <= min_addr || max_addr >= UTOP) {
    cprintf("Invalid memory mappings\n");
    return -E_INVALID_EXE;
  }

  if (elf->e_entry >= max_addr || elf->e_entry < min_addr) {
    cprintf("Program entry point %lu is outside proram data\n",
            (unsigned long)elf->e_entry);
    return -E_INVALID_EXE;
  }

  /* Set progrma entry point */
  env->env_tf.tf_rip = elf->e_entry;
  cprintf("Program entry point %lx\n", (unsigned long)elf->e_entry);

  int res = bind_functions(env, binary, size, min_addr, max_addr);
  if (res < 0) {
    cprintf("Failed to bind functions: %i\n", res);
    return res;
  }

  /* Allocate stack for new task */
  res = region_alloc(env, (void *)(USTACKTOP - USTACKSIZE), USTACKSIZE);
  if (res < 0) return res;

#ifdef SANITIZE_USER_SHADOW_BASE
  void uvpt_shadow_map(struct Env *e);
  uvpt_shadow_map(env);
  res = region_alloc(env, (void *)SANITIZE_USER_SHADOW_BASE, SANITIZE_USER_SHADOW_SIZE);
  if (res < 0) return res;
  res = region_alloc(env, (void *)SANITIZE_USER_EXTRA_SHADOW_BASE, SANITIZE_USER_EXTRA_SHADOW_SIZE);
  if (res < 0) return res;
  res = region_alloc(env, (void *)SANITIZE_USER_STACK_SHADOW_BASE, SANITIZE_USER_STACK_SHADOW_SIZE);
  if (res < 0) return res;
  res = region_alloc(env, (void *)SANITIZE_USER_FS_SHADOW_BASE, SANITIZE_USER_FS_SHADOW_SIZE);
  if (res < 0) return res;
#endif

  return 0;
}

/* Allocates a new env with env_alloc, loads the named elf
 * binary into it with load_icode, and sets its env_type.
 * This function is ONLY called during kernel initialization,
 * before running the first user-mode environment.
 * The new env's parent ID is set to 0.
 */
void
env_create(uint8_t *binary, size_t size, enum EnvType type) {
  // LAB 3: Your code here:

  if (!binary) panic("binary = NULL");

  struct Env *newenv;
  if (env_alloc(&newenv, 0, type) < 0)
    panic("Can't allocate new environment");


  if (load_icode(newenv, binary, size) < 0)
    panic("Can't load ELF image");

  newenv->binary = binary;
}



/* Frees env and all memory it uses */
void
env_free(struct Env *env) {

#ifndef CONFIG_KSPACE
  /* If freeing the current environment, switch to kern_pgdir
   * before freeing the page directory, just in case the page
   * gets reused. */
  if (env == curenv) lcr3(kern_cr3);
#endif

  /* Note the environment's demise. */
  cprintf("[%08x] free env %08x\n", curenv ? curenv->env_id : 0, env->env_id);

#ifndef CONFIG_KSPACE
  /* Flush all mapped pages in the user portion of the address space */
  static_assert(UTOP % PTSIZE == 0, "Misaligned UTOP");

  /* UTOP < PDPE[1] start, so all mapped memory should be in first PDPE */
  pdpe_t *pdpe = KADDR(PTE_ADDR(env->env_pml4e[0]));
  for (size_t pdpeno = 0; pdpeno <= PDPE(UTOP); pdpeno++) {
    /*  only look at mapped page directory pointer index */
    if (!(pdpe[pdpeno] & PTE_P))
      continue;

    pde_t *pgdir = KADDR(PTE_ADDR(pdpe[pdpeno]));
    size_t pdeno_limit = pdpeno == PDPE(UTOP) ? PDX(UTOP) : NPDPENTRIES;

    for (size_t pdeno = 0; pdeno < pdeno_limit; pdeno++) {

      /* only look at mapped page tables */
      if (!(pgdir[pdeno] & PTE_P))
        continue;

      /* find the pa and va of the page table */
      physaddr_t pa = PTE_ADDR(pgdir[pdeno]);
      pte_t *pt = (pte_t *)KADDR(pa);

      /* unmap all PTEs in this page table */
      for (size_t pteno = 0; pteno < NPTENTRIES; pteno++) {
        if (pt[pteno] & PTE_P) page_remove(env->env_pml4e, PGADDR((uint64_t)0, pdpeno, pdeno, pteno, 0));
      }

      /* free the page table itself */
      pgdir[pdeno] = 0;
      page_decref(pa2page(pa));
    }

    /* free the page directory */
    size_t pa = PTE_ADDR(pdpe[pdpeno]);
    pdpe[pdpeno] = 0;
    page_decref(pa2page(pa));
  }

  /* free the page directory pointer */
  page_decref(pa2page(PTE_ADDR(env->env_pml4e[0])));

  /* free the page map level 4 (PML4) */
  physaddr_t pa = env->env_cr3;
  env->env_pml4e[0] = 0;
  env->env_pml4e = 0;
  env->env_cr3 = 0;
  page_decref(pa2page(pa));
#endif

  /* return the environment to the free list */
  env->env_status = ENV_FREE;
  env->env_link = env_free_list;
  env_free_list = env;
}

/* Frees environment env
 *
 * If env was the current one, then runs a new environment
 * (and does not return to the caller)
 */
void
env_destroy(struct Env *env) {
  /* If env is currently running on other CPUs, we change its state to
   * ENV_DYING. A zombie environment will be freed the next time
   * it traps to the kernel. */

  // LAB 3: Your code here:

  env->env_status = ENV_DYING;
  if (env == curenv) {
    env_free(env);
    sched_yield();
  }
}

void
csys_exit(void) {
  if (!curenv) panic("curenv = NULL");
  env_destroy(curenv);
}

void
csys_yield(struct Trapframe *tf) {
  memcpy(&curenv->env_tf, tf, sizeof(struct Trapframe));
  sched_yield();
}

/* Restores the register values in the Trapframe with the 'ret' instruction.
 * This exits the kernel and starts executing some environment's code.
 *
 * This function does not return.
 */

_Noreturn void
env_pop_tf(struct Trapframe *tf) {
  //TODO Why is it here?
  //static uintptr_t rip = 0;
  //rip = tf->tf_rip;

#ifdef CONFIG_KSPACE
  asm volatile(
      "movq %c[rbx](%[tf]), %%rbx \n\t"
      "movq %c[rcx](%[tf]), %%rcx \n\t"
      "movq %c[rdx](%[tf]), %%rdx \n\t"
      "movq %c[rsi](%[tf]), %%rsi \n\t"
      "movq %c[rdi](%[tf]), %%rdi \n\t"
      "movq %c[rbp](%[tf]), %%rbp \n\t"
      "movq %c[rd8](%[tf]), %%r8 \n\t"
      "movq %c[rd9](%[tf]), %%r9 \n\t"
      "movq %c[rd10](%[tf]), %%r10 \n\t"
      "movq %c[rd11](%[tf]), %%r11 \n\t"
      "movq %c[rd12](%[tf]), %%r12 \n\t"
      "movq %c[rd13](%[tf]), %%r13 \n\t"
      "movq %c[rd14](%[tf]), %%r14 \n\t"
      "movq %c[rd15](%[tf]), %%r15 \n\t"
      "pushq %c[ss](%[tf])\n\t"
      "pushq %c[rsp](%[tf])\n\t"
      "pushq %c[rflags](%[tf])\n\t"
      "pushq %c[cs](%[tf])\n\t"
      "pushq %c[rip](%[tf])\n\t"
      "movq %c[rax](%[tf]), %%rax\n\t"
      "iretq\n\t"
      :
      : [ tf ] "a"(tf),
        [ rip ] "i"(offsetof(struct Trapframe, tf_rip)),
        [ rax ] "i"(offsetof(struct Trapframe, tf_regs.reg_rax)),
        [ rbx ] "i"(offsetof(struct Trapframe, tf_regs.reg_rbx)),
        [ rcx ] "i"(offsetof(struct Trapframe, tf_regs.reg_rcx)),
        [ rdx ] "i"(offsetof(struct Trapframe, tf_regs.reg_rdx)),
        [ rsi ] "i"(offsetof(struct Trapframe, tf_regs.reg_rsi)),
        [ rdi ] "i"(offsetof(struct Trapframe, tf_regs.reg_rdi)),
        [ rbp ] "i"(offsetof(struct Trapframe, tf_regs.reg_rbp)),
        [ rd8 ] "i"(offsetof(struct Trapframe, tf_regs.reg_r8)),
        [ rd9 ] "i"(offsetof(struct Trapframe, tf_regs.reg_r9)),
        [ rd10 ] "i"(offsetof(struct Trapframe, tf_regs.reg_r10)),
        [ rd11 ] "i"(offsetof(struct Trapframe, tf_regs.reg_r11)),
        [ rd12 ] "i"(offsetof(struct Trapframe, tf_regs.reg_r12)),
        [ rd13 ] "i"(offsetof(struct Trapframe, tf_regs.reg_r13)),
        [ rd14 ] "i"(offsetof(struct Trapframe, tf_regs.reg_r14)),
        [ rd15 ] "i"(offsetof(struct Trapframe, tf_regs.reg_r15)),
        [ rflags ] "i"(offsetof(struct Trapframe, tf_rflags)),
        [ cs ] "i"(offsetof(struct Trapframe, tf_cs)),
        [ ss ] "i"(offsetof(struct Trapframe, tf_ss)),
        [ rsp ] "i"(offsetof(struct Trapframe, tf_rsp))
      : "cc", "memory", "ebx", "ecx", "edx", "esi", "edi");
#else
  asm volatile("movq %0,%%rsp\n" POPA
               "movw (%%rsp),%%es\n"
               "movw 8(%%rsp),%%ds\n"
               "addq $16,%%rsp\n"
               "addq $16,%%rsp\n" /* skip tf_trapno and tf_errcode */
               "iretq"
                   :: "g"(tf) : "memory");
#endif
  /* Mostly to placate the compiler */
  panic("Reached unrecheble");
}

/* Context switch from curenv to env.
 * This function does not return.
 *
 * Step 1: If this is a context switch (a new environment is running):
 *       1. Set the current environment (if any) back to
 *          ENV_RUNNABLE if it is ENV_RUNNING (think about
 *          what other states it can be in),
 *       2. Set 'curenv' to the new environment,
 *       3. Set its status to ENV_RUNNING,
 *       4. Update its 'env_runs' counter,
 *       5. Use lcr3() to switch to its address space.
 * Step 2: Use env_pop_tf() to restore the environment's
 *       registers and starting execution of process.

 * Hints:
 *    If this is the first call to env_run, curenv is NULL.
 *
 *    This function loads the new environment's state from
 *    env->env_tf.  Go back through the code you wrote above
 *    and make sure you have set the relevant parts of
 *    env->env_tf to sensible values.
 */
void
env_run(struct Env *env) {
  cprintf("envrun %s: %d\n", (const char *[]){
      "FREE", "DYING", "RUNNABLE", "RUNNING", "NOT_RUNNABLE" }[env->env_status], ENVX(env->env_id));

  // LAB 3: Your code here:

  if (curenv) {
    if (curenv->env_status == ENV_DYING) {
      struct Env *old = curenv;
      env_free(curenv);
      if (old == env) sched_yield();
    } else if (curenv->env_status == ENV_RUNNING) {
      curenv->env_status = ENV_RUNNABLE;
    }
  }

  curenv = env;
  curenv->env_status = ENV_RUNNING;
  curenv->env_runs++;

  // LAB 8: Your code here:

  lcr3(env->env_cr3);

  env_pop_tf(&curenv->env_tf);
}
