// implement fork from user space

#include <inc/string.h>
#include <inc/lib.h>

/* PTE_COW marks copy-on-write page table entries.
 * It is one of the bits explicitly allocated to user processes (PTE_AVAIL). */
#define PTE_COW 0x800

pte_t find_uvptent(uintptr_t va) {
    if (!(uvpml4e[VPML4E(va)] & PTE_P)) return 0;
    if (!(uvpde[VPDPE(va)] & PTE_P)) return 0;
    if (!(uvpd[VPD(va)] & PTE_P)) return 0;

    return uvpt[va / PGSIZE];
}

/* Custom page fault handler - if faulting page is copy-on-write,
 * map in our own private writable copy. */
static void
pgfault(struct UTrapframe *utf) {
  /* Check that the faulting access was (1) a write, and (2) to a
   * copy-on-write page.  If not, panic.
   * Hint:
   *   Use the read-only page table mappings at uvpt
   *   (see <inc/memlayout.h>). */

  // LAB 9: Your code here:
  pte_t ent = find_uvptent(utf->utf_fault_va);
  if ((ent & (PTE_COW | PTE_P)) != (PTE_P | PTE_COW) || !(utf->utf_err & 2)) panic("Pagefault");

  /* Allocate a new page, map it at a temporary location (PFTEMP),
   * copy the data from the old page to the new page, then move the new
   * page to the old page's address.
   * Hint:
   *   You should make three system calls.
   *   No need to explicitly delete the old page's mapping.
   *   Make sure you DO NOT use sanitized memcpy/memset routines when using UASAN. */

  // LAB 9: Your code here:

  envid_t id = sys_getenvid();
  int res = sys_page_alloc(id, (void *)PFTEMP, PTE_U | PTE_P | PTE_W);
  if (res < 0) panic("Pagefault");

  void *addr = (void *)ROUNDDOWN(utf->utf_fault_va, PGSIZE);

#ifdef SANITIZE_USER_SHADOW_BASE
  void *__nosan_memcpy(void *dst, const void *src, size_t sz);
  __nosan_memcpy
#else
  memcpy
#endif
  ((void *)PFTEMP, addr, PGSIZE);

  res = sys_page_map(id, (void *)PFTEMP, id, addr, PTE_U | PTE_P | PTE_W);
  if (res < 0) panic("Pagefault");
}

/* Map our virtual page pn (address pn*PGSIZE) into the target envid
 * at the same virtual address.  If the page is writable or copy-on-write,
 * the new mapping must be created copy-on-write, and then our mapping must be
 * marked copy-on-write as well.  (Exercise: Why do we need to mark ours
 * copy-on-write again if it was already copy-on-write at the beginning of
 * this function?)
 *
 * Returns: 0 on success, < 0 on error.
 * It is also OK to panic on error. */
static int
duppage(envid_t envid, uintptr_t pn) {
  // LAB 9: Your code here.

  pte_t ent = uvpt[pn];
  envid_t id = sys_getenvid();

  int res = sys_page_map(id, (void *)(pn * PGSIZE),
                         envid, (void *)(pn * PGSIZE), (ent & 0xFFF) | PTE_COW);
  if (res < 0) return res;

  res = sys_page_map(id, (void *)(pn * PGSIZE),
                     id, (void *)(pn * PGSIZE), (ent & 0xFFF) | PTE_COW);
  return res;
}

/* User-level fork with copy-on-write.
 * Set up our page fault handler appropriately.
 * Create a child.
 * Copy our address space and page fault handler setup to the child.
 * Then mark the child as runnable and return.
 *
 * Returns: child's envid to the parent, 0 to the child, < 0 on error.
 * It is also OK to panic on error.
 *
 * Hint:
 *   Use uvpd, uvpt, and duppage.
 *   Remember to fix "thisenv" in the child process.
 *   Neither user exception stack should ever be marked copy-on-write,
 *   so you must allocate a new page for the child's user exception stack. */
envid_t
fork(void) {
  // LAB 9: Your code here.

  set_pgfault_handler(pgfault);
  int err, res = sys_exofork();
  if (res < 0) return res;
  else if (!res) {
    set_pgfault_handler(pgfault);
    return 0;
  }

  thisenv = &envs[ENVX(res)];

  for (size_t i = 0; i < UTOP; i += PGSIZE) {
    if (
#ifdef SANITIZE_USER_SHADOW_BASE
        (i >= SANITIZE_USER_SHADOW_BASE && i < SANITIZE_USER_SHADOW_BASE + SANITIZE_USER_SHADOW_SIZE) ||
        (i >= SANITIZE_USER_EXTAR_SHADOW_BASE && i < SANITIZE_USER_EXTAR_SHADOW_BASE + SANITIZE_USER_EXTAR_SHADOW_SIZE) ||
        (i >= SANITIZE_USER_FS_SHADOW_BASE && i < SANITIZE_USER_FS_SHADOW_BASE + SANITIZE_USER_FS_SHADOW_SIZE) ||
        (i >= SANITIZE_USER_VPT_SHADOW_BASE && i < SANITIZE_USER_VPT_SHADOW_BASE + SANITIZE_USER_VPT_SHADOW_SIZE) ||
#endif
        (i >= UXSTACKTOP - UXSTACKSIZE && i < UXSTACKTOP)) {
      err = sys_page_alloc(res, (void *)i, PTE_U | PTE_P | PTE_W);
      if (err < 0) goto error;
    } else {
      pte_t pte = find_uvptent(i);
      if (pte & PTE_P) duppage(res, i/PGSIZE);
    }
  }

  err = sys_env_set_status(res, ENV_RUNNABLE);
  if (err < 0) goto error;

  /* Duplicating shadow addresses is insane. Make sure to skip shadow addresses in COW above. */

  return res;

error:
  sys_env_destroy(res);
  return err;
}

/* Challenge! */
int
sfork(void) {
  panic("sfork not implemented");
  return -E_INVAL;
}
