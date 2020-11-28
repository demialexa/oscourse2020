// implement fork from user space

#include <inc/string.h>
#include <inc/lib.h>

/* PTE_COW marks copy-on-write page table entries.
 * It is one of the bits explicitly allocated to user processes (PTE_AVAIL). */
#define PTE_COW 0x800

/* Custom page fault handler - if faulting page is copy-on-write,
 * map in our own private writable copy. */
static void
pgfault(struct UTrapframe *utf) {
    int res;

    /* Check that the faulting access was (1) a write, and (2) to a
     * copy-on-write page.  If not, panic.
     * Hint:
     *   Use the read-only page table mappings at uvpt
     *   (see <inc/memlayout.h>). */

    // LAB 9: Your code here
    pte_t ent = get_uvpt_entry((void *)utf->utf_fault_va);
    if ((ent & (PTE_COW | PTE_P)) != (PTE_P | PTE_COW) || !(utf->utf_err & FEC_WR))
        panic("User pagefault at va=%p ip=%p\n", (void *)utf->utf_fault_va, (void *)utf->utf_rip);

    /* Allocate a new page, map it at a temporary location (PFTEMP),
     * copy the data from the old page to the new page, then move the new
     * page to the old page's address.
     * Hint:
     *   You should make three system calls.
     *   No need to explicitly delete the old page's mapping.
     *   Make sure you DO NOT use sanitized memcpy/memset routines when using UASAN. */

    // LAB 9: Your code here
    void *addr = (void *)ROUNDDOWN(utf->utf_fault_va, PAGE_SIZE);

    /* Only one reference, no need to copy */
    if (pageref(addr) != 1 || sys_page_map(CURENVID, addr, CURENVID, addr, PTE_UWP) < 0) {
        /* If remapping failed or there's more (or less) than one ref, we need to copy */

        res = sys_page_alloc(CURENVID, PFTEMP, PTE_UWP);
        if (res < 0) panic("[pagefault] sys_page_alloc: %i\n", res);

#ifdef SANITIZE_USER_SHADOW_BASE
        __nosan_memcpy(PFTEMP, addr, PAGE_SIZE);
#else
        memcpy(PFTEMP, addr, PAGE_SIZE);
#endif

        res = sys_page_map(CURENVID, PFTEMP, CURENVID, addr, PTE_UWP);
        if (res < 0) panic("[pagefault] sys_page_map: %i\n", res);

        res = sys_page_unmap(CURENVID, PFTEMP);
        if (res < 0) panic("[pagefault] sys_page_unmap: %i\n", res);
    }
}

/* Map our virtual page pn (address pn*PAGE_SIZE) into the target envid
 * at the same virtual address.  If the page is writable or copy-on-write,
 * the new mapping must be created copy-on-write, and then our mapping must be
 * marked copy-on-write as well.  (Exercise: Why do we need to mark ours
 * copy-on-write again if it was already copy-on-write at the beginning of
 * this function?)
 *
 * Returns: 0 on success, < 0 on error.
 * It is also OK to panic on error. */
static int
duppage(envid_t envid, void *addr) {
    // LAB 9: Your code here:

    pte_t ent = uvpt[VPT(addr)] & PTE_SYSCALL;

    int res;
    if (ent & PTE_W) {
        ent = (ent | PTE_COW) & ~PTE_W;

        res = sys_page_map(CURENVID, addr, envid, addr, ent);
        if (res < 0) return res;

        res = sys_page_map(CURENVID, addr, CURENVID, addr, ent);
    } else {
        res = sys_page_map(CURENVID, addr, envid, addr, ent);
    }

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
    int res = 0, child = sys_exofork();
    if (!child) thisenv = &envs[ENVX(sys_getenvid())];

    if (child <= 0) return child;

    for (char *addr = 0; addr < (char *)UTOP; addr += PAGE_SIZE) {
        if (!(uvpml4[VPML4(addr)] & PTE_P)) {
            addr += HUGE_PAGE_SIZE*PD_ENTRY_COUNT*PDP_ENTRY_COUNT - PAGE_SIZE;
            continue;
        }
        if (!(uvpdp[VPDP(addr)] & PTE_P)) {
            addr += HUGE_PAGE_SIZE*PD_ENTRY_COUNT - PAGE_SIZE;
            continue;
        }
        if (!(uvpd[VPD(addr)] & PTE_P)) {
            addr += HUGE_PAGE_SIZE - PAGE_SIZE;
            continue;
        }
        pte_t ent = uvpt[VPT(addr)];
        if (!(ent & PTE_P)) continue;

        if (
#ifdef SANITIZE_USER_SHADOW_BASE
#define _IN(x)  (addr >= ROUNDDOWN(SANITIZE_USER##x##SHADOW_BASE, PAGE_SIZE) &&\
                 addr < ROUNDUP(SANITIZE_USER##x##SHADOW_BASE + SANITIZE_USER##x##SHADOW_SIZE, PAGE_SIZE))
                _IN(_) || _IN(_EXTRA_) || _IN(_FS_) || _IN(_VPT_) ||
#undef _IN
#endif
                (((uintptr_t)addr - UXSTACKTOP + UXSTACKSIZE) < UXSTACKSIZE)) {
            res = sys_page_alloc(child, addr, PTE_UWP);
        } else if (ent & PTE_SHARE) {
            res = sys_page_map(CURENVID, addr, child, addr, ent & PTE_SYSCALL);
        } else {
            res = duppage(child, addr);
        }
        if (res < 0) goto error;
    }

    res = sys_env_set_pgfault_upcall(child, thisenv->env_pgfault_upcall);
    if (res < 0) goto error;

    res = sys_env_set_status(child, ENV_RUNNABLE);
    if (res < 0) goto error;

    /* NOTE: Duplicating shadow addresses is insane.
     *       Make sure to skip shadow addresses in COW above. */

    return child;

 error:
    sys_env_destroy(child);
    return res;
}

envid_t sfork() {
    panic("sfork() is not implemented");
}
