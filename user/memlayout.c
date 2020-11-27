#include <inc/lib.h>

#ifndef PTE_COW
#     define PTE_COW 0x800
#endif
#ifndef PTE_SHARE
#    define PTE_SHARE 0x400
#endif

void
memlayout(void) {
    uintptr_t addr;
    size_t total_p = 0;
    size_t total_u = 0;
    size_t total_w = 0;
    size_t total_cow = 0;

    cprintf("EID: %d, PEID: %d\n", thisenv->env_id, thisenv->env_parent_id);
    cprintf("pml4: %p, uvpd: %p, uvpt: %p\n", thisenv->env_pagetable, uvpd, uvpt);

    for (addr = 0; addr < KERNBASE; addr += PAGE_SIZE) {
        pte_t ent = get_uvpt_entry((void *)addr);
        if (ent) {
            cprintf("[%p] %lx -> %08lx: %c %c %c |%s%s\n",
                &uvpt[VPT(addr)], (unsigned long)addr, (unsigned long)ent,
                (ent & PTE_P) ? total_p++, 'P' : '-',
                (ent & PTE_U) ? total_u++, 'U' : '-',
                (ent & PTE_W) ? total_w++, 'W' : '-',
                (ent & PTE_COW) ? total_cow++, " COW" : "",
                (ent & PTE_SHARE) ? " SHARE" : "");
        }
    }

    cprintf("Memory usage summary:\n");
    cprintf("  PTE_P: %lu\n", (unsigned long)total_p);
    cprintf("  PTE_U: %lu\n", (unsigned long)total_u);
    cprintf("  PTE_W: %lu\n", (unsigned long)total_w);
    cprintf("  PTE_COW: %lu\n", (unsigned long)total_cow);
}

void
umain(int argc, char *argv[]) {
    envid_t ceid;
    int pipefd[2];
    int res;

    memlayout();

    res = pipe(pipefd);
    if (res < 0) panic("pipe() failed\n");
    ceid = fork();
    if (ceid < 0) panic("fork() failed\n");

    if (!ceid) {
        /* Child environment */
        int i;
        cprintf("\n");
        for (i = 0; i < 102400; i++)
            sys_yield();
        cprintf("==== Child\n");
        memlayout();
        return;
    }

    cprintf("==== Parent\n");
    memlayout();
}
