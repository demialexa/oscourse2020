#include <inc/lib.h>

pte_t
get_uvpt_entry(void *va) {
    if (!(uvpml4e[VPML4E(va)] & PTE_P)) return 0;
    if (!(uvpde[VPDPE(va)] & PTE_P)) return 0;
    if (!(uvpd[VPD(va)] & PTE_P)) return 0;

    return uvpt[PGNUM(va)];
}

int
pageref(void *v) {
    pte_t pte = get_uvpt_entry(v);
    return (pte & PTE_P) ? pages[PPN(pte)].pp_ref + 1 : 0;
}
