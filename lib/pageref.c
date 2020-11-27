#include <inc/lib.h>

pte_t
get_uvpt_entry(void *va) {
    if (!(uvpml4[VPML4(va)] & PTE_P)) return 0;
    if (!(uvpdp[VPDP(va)] & PTE_P)) return 0;
    if (!(uvpd[VPD(va)] & PTE_P)) return 0;
    return uvpt[VPT(va)];
}

int
pageref(void *v) {
    pte_t pte = get_uvpt_entry(v);
    return (pte & PTE_P) ? pages[PAGE_NUMBER(pte)].pp_ref + 1 : 0;
}
