/* Test bad pointer for user-level fault handler
 * this is going to fault in the fault handler accessing rip (always!)
 * so eventually the kernel kills it (PFM_KILL) because
 * we outrun the stack with invocations of the user-level handler */

#include <inc/lib.h>

void
umain(int argc, char **argv) {
    sys_page_alloc(0, (void *)(UXSTACKTOP - PAGE_SIZE), PTE_P | PTE_U | PTE_W);
    sys_env_set_pgfault_upcall(0, (void *)0xDEADBEEF);
    *(volatile int *)0 = 0;
}
