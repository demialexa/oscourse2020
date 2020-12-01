/* System call stubs. */

#include <inc/syscall.h>
#include <inc/lib.h>

static inline int64_t
syscall(uintptr_t num, bool check, uintptr_t a1, uintptr_t a2, uintptr_t a3, uintptr_t a4, uintptr_t a5) {
    intptr_t ret;

    /* Generic system call.
    * Pass system call number in RAX,
    * Up to five parameters in RDX, RCX, RBX, RDI, RSI.
    * Interrupt kernel with T_SYSCALL.
    *
    * The "volatile" tells the assembler not to optimize
    * this instruction away just because we don't use the
    * return value.
    *
    * The last clause tells the assembler that this can
    * potentially change the condition codes and arbitrary
    * memory locations. */

    asm volatile("int %1\n"
               : "=a"(ret)
               : "i"(T_SYSCALL), "a"(num), "d"(a1), "c"(a2), "b"(a3), "D"(a4), "S"(a5)
               : "cc", "memory");

    if (check && ret > 0) {
        panic("syscall %zd returned %zd (> 0)", num, ret);
    }

    return ret;
}

void
sys_cputs(const char *s, size_t len) {
    syscall(SYS_cputs, 0, (uintptr_t)s, len, 0, 0, 0);
}

int
sys_cgetc(void) {
    return syscall(SYS_cgetc, 0, 0, 0, 0, 0, 0);
}

int
sys_env_destroy(envid_t envid) {
    return syscall(SYS_env_destroy, 1, envid, 0, 0, 0, 0);
}

envid_t
sys_getenvid(void) {
    return syscall(SYS_getenvid, 0, 0, 0, 0, 0, 0);
}

void
sys_yield(void) {
    syscall(SYS_yield, 0, 0, 0, 0, 0, 0);
}

int
sys_page_alloc(envid_t envid, void *va, int perm) {
    int res = syscall(SYS_page_alloc, 1, envid, (uintptr_t)va, perm, 0, 0);
#ifdef SANITIZE_USER_SHADOW_BASE
    /* Unpoison the allocated page */
    if (!res) platform_asan_unpoison(ROUNDDOWN(va, PAGE_SIZE), PAGE_SIZE);
#endif

    return res;
}

int
sys_page_map(envid_t srcenv, void *srcva, envid_t dstenv, void *dstva, int perm) {
    int res = syscall(SYS_page_map, 1, srcenv, (uintptr_t)srcva, dstenv, (uintptr_t)dstva, perm);
#ifdef SANITIZE_USER_SHADOW_BASE
    if (!res) {
        if (dstenv == CURENVID) {
            platform_asan_unpoison(ROUNDDOWN(dstva, PAGE_SIZE), PAGE_SIZE);
        } else {
            uintptr_t addr = ((uintptr_t)dstva >> 3) + SANITIZE_USER_SHADOW_OFF;
            uintptr_t paddr = (uintptr_t)ROUNDDOWN(addr, PAGE_SIZE);
            uintptr_t pdst = (uintptr_t)PFTEMP - PAGE_SIZE;
            res = syscall(SYS_page_map, 1, srcenv, paddr, CURENVID, pdst, PTE_UWP);
            // Ignore failures
            if (res >= 0) {
                __nosan_memset((void *)pdst + (addr - paddr), 0, PAGE_SIZE/8);
                syscall(SYS_page_unmap, 1, CURENVID, pdst, 0, 0, 0);
            }
        }
    }
#endif
    return res;
}

int
sys_page_unmap(envid_t envid, void *va) {
    // TODO Poison mapped memory
    return syscall(SYS_page_unmap, 1, envid, (uintptr_t)va, 0, 0, 0);
}

/* sys_exofork is inlined in lib.h */

int
sys_env_set_status(envid_t envid, int status) {
    return syscall(SYS_env_set_status, 1, envid, status, 0, 0, 0);
}

int
sys_env_set_trapframe(envid_t envid, struct Trapframe *tf) {
    return syscall(SYS_env_set_trapframe, 1, envid, (uintptr_t)tf, 0, 0, 0);
}

int
sys_env_set_pgfault_upcall(envid_t envid, void *upcall) {
    return syscall(SYS_env_set_pgfault_upcall, 1, envid, (uintptr_t)upcall, 0, 0, 0);
}

int
sys_ipc_try_send(envid_t envid, uintptr_t value, void *srcva, int perm) {
    return syscall(SYS_ipc_try_send, 0, envid, value, (uintptr_t)srcva, perm, 0);
}

int
sys_ipc_recv(void *dstva) {
    int res = syscall(SYS_ipc_recv, 1, (uintptr_t)dstva, 0, 0, 0, 0);
#ifdef SANITIZE_USER_SHADOW_BASE
    if (!res) platform_asan_unpoison(ROUNDDOWN(dstva, PAGE_SIZE), PAGE_SIZE);
#endif
    return res;
}
