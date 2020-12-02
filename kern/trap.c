#include <inc/mmu.h>
#include <inc/x86.h>
#include <inc/assert.h>
#include <inc/string.h>
#include <inc/vsyscall.h>

#include <kern/pmap.h>
#include <kern/trap.h>
#include <kern/console.h>
#include <kern/monitor.h>
#include <kern/env.h>
#include <kern/syscall.h>
#include <kern/sched.h>
#include <kern/kclock.h>
#include <kern/picirq.h>
#include <kern/timer.h>
#include <kern/vsyscall.h>

static struct Taskstate ts;

/* For debugging, so print_trapframe can distinguish between printing
 * a saved trapframe and printing the current trapframe and print some
 * additional information in the latter case */
static struct Trapframe *last_tf;

/* Interrupt descriptor table  (Must be built at run time because
 * shifted function addresses can't be represented in relocation records) */
struct Gatedesc idt[256] = {{0}};
struct Pseudodesc idt_pd = {sizeof(idt) - 1, (uint64_t)idt};

static const char *
trapname(int trapno) {
    static const char *const excnames[] = {
        "Divide error",
        "Debug",
        "Non-Maskable Interrupt",
        "Breakpoint",
        "Overflow",
        "BOUND Range Exceeded",
        "Invalid Opcode",
        "Device Not Available",
        "Double Fault",
        "Coprocessor Segment Overrun",
        "Invalid TSS",
        "Segment Not Present",
        "Stack Fault",
        "General Protection",
        "Page Fault",
        "(unknown trap)",
        "x87 FPU Floating-Point Error",
        "Alignment Check",
        "Machine-Check",
        "SIMD Floating-Point Exception"
    };

    if (trapno < sizeof(excnames) / sizeof(excnames[0])) return excnames[trapno];
    if (trapno == T_SYSCALL) return "System call";
    if (trapno >= IRQ_OFFSET && trapno < IRQ_OFFSET + 16) return "Hardware Interrupt";

    return "(unknown trap)";
}

void
trap_init(void) {
    // LAB 4: Your code here
    extern void clock_thdlr(void), timer_thdlr(void);
    idt[IRQ_OFFSET + IRQ_TIMER] = GATE(0, GD_KT, (uintptr_t)(&timer_thdlr), 0);
    idt[IRQ_OFFSET + IRQ_CLOCK] = GATE(0, GD_KT, (uintptr_t)(&clock_thdlr), 0);

    // LAB 8: Your code here
    extern void trap_divide(void), trap_debig(void), trap_nmi(void),
    trap_brkpt(void), trap_oflow(void), trap_bound(void), trap_illop(void),
    trap_device(void), trap_dblflt(void), trap_tss(void), trap_segnp(void),
    trap_stack(void), trap_gpflt(void), trap_pgflt(void), trap_fperr(void),
    trap_align(void), trap_mchk(void), trap_simderr(void), trap_syscall(void);

    idt[T_DIVIDE] = GATE(0, GD_KT, (uintptr_t)(&trap_divide), 0);
    idt[T_DEBUG] = GATE(0, GD_KT, (uintptr_t)(&trap_debig), 0);
    idt[T_NMI] = GATE(0, GD_KT, (uintptr_t)(&trap_nmi), 0);
    idt[T_BRKPT] = GATE(0, GD_KT, (uintptr_t)(&trap_brkpt), 3);
    idt[T_OFLOW] = GATE(0, GD_KT, (uintptr_t)(&trap_oflow), 0);
    idt[T_BOUND] = GATE(0, GD_KT, (uintptr_t)(&trap_bound), 0);
    idt[T_ILLOP] = GATE(0, GD_KT, (uintptr_t)(&trap_illop), 0);
    idt[T_DEVICE] = GATE(0, GD_KT, (uintptr_t)(&trap_device), 0);
    idt[T_DBLFLT] = GATE(0, GD_KT, (uintptr_t)(&trap_dblflt), 0);
    idt[T_TSS] = GATE(0, GD_KT, (uintptr_t)(&trap_tss), 0);
    idt[T_SEGNP] = GATE(0, GD_KT, (uintptr_t)(&trap_segnp), 0);
    idt[T_STACK] = GATE(0, GD_KT, (uintptr_t)(&trap_stack), 0);
    idt[T_GPFLT] = GATE(0, GD_KT, (uintptr_t)(&trap_gpflt), 0);
    idt[T_PGFLT] = GATE(0, GD_KT, (uintptr_t)(&trap_pgflt), 0);
    idt[T_FPERR] = GATE(0, GD_KT, (uintptr_t)(&trap_fperr), 0);
    idt[T_ALIGN] = GATE(0, GD_KT, (uintptr_t)(&trap_align), 0);
    idt[T_MCHK] = GATE(0, GD_KT, (uintptr_t)(&trap_mchk), 0);
    idt[T_SIMDERR] = GATE(0, GD_KT, (uintptr_t)(&trap_simderr), 0);
    idt[T_SYSCALL] = GATE(0, GD_KT, (uintptr_t)(&trap_syscall), 3);

    // LAB 11: Your code here
    extern void serial_thdlr(void), kbd_thdlr(void);

    idt[IRQ_OFFSET + IRQ_KBD] = GATE(0, GD_KT, (uintptr_t)(&kbd_thdlr), 0);
    idt[IRQ_OFFSET + IRQ_SERIAL] = GATE(0, GD_KT, (uintptr_t)(&serial_thdlr), 0);

    /* Per-CPU setup */
    trap_init_percpu();
}

/* Initialize and load the per-CPU TSS and IDT */
void
trap_init_percpu(void) {
    /* Setup a TSS so that we get the right stack
     * when we trap to the kernel. */
    ts.ts_rsp0 = KSTACKTOP;

    /* Initialize the TSS slot of the gdt. */
    *(struct Segdesc64 *)(&gdt[(GD_TSS0 >> 3)]) = SEG64_TSS(STS_T64A, ((uint64_t)&ts), sizeof(struct Taskstate), 0);

    /* Load the TSS selector (like other segment selectors, the
     * bottom three bits are special; we leave them 0) */
    ltr(GD_TSS0);

    /* Load the IDT */
    lidt(&idt_pd);
}

void
print_trapframe(struct Trapframe *tf) {
    cprintf("TRAP frame at %p\n", tf);
    print_regs(&tf->tf_regs);
    cprintf("  es   0x----%04x\n", tf->tf_es);
    cprintf("  ds   0x----%04x\n", tf->tf_ds);
    cprintf("  trap 0x%08lx %s\n", (unsigned long)tf->tf_trapno, trapname(tf->tf_trapno));

    /* If this trap was a page fault that just happened
     * (so %cr2 is meaningful), print the faulting linear address */
    if (tf == last_tf && tf->tf_trapno == T_PGFLT)
        cprintf("  cr2  0x%08lx\n", (unsigned long)rcr2());

    cprintf("  err  0x%08lx", (unsigned long)tf->tf_err);

    /* For page faults, print decoded fault error code:
     *     U/K=fault occurred in user/kernel mode
     *     W/R=a write/read caused the fault
     *     PR=a protection violation caused the fault (NP=page not present) */
    if (tf->tf_trapno == T_PGFLT) {
        cprintf(" [%s, %s, %s]\n",
                tf->tf_err & FEC_U ? "user" : "kernel",
                tf->tf_err & FEC_WR ? "write" : "read",
                tf->tf_err & FEC_PR ? "protection" : "not-present");
    } else cprintf("\n");

    cprintf("  rip  0x%08lx\n", (unsigned long)tf->tf_rip);
    cprintf("  cs   0x----%04x\n", tf->tf_cs);
    cprintf("  flag 0x%08lx\n", (unsigned long)tf->tf_rflags);
    cprintf("  rsp  0x%08lx\n", (unsigned long)tf->tf_rsp);
    cprintf("  ss   0x----%04x\n", tf->tf_ss);
}

void
print_regs(struct PushRegs *regs) {
    cprintf("  r15  0x%08lx\n", (unsigned long)regs->reg_r15);
    cprintf("  r14  0x%08lx\n", (unsigned long)regs->reg_r14);
    cprintf("  r13  0x%08lx\n", (unsigned long)regs->reg_r13);
    cprintf("  r12  0x%08lx\n", (unsigned long)regs->reg_r12);
    cprintf("  r11  0x%08lx\n", (unsigned long)regs->reg_r11);
    cprintf("  r10  0x%08lx\n", (unsigned long)regs->reg_r10);
    cprintf("  r9   0x%08lx\n", (unsigned long)regs->reg_r9);
    cprintf("  r8   0x%08lx\n", (unsigned long)regs->reg_r8);
    cprintf("  rdi  0x%08lx\n", (unsigned long)regs->reg_rdi);
    cprintf("  rsi  0x%08lx\n", (unsigned long)regs->reg_rsi);
    cprintf("  rbp  0x%08lx\n", (unsigned long)regs->reg_rbp);
    cprintf("  rbx  0x%08lx\n", (unsigned long)regs->reg_rbx);
    cprintf("  rdx  0x%08lx\n", (unsigned long)regs->reg_rdx);
    cprintf("  rcx  0x%08lx\n", (unsigned long)regs->reg_rcx);
    cprintf("  rax  0x%08lx\n", (unsigned long)regs->reg_rax);
}

static void
trap_dispatch(struct Trapframe *tf) {
    switch (tf->tf_trapno) {
    case T_SYSCALL:
        tf->tf_regs.reg_rax = syscall(
            tf->tf_regs.reg_rax,
            tf->tf_regs.reg_rdx,
            tf->tf_regs.reg_rcx,
            tf->tf_regs.reg_rbx,
            tf->tf_regs.reg_rdi,
            tf->tf_regs.reg_rsi);
        return;
    case T_PGFLT:
        /* Handle processor exceptions. */
        page_fault_handler(tf);
        return;
    case T_BRKPT:
        monitor(tf);
        return;
    case IRQ_OFFSET + IRQ_SPURIOUS:
        /* Handle spurious interrupts
         * The hardware sometimes raises these because of noise on the
         * IRQ line or other reasons, we don't care */
        cprintf("Spurious interrupt on irq 7\n");
        print_trapframe(tf);
        return;
    case IRQ_OFFSET + IRQ_TIMER:
    case IRQ_OFFSET + IRQ_CLOCK:
        /* All timers are actually routed through this IRQ */
        timer_for_schedule->handle_interrupts();
        /* Update current time */
        vsys[VSYS_gettime] = gettime();
        sched_yield();
        return;
        /* Handle keyboard and serial interrupts. */
        // LAB 11: Your code here
    case IRQ_OFFSET + IRQ_KBD:
        kbd_intr();
        return;
    case IRQ_OFFSET + IRQ_SERIAL:
        serial_intr();
        return;
    default:
        print_trapframe(tf);
        if (!(tf->tf_cs & 3))
            panic("Unhandled trap in kernel");
        env_destroy(curenv);
    }
}

void
trap(struct Trapframe *tf) {
    /* The environment may have set DF and some versions
     * of GCC rely on DF being clear */
    asm volatile("cld" ::: "cc");

    /* Halt the CPU if some other CPU has called panic() */
    extern char *panicstr;
    if (panicstr) asm volatile("hlt");

    /* Check that interrupts are disabled.  If this assertion
     * fails, DO NOT be tempted to fix it by inserting a "cli" in
     * the interrupt path */
    assert(!(read_rflags() & FL_IF));

    if (debug) cprintf("Incoming TRAP frame at %p\n", tf);

    assert(curenv);

    /* Garbage collect if current enviroment is a zombie */
    if (curenv->env_status == ENV_DYING) {
        env_free(curenv);
        curenv = NULL;
        sched_yield();
    }

    /* Copy trap frame (which is currently on the stack)
     * into 'curenv->env_tf', so that running the environment
     * will restart at the trap point */
    curenv->env_tf = *tf;
    /* The trapframe on the stack should be ignored from here on */
    tf = &curenv->env_tf;

    /* Record that tf is the last real trapframe so
     * print_trapframe can print some additional information */
    last_tf = tf;

    /* Dispatch based on what type of trap occurred */
    trap_dispatch(tf);

    /* If we made it to this point, then no other environment was
     * scheduled, so we should return to the current environment
     * if doing so makes sense */
    if (curenv && curenv->env_status == ENV_RUNNING) env_run(curenv);
    else sched_yield();
}

void
page_fault_handler(struct Trapframe *tf) {
    // LAB 8: Your code here:

    /* Read processor's CR2 register to find the faulting address */
    uintptr_t fault_va = rcr2();

    if (debug) {
        cprintf("[%08x] user fault va %08lX ip %08lX\n", curenv->env_id, fault_va, tf->tf_rip);
        print_trapframe(tf);
    }

    /* Handle kernel-mode page faults. */

    if (!(tf->tf_err & FEC_U))
      panic("Kernel pagefault");

    /* We've already handled kernel-mode exceptions, so if we get here,
     * the page fault happened in user mode.
     * 
     * Call the environment's page fault upcall, if one exists.  Set up a
     * page fault stack frame on the user exception stack (below
     * UXSTACKTOP), then branch to curenv->env_pgfault_upcall.
     *
     * The page fault upcall might cause another page fault, in which case
     * we branch to the page fault upcall recursively, pushing another
     * page fault stack frame on top of the user exception stack.
     *
     * The trap handler needs one word of scratch space at the top of the
     * trap-time stack in order to return.  In the non-recursive case, we
     * don't have to worry about this because the top of the regular user
     * stack is free.  In the recursive case, this means we have to leave
     * an extra word between the current top of the exception stack and
     * the new stack frame because the exception stack _is_ the trap-time
     * stack.
     *
     * If there's no page fault upcall, the environment didn't allocate a
     * page for its exception stack or can't write to it, or the exception
     * stack overflows, then destroy the environment that caused the fault.
     * Note that the grade script assumes you will first check for the page
     * fault upcall and print the "user fault va" message below if there is
     * none.  The remaining three checks can be combined into a single test.
     *
     * Hints:
     *   user_mem_assert() and env_run() are useful here.
     *   To change what the user environment runs, modify 'curenv->env_tf'
     *   (the 'tf' variable points at 'curenv->env_tf'). */

    static_assert(UTRAP_RIP == offsetof(struct UTrapframe, utf_rip), "UTRAP_RIP should be equal to RIP offset");
    static_assert(UTRAP_RSP == offsetof(struct UTrapframe, utf_rsp), "UTRAP_RSP should be equal to RSP offset");

    // LAB 9: Your code here:

    struct UTrapframe *utf = (struct UTrapframe *)(curenv->env_tf.tf_rsp < UXSTACKTOP &&
        UXSTACKTOP - curenv->env_tf.tf_rsp < UXSTACKSIZE ? curenv->env_tf.tf_rsp - sizeof(void *) : UXSTACKTOP) - 1;

    user_mem_assert(curenv, (uint8_t *)utf - sizeof(utf), sizeof(*utf) + sizeof(utf), PTE_U | PTE_W);

    // Apparently this breaks tests...
    //user_mem_assert(curenv, curenv->env_pgfault_upcall, 1, PTE_U);

    utf->utf_fault_va = fault_va;
    utf->utf_err = tf->tf_err;
    utf->utf_rip = tf->tf_rip;
    utf->utf_rsp = tf->tf_rsp;
    utf->utf_rflags = tf->tf_rflags;
    utf->utf_regs = tf->tf_regs;

    tf->tf_rsp = (uintptr_t)utf;
    tf->tf_rip = (uintptr_t)curenv->env_pgfault_upcall;

    env_run(curenv);
}
