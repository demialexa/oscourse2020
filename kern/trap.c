#include <inc/mmu.h>
#include <inc/x86.h>
#include <inc/assert.h>
#include <inc/string.h>

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

extern uintptr_t gdtdesc_64;
static struct Taskstate ts;
extern struct Segdesc gdt[];
extern long gdt_pd;

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
  //extern struct Segdesc gdt[];
  // LAB 8: Your code here:

  extern void trap_divide(void);
  extern void trap_debig(void);
  extern void trap_nmi(void);
  extern void trap_brkpt(void);
  extern void trap_oflow(void);
  extern void trap_bound(void);
  extern void trap_illop(void);
  extern void trap_device(void);
  extern void trap_dblflt(void);
  extern void trap_tss(void);
  extern void trap_segnp(void);
  extern void trap_stack(void);
  extern void trap_gpflt(void);
  extern void trap_pgflt(void);
  extern void trap_fperr(void);
  extern void trap_align(void);
  extern void trap_mchk(void);
  extern void trap_simderr(void);
  extern void trap_syscall(void);

  SETGATE(idt[T_DIVIDE], 0, GD_KT, (uintptr_t)(&trap_divide), 0)
  SETGATE(idt[T_DEBUG], 0, GD_KT, (uintptr_t)(&trap_debig), 0)
  SETGATE(idt[T_NMI], 0, GD_KT, (uintptr_t)(&trap_nmi), 0)
  SETGATE(idt[T_BRKPT], 0, GD_KT, (uintptr_t)(&trap_brkpt), 3)
  SETGATE(idt[T_OFLOW], 0, GD_KT, (uintptr_t)(&trap_oflow), 0)
  SETGATE(idt[T_BOUND], 0, GD_KT, (uintptr_t)(&trap_bound), 0)
  SETGATE(idt[T_ILLOP], 0, GD_KT, (uintptr_t)(&trap_illop), 0)
  SETGATE(idt[T_DEVICE], 0, GD_KT, (uintptr_t)(&trap_device), 0)
  SETGATE(idt[T_DBLFLT], 0, GD_KT, (uintptr_t)(&trap_dblflt), 0)
  SETGATE(idt[T_TSS], 0, GD_KT, (uintptr_t)(&trap_tss), 0)
  SETGATE(idt[T_SEGNP], 0, GD_KT, (uintptr_t)(&trap_segnp), 0)
  SETGATE(idt[T_STACK], 0, GD_KT, (uintptr_t)(&trap_stack), 0)
  SETGATE(idt[T_GPFLT], 0, GD_KT, (uintptr_t)(&trap_gpflt), 0)
  SETGATE(idt[T_PGFLT], 0, GD_KT, (uintptr_t)(&trap_pgflt), 0)
  SETGATE(idt[T_FPERR], 0, GD_KT, (uintptr_t)(&trap_fperr), 0)
  SETGATE(idt[T_ALIGN], 0, GD_KT, (uintptr_t)(&trap_align), 0)
  SETGATE(idt[T_MCHK], 0, GD_KT, (uintptr_t)(&trap_mchk), 0)
  SETGATE(idt[T_SIMDERR], 0, GD_KT, (uintptr_t)(&trap_simderr), 0)
  SETGATE(idt[T_SYSCALL], 0, GD_KT, (uintptr_t)(&trap_syscall), 3)

  /* Per-CPU setup */
  trap_init_percpu();
}

/* Initialize and load the per-CPU TSS and IDT */
void
trap_init_percpu(void) {
  /* Setup a TSS so that we get the right stack
   * when we trap to the kernel. */
  ts.ts_esp0 = KSTACKTOP;

  /* Initialize the TSS slot of the gdt. */
  SETTSS((struct SystemSegdesc64 *)(&gdt[(GD_TSS0 >> 3)]), STS_T64A,
         (uint64_t)(&ts), sizeof(struct Taskstate), 0);

  /* Load the TSS selector (like other segment selectors, the
   * bottom three bits are special; we leave them 0) */
  ltr(GD_TSS0);

  /* Load the IDT */
  lidt(&idt_pd);
}

void
clock_idt_init(void) {
  extern void clock_thdlr(void);
  extern void timer_thdlr(void);

  /* init idt structure */
  SETGATE(idt[IRQ_OFFSET + IRQ_TIMER], 0, GD_KT, (uintptr_t)(&timer_thdlr), 0);
  SETGATE(idt[IRQ_OFFSET + IRQ_CLOCK], 0, GD_KT, (uintptr_t)(&clock_thdlr), 0);

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
            tf->tf_err & 4 ? "user" : "kernel",
            tf->tf_err & 2 ? "write" : "read",
            tf->tf_err & 1 ? "protection" : "not-present");
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
    sched_yield();
    return;
  default:
    print_trapframe(tf);
    if (!(tf->tf_cs & 0x3))
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

  /* Read processor's CR2 register to find the faulting address */
  uintptr_t fault_va = rcr2();

  (void)fault_va;

  cprintf("[%08x] user fault va %08lX ip %08lX\n",
    curenv->env_id, fault_va, tf->tf_rip);
  print_trapframe(tf);

  /* Handle kernel-mode page faults. */
  // LAB 8: Your code here.

  if (!(tf->tf_err & 4))
    panic("Kernel pagefault");

  env_destroy(curenv);
}
