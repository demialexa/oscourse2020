/* See COPYRIGHT for copyright information. */

#include <inc/mmu.h>
#include <inc/memlayout.h>
#include <inc/trap.h>
#include <kern/macro.h>

#include <kern/picirq.h>

#ifdef CONFIG_KSPACE

.globl clock_thdlr
.type clock_thdlr, @function
clock_thdlr:
  call save_trapframe_trap
  # Set trap code for trapframe
  movl $(IRQ_OFFSET + IRQ_CLOCK), 136(%rsp)
  call trap
  jmp .

.globl timer_thdlr
.type timer_thdlr, @function
timer_thdlr:
  call save_trapframe_trap
  # Set trap code for trapframe
  movl $(IRQ_OFFSET + IRQ_TIMER), 136(%rsp)
  call trap
  jmp .

#else

/* TRAPHANDLER defines a globally-visible function for handling a trap.
 * It pushes a trap number onto the stack, then jumps to _alltraps.
 * Use TRAPHANDLER for traps where the CPU automatically pushes an error code.
 *
 * You shouldn't call a TRAPHANDLER function from C, but you may
 * need to _declare_ one in C (for instance, to get a function pointer
 * during IDT setup).  You can declare the function with
 *   void NAME();
 * where NAME is the argument passed to TRAPHANDLER.
 */
#define TRAPHANDLER(name, num)                                   \
  .globl name;            /* define global symbol for 'name' */  \
  .type name, @function;  /* symbol type is function */          \
  .align 2;               /* align function definition */        \
  name:                   /* function starts here */             \
  pushq $(num);                                                  \
  jmp _alltraps

/* Use TRAPHANDLER_NOEC for traps where the CPU doesn't push an error code.
 * It pushes a 0 in place of the error code, so the trap frame has the same
 * format in either case.
 */
#define TRAPHANDLER_NOEC(name, num) \
  .globl name;                      \
  .type name, @function;            \
  .align 2;                         \
  name:                             \
  pushq $0;                         \
  pushq $(num);                     \
  jmp _alltraps

.text

.globl _alltraps
.type _alltraps, @function;
.align 2
_alltraps:
  subq $16,%rsp
  movw %ds,8(%rsp)
  movw %es,(%rsp)
  PUSHA
  movl $GD_KD,%eax
  movw %ax,%ds
  movw %ax,%es
  movq %rsp, %rdi
  call trap
  jmp .

TRAPHANDLER_NOEC(trap_divide, T_DIVIDE)
TRAPHANDLER_NOEC(trap_debig, T_DEBUG)
TRAPHANDLER_NOEC(trap_nmi, T_NMI)
TRAPHANDLER_NOEC(trap_brkpt, T_BRKPT)
TRAPHANDLER_NOEC(trap_oflow, T_OFLOW)
TRAPHANDLER_NOEC(trap_bound, T_BOUND)
TRAPHANDLER_NOEC(trap_illop, T_ILLOP)
TRAPHANDLER_NOEC(trap_device, T_DEVICE)
TRAPHANDLER(trap_dblflt, T_DBLFLT)
TRAPHANDLER(trap_tss, T_TSS)
TRAPHANDLER(trap_segnp, T_SEGNP)
TRAPHANDLER(trap_stack, T_STACK)
TRAPHANDLER(trap_gpflt, T_GPFLT)
TRAPHANDLER(trap_pgflt, T_PGFLT)
TRAPHANDLER_NOEC(trap_fperr, T_FPERR)
TRAPHANDLER(trap_align, T_ALIGN)
TRAPHANDLER_NOEC(trap_mchk, T_MCHK)
TRAPHANDLER_NOEC(trap_simderr, T_SIMDERR)

TRAPHANDLER_NOEC(trap_syscall, T_SYSCALL)

TRAPHANDLER_NOEC(clock_thdlr, IRQ_OFFSET + IRQ_CLOCK)
TRAPHANDLER_NOEC(timer_thdlr, IRQ_OFFSET + IRQ_TIMER)
TRAPHANDLER_NOEC(serial_thdlr, IRQ_OFFSET + IRQ_SERIAL)
TRAPHANDLER_NOEC(kbd_thdlr, IRQ_OFFSET + IRQ_KBD)

#endif
