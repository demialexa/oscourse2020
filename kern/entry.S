/* See COPYRIGHT for copyright information. */

#ifdef CONFIG_KSPACE

#include <inc/mmu.h>
#include <inc/memlayout.h>

.code64
.text

.globl entry
entry:
  # Set up kernel stack
  leaq bootstacktop(%rip),%rsp
  xor %ebp, %ebp

  # Save LoadParams in uefi_lp.
  movq %rcx, uefi_lp(%rip)

  # Invoke C code
  call i386_init
  # Should never reach this place
  jmp .


.global save_trapframe_trap
save_trapframe_trap:
  popq save_trapframe_ret(%rip)
  popq saved_rip(%rip)
  popq saved_cs(%rip)
  # Guard to avoid hard to debug errors due to cli misusage.
  orl $FL_IF, (%rsp)
  popq saved_rflags(%rip)
  jmp save_trapframe

# For grade tests to work...
_generall_syscall:

save_trapframe_syscall:
  popq save_trapframe_ret(%rip)
  popq saved_rip(%rip)
  pushfq
  movl $GD_KT, saved_cs(%rip)
  popq %rax
  # Guard to avoid hard to debug errors due to cli misusage.
  orq $FL_IF, %rax
  movq %rax, saved_rflags(%rip)
  # fallthrough

save_trapframe:
  movq %rsp, saved_rsp(%rip)
  leaq bootstacktop(%rip), %rsp

  pushq $GD_KD
  pushq saved_rsp(%rip)
  pushq saved_rflags(%rip)
  pushq saved_cs(%rip)
  pushq saved_rip(%rip)
  pushq $0x0
  pushq $0x0
  pushq $0x0 # %ds
  pushq $0x0 # %es

  pushq %rax
  pushq %rbx
  pushq %rcx
  pushq %rdx
  pushq %rbp
  pushq %rdi
  pushq %rsi
  pushq %r8
  pushq %r9
  pushq %r10
  pushq %r11
  pushq %r12
  pushq %r13
  pushq %r14
  pushq %r15

  xor %ebp, %ebp
  movq  %rsp, %rdi
  jmp *save_trapframe_ret(%rip)

.globl sys_yield
.type  sys_yield, @function
sys_yield:
  cli
  call save_trapframe_syscall
  call csys_yield
  jmp .

# LAB 3: Your code here:
.globl sys_exit
.type  sys_exit, @function
sys_exit:
  cli
  leaq bootstacktop(%rip), %rsp
  xor %ebp, %ebp
  call csys_exit
  jmp .

.data


# Allocate boot stack forcing page alignment.
.p2align PGSHIFT
.globl bootstack
bootstack:
  .space KSTKSIZE
.globl bootstacktop
bootstacktop:

# Provide storage for loader parameters.
.globl uefi_lp
.global saved_rip
.global saved_rflags
.global saved_cs

uefi_lp: .quad 0
save_trapframe_ret: .quad 0
saved_rip: .quad 0
saved_rsp: .quad 0
saved_rflags: .quad 0
saved_cs: .quad 0

#endif
