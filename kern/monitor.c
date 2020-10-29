/* Simple command-line kernel monitor useful for
 * controlling the kernel and exploring the system interactively. */

#include <inc/stdio.h>
#include <inc/string.h>
#include <inc/memlayout.h>
#include <inc/assert.h>
#include <inc/env.h>
#include <inc/x86.h>

#include <kern/console.h>
#include <kern/monitor.h>
#include <kern/kdebug.h>
#include <kern/tsc.h>
#include <kern/timer.h>
#include <kern/env.h>
#include <kern/pmap.h>

#define WHITESPACE "\t\r\n "
#define MAXARGS    16

struct Command {
  const char *name;
  const char *desc;
  /* return -1 to force monitor to exit */
  int (*func)(int argc, char **argv, struct Trapframe *tf);
};

static struct Command commands[] = {
    {"help", "Display this list of commands", mon_help},
    {"hello", "Display greeting message", mon_hello},
    {"kerninfo", "Display information about the kernel", mon_kerninfo},
    {"backtrace", "Print stack backtrace", mon_backtrace},
    {"timer_start", "Start timer",  mon_start},
    {"timer_stop", "Stop timer", mon_stop},
    {"timer_freq", "Get timer frequency", mon_frequency},
    {"memory", "Display allocated memory pages", mon_memory},
    {"pagedump", "Display kernel page table", mon_pagedump},
};
#define NCOMMANDS (sizeof(commands) / sizeof(commands[0]))

/* Implementations of basic kernel monitor commands */

int
mon_help(int argc, char **argv, struct Trapframe *tf) {
  for (size_t i = 0; i < NCOMMANDS; i++)
    cprintf("%s - %s\n", commands[i].name, commands[i].desc);
  return 0;
}

int
mon_hello(int argc, char **argv, struct Trapframe *tf) {
  cprintf("Hello!\n");
  return 0;
}

int
mon_kerninfo(int argc, char **argv, struct Trapframe *tf) {
  extern char _head64[], entry[], etext[], edata[], end[];

  cprintf("Special kernel symbols:\n");
  cprintf("  _head64 %16lx (virt)  %16lx (phys)\n", (unsigned long)_head64, (unsigned long)_head64);
  cprintf("  entry   %16lx (virt)  %16lx (phys)\n", (unsigned long)entry, (unsigned long)entry - KERNBASE);
  cprintf("  etext   %16lx (virt)  %16lx (phys)\n", (unsigned long)etext, (unsigned long)etext - KERNBASE);
  cprintf("  edata   %16lx (virt)  %16lx (phys)\n", (unsigned long)edata, (unsigned long)edata - KERNBASE);
  cprintf("  end     %16lx (virt)  %16lx (phys)\n", (unsigned long)end, (unsigned long)end - KERNBASE);
  cprintf("Kernel executable memory footprint: %luKB\n", (unsigned long)ROUNDUP(end - entry, 1024) / 1024);
  return 0;
}

int
mon_backtrace(int argc, char **argv, struct Trapframe *tf) {
  // LAB 2: Your code here:

  uintptr_t rip, *rbp;

  /* Read current address and current stack frame */
  rbp = (uintptr_t *)read_rbp();

  cprintf("Stack backtrace: \n");
  do {
    rip = rbp[1];
    struct Ripdebuginfo info;
    debuginfo_rip(rip, &info);

    cprintf("  rbp %016lx  rip %016lx\n", (unsigned long)rbp, (unsigned long)rip);
    cprintf("    %.256s:%d: %.*s+%ld\n", info.rip_file, info.rip_line,
            info.rip_fn_namelen, info.rip_fn_name, rip - info.rip_fn_addr);

    /* Next stack frame */
    rbp = (uintptr_t *)rbp[0];
  } while (rbp);

  return 0;
}

// Implement timer_start (mon_start), timer_stop (mon_stop), timer_freq (mon_frequency) commands.
// LAB 5: Your code here:

int
mon_start(int argc, char **argv, struct Trapframe *tf) {
  if (argc < 2) return 1;
  timer_start(argv[1]);
  return 0;
}

int
mon_stop(int argc, char **argv, struct Trapframe *tf) {
  timer_stop();
  return 0;
}

int
mon_frequency(int argc, char **argv, struct Trapframe *tf) {
  if (argc < 2) return 1;
  timer_cpu_frequency(argv[1]);
  return 0;
}

// LAB 6: Your code here.
// Implement memory (mon_memory) commands.
int
mon_memory(int argc, char **argv, struct Trapframe *tf) {
    bool region = !page_is_allocated(pages);
    size_t npg = 1, pgi = 0;
    for (size_t i = 0; i < npages; i++) {
        if (region == page_is_allocated(&pages[i]) || i == npages - 1) {
            if (pgi + 1 != i) cprintf("%lu..", pgi + 1);
            cprintf("%lu %s  \n", i, (const char *[]){"ALLOCATED", "FREE"}[region]);
            region = !page_is_allocated(&pages[i]);
            npg = 0, pgi = i;
        }
    }
    return 0;
}

int
mon_pagedump(int argc, char **argv, struct Trapframe *tf) {
  pml4e_t *pml4 = kern_pml4e;
  cprintf("CR3 %016lX\n", kern_cr3);
  cprintf("PML4 %p\n", kern_pml4e);
  for (size_t i = 0; i < NPMLENTRIES; i++) {
    if (pml4[i] & PTE_P) {
      cprintf("|-[%03lu] = %016lX\n", i, pml4[i]);
      pdpe_t *pdpe = KADDR(PTE_ADDR(pml4[i]));
      for (size_t i = 0; i < NPDPENTRIES; i++) {
        if (pdpe[i] & PTE_P) {
          cprintf("   |-[%03lu] = %016lX\n", i, pdpe[i]);
          pde_t *pde = KADDR(PTE_ADDR(pdpe[i]));
          for (size_t i = 0; i < NPDENTRIES; i++) {
            if (pde[i] & PTE_P) {
              cprintf("      |-[%03lu] = %016lX\n", i, pde[i]);
#if 0 // Slow
              pte_t *pte = KADDR(PTE_ADDR(pde[i]));
              for (size_t i = 0; i < NPDPENTRIES; i++) {
                if (pte[i] & PTE_P) {
                    cprintf("         |-[%03lu] = %016lX\n", i, pte[i]);
                }
              }
#endif
            }
          }
        }
      }
    }
  }
  return 0;
}



/* Kernel monitor command interpreter */

static int
runcmd(char *buf, struct Trapframe *tf) {
  int argc = 0;
  char *argv[MAXARGS];

  argv[0] = NULL;

  /* Parse the command buffer into whitespace-separated arguments */
  for (;;) {
    /* gobble whitespace */
    while (*buf && strchr(WHITESPACE, *buf)) *buf++ = 0;
    if (!*buf) break;

    /* save and scan past next arg */
    if (argc == MAXARGS - 1) {
      cprintf("Too many arguments (max %d)\n", MAXARGS);
      return 0;
    }
    argv[argc++] = buf;
    while (*buf && !strchr(WHITESPACE, *buf)) buf++;
  }
  argv[argc] = NULL;

  /* Lookup and invoke the command */
  if (!argc) return 0;
  for (size_t i = 0; i < NCOMMANDS; i++) {
    if (strcmp(argv[0], commands[i].name) == 0)
      return commands[i].func(argc, argv, tf);
  }

  cprintf("Unknown command '%s'\n", argv[0]);
  return 0;
}

void
monitor(struct Trapframe *tf) {

  cprintf("Welcome to the JOS kernel monitor!\n");
  cprintf("Type 'help' for a list of commands.\n");

  char *buf;
  do buf = readline("K> ");
  while (!buf || runcmd(buf, tf) >= 0);
}
