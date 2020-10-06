// Simple command-line kernel monitor useful for
// controlling the kernel and exploring the system interactively.

#include <inc/stdio.h>
#include <inc/string.h>
#include <inc/memlayout.h>
#include <inc/assert.h>
#include <inc/env.h>
#include <inc/x86.h>

#include <kern/console.h>
#include <kern/monitor.h>
#include <kern/kdebug.h>
#include <kern/env.h>

/* enough for one VGA text line */
#define CMDBUF_SIZE 80 

#define WHITESPACE "\t\r\n "
#define MAXARGS    16


struct Command {
  const char *name;
  const char *desc;
  // return -1 to force monitor to exit
  int (*func)(int argc, char **argv, struct Trapframe *tf);
};

static struct Command commands[] = {
    {"help", "Display this list of commands", mon_help},
    {"hello", "Display greeting message", mon_hello},
    {"kerninfo", "Display information about the kernel", mon_kerninfo},
    {"backtrace", "Print stack backtrace", mon_backtrace}
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
  cprintf("  _head64                  %08lx (phys)\n", (unsigned long)_head64);
  cprintf("  entry  %08lx (virt)  %08lx (phys)\n", (unsigned long)entry, (unsigned long)entry - KERNBASE);
  cprintf("  etext  %08lx (virt)  %08lx (phys)\n", (unsigned long)etext, (unsigned long)etext - KERNBASE);
  cprintf("  edata  %08lx (virt)  %08lx (phys)\n", (unsigned long)edata, (unsigned long)edata - KERNBASE);
  cprintf("  end    %08lx (virt)  %08lx (phys)\n", (unsigned long)end, (unsigned long)end - KERNBASE);
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

    // save and scan past next arg
    if (argc == MAXARGS - 1) {
      cprintf("Too many arguments (max %d)\n", MAXARGS);
      return 0;
    }
    argv[argc++] = buf;
    while (*buf && !strchr(WHITESPACE, *buf)) buf++;
  }
  argv[argc] = NULL;

  // Lookup and invoke the command
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
