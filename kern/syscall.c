/* See COPYRIGHT for copyright information. */

#include <inc/x86.h>
#include <inc/error.h>
#include <inc/string.h>
#include <inc/assert.h>

#include <kern/env.h>
#include <kern/pmap.h>
#include <kern/trap.h>
#include <kern/syscall.h>
#include <kern/console.h>

/* Print a string to the system console.
 * The string is exactly 'len' characters long.
 * Destroys the environment on memory errors. */
static int
sys_cputs(const char *s, size_t len) {
  // LAB 8: Your code here.

  /* Check that the user has permission to read memory [s, s+len).
   * Destroy the environment if not. */

  if (user_mem_check(curenv, s, len, PTE_U) < 0) {
      env_destroy(curenv);
      // maybe return -E_FAULT?
  }

  while (len-- > 0) cputchar(*s++);

  return 0;
}

/* Read a character from the system console without blocking.
 * Returns the character, or 0 if there is no input waiting. */
static int
sys_cgetc(void) {
  // LAB 8: Your code here.

  return cons_getc();
}

/* Returns the current environment's envid. */
static envid_t
sys_getenvid(void) {
  // LAB 8: Your code here.
  return curenv->env_id;
}

/* Destroy a given environment (possibly the currently running environment).
 * 
 *  Returns 0 on success, < 0 on error.  Errors are:
 *  -E_BAD_ENV if environment envid doesn't currently exist,
 *      or the caller doesn't have permission to change envid. */
static int
sys_env_destroy(envid_t envid) {
  // LAB 8: Your code here.
  if (ENVX(envid) >= NENV)
      return -E_BAD_ENV;

  struct Env *env = &envs[ENVX(envid)];
  if (env->env_status == ENV_FREE)
      return -E_BAD_ENV;

  env_destroy(env);

  return 0;
}

/* Dispatches to the correct kernel function, passing the arguments. */
uintptr_t
syscall(uintptr_t syscallno, uintptr_t a1, uintptr_t a2, uintptr_t a3, uintptr_t a4, uintptr_t a5) {
  /* Call the function corresponding to the 'syscallno' parameter.
   * Return any appropriate return value. */
  // LAB 8: Your code here.

  switch (syscallno) {
  case SYS_cputs:
    return sys_cputs((void *)a1, a2);
  case SYS_cgetc:
    return sys_cgetc();
  case SYS_getenvid:
    return sys_getenvid();
  case SYS_env_destroy:
    return sys_env_destroy(a1);
  default:
    return -E_NO_SYS;
  }
}
