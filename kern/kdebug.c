#include <inc/string.h>
#include <inc/memlayout.h>
#include <inc/assert.h>
#include <inc/dwarf.h>
#include <inc/elf.h>
#include <inc/x86.h>

#include <kern/kdebug.h>
#include <kern/pmap.h>
#include <kern/env.h>
#include <inc/uefi.h>

void
load_kernel_dwarf_info(struct Dwarf_Addrs *addrs) {
  addrs->aranges_begin  = (uint8_t *)(uefi_lp->DebugArangesStart);
  addrs->aranges_end    = (uint8_t *)(uefi_lp->DebugArangesEnd);
  addrs->abbrev_begin   = (uint8_t *)(uefi_lp->DebugAbbrevStart);
  addrs->abbrev_end     = (uint8_t *)(uefi_lp->DebugAbbrevEnd);
  addrs->info_begin     = (uint8_t *)(uefi_lp->DebugInfoStart);
  addrs->info_end       = (uint8_t *)(uefi_lp->DebugInfoEnd);
  addrs->line_begin     = (uint8_t *)(uefi_lp->DebugLineStart);
  addrs->line_end       = (uint8_t *)(uefi_lp->DebugLineEnd);
  addrs->str_begin      = (uint8_t *)(uefi_lp->DebugStrStart);
  addrs->str_end        = (uint8_t *)(uefi_lp->DebugStrEnd);
  addrs->pubnames_begin = (uint8_t *)(uefi_lp->DebugPubnamesStart);
  addrs->pubnames_end   = (uint8_t *)(uefi_lp->DebugPubnamesEnd);
  addrs->pubtypes_begin = (uint8_t *)(uefi_lp->DebugPubtypesStart);
  addrs->pubtypes_end   = (uint8_t *)(uefi_lp->DebugPubtypesEnd);
}

#define UNKNOWN "<unknown>"
#define CALL_INSN_LEN 5

/* debuginfo_rip(addr, info)
 * Fill in the 'info' structure with information about the specified
 * instruction address, 'addr'.  Returns 0 if information was found, and
 * negative if not.  But even if it returns negative it has stored some
 * information into '*info'
 */
int
debuginfo_rip(uintptr_t addr, struct Ripdebuginfo *info) {
  /* Initialize *info */
  strcpy(info->rip_file, UNKNOWN);
  strcpy(info->rip_fn_name, UNKNOWN);
  info->rip_fn_namelen = sizeof UNKNOWN - 1;
  info->rip_line = 0;
  info->rip_fn_addr = addr;
  info->rip_fn_narg = 0;

  if (!addr) return 0;
  if (addr <= ULIM) panic("Can't search for user-level addresses yet!");

  struct Dwarf_Addrs addrs;
  load_kernel_dwarf_info(&addrs);

  Dwarf_Off offset = 0, line_offset = 0;
  int res = info_by_address(&addrs, addr, &offset);
  if (res < 0) return res;

  char *tmp_buf = NULL;

  res = file_name_by_info(&addrs, offset, &tmp_buf, &line_offset);
  if (res < 0) return res;
  strncpy(info->rip_file, tmp_buf, sizeof(info->rip_file));

  /* Find line number corresponding to given address.
   * Hint: note that we need the address of `call` instruction, but rip holds
   * address of the next instruction, so we should substract 5 from it.
   * Hint: use line_for_address from kern/dwarf_lines.c */

  // LAB 2: Your res here:

  addr -= CALL_INSN_LEN;

  res = line_for_address(&addrs, addr, line_offset, &info->rip_line);
  if (res < 0) return res;

  res = function_by_info(&addrs, addr, offset, &tmp_buf, &info->rip_fn_addr);
  if (res < 0) return res;
  strncpy(info->rip_fn_name, tmp_buf, sizeof(info->rip_fn_name));
  info->rip_fn_namelen = strnlen(info->rip_fn_name, sizeof(info->rip_fn_name));

  return 0;
}

uintptr_t
find_function(const char *const fname) {
  /* There are two functions for function name lookup.
   * address_by_fname, which looks for function name in section .debug_pubnames
   * and naive_address_by_fname which performs full traversal of DIE tree */

  // LAB 3: Your code here:

  /* Load kernel symbol and string tables */


  struct Elf64_Sym *ksyms = (struct Elf64_Sym *)uefi_lp->SymbolTableStart;
  struct Elf64_Sym *ksymsend = (struct Elf64_Sym *)uefi_lp->SymbolTableEnd;
  const char *kstrs = (char *)uefi_lp->StringTableStart;

  /* And try to find symbol there */

  if (!strncmp(fname, "sys_", 4)) {
    for (struct Elf64_Sym *ksym = ksyms; ksym < ksymsend; ksym++) {
      if (!strcmp(kstrs + ksym->st_name, fname) &&
          ELF64_ST_BIND(ksym->st_info) == STB_GLOBAL &&
          ELF64_ST_TYPE(ksym->st_info) == STT_FUNC &&
          ksym->st_other == STV_DEFAULT) {
        return ksym->st_value;
      }
    }
  }

  /* Or else try to find symbols via DWARF debug info */

  struct Dwarf_Addrs addrs;
  uintptr_t offset = 0;

  load_kernel_dwarf_info(&addrs);

  if (!address_by_fname(&addrs, fname, &offset) && offset) return offset;
  if (!naive_address_by_fname(&addrs, fname, &offset) && offset) return offset;

  return 0;
}
