// Stripped-down primitive printf-style formatting routines,
// used in common by printf, sprintf, fprintf, etc.
// This code is also used by both the kernel and user programs.

#include <inc/types.h>
#include <inc/stdio.h>
#include <inc/string.h>
#include <inc/stdarg.h>
#include <inc/error.h>

/*
 * Space or zero padding and a field width are supported for the numeric
 * formats only.
 *
 * The special format %i takes an integer error code
 * and prints a string describing the error.
 * The integer may be positive or negative,
 * so that -E_NO_MEM and E_NO_MEM are equivalent.
 */

static const char *const error_string[MAXERROR] = {
  [E_UNSPECIFIED] = "unspecified error",
  [E_BAD_ENV]     = "bad environment",
  [E_INVAL]       = "invalid parameter",
  [E_NO_MEM]      = "out of memory",
  [E_NO_FREE_ENV] = "out of environments",
  [E_BAD_DWARF]   = "corrupted debug info",
  [E_FAULT]       = "segmentation fault",
  [E_INVALID_EXE] = "invalid ELF image",
  [E_NO_ENT]      = "entry not found",
  [E_NO_SYS]      = "no such system call",
  [E_IPC_NOT_RECV] = "env is not recving",
  [E_EOF]          = "unexpected end of file",
};

/* Print a number (base <= 16) in reverse order,
 * using specified putch function and associated pointer putdat.
 */
static void
printnum(void (*putch)(int, void *), void *putdat,
         unsigned long long num, unsigned base, int width, int padc) {
  /* first recursively print all preceding (more significant) digits */
  if (num >= base) {
    printnum(putch, putdat, num / base, base, width - 1, padc);
  } else {
    /* print any needed pad characters before first digit */
    while (--width > 0) putch(padc, putdat);
  }

  /* then print this (the least significant) digit */
  putch("0123456789abcdef"[num % base], putdat);
}

/* Get an unsigned int of various possible sizes from a varargs list,
 * depending on the lflag parameter. */
static unsigned long long
getuint(va_list *ap, unsigned lflag) {
  switch(lflag) {
  case 0:  return va_arg(*ap, unsigned int);
  case 1:  return va_arg(*ap, unsigned long);
  default: return va_arg(*ap, unsigned long long);
  }
}

/* Same as getuint but signed - can't use getuint
 * because of sign extension */
static long long
getint(va_list *ap, int lflag) {
  switch(lflag) {
  case 0:  return va_arg(*ap, int);
  case 1:  return va_arg(*ap, long);
  default: return va_arg(*ap, long long);
  }
}

/* Main function to format and print a string. */
void printfmt(void (*putch)(int, void *), void *putdat, const char *fmt, ...);

void
vprintfmt(void (*putch)(int, void *), void *putdat, const char *fmt, va_list ap) {
  va_list aq;
  va_copy(aq, ap);

  for (;;) {
    unsigned ch;
    while ((ch = *(unsigned char *)fmt++) != '%') {
      if (!ch) return;
      putch(ch, putdat);
    }

    /* Process a %-escape sequence */
    char padc = ' ';
    int width  = -1, precision = -1;
    unsigned lflag = 0, base = 10;
    bool altflag = 0;
    uint64_t num = 0;
  reswitch:
    switch (ch = *(unsigned char *)fmt++) {
      case '0': /* '-' flag to pad on the right */
      case '-': /* '0' flag to pad with 0's instead of spaces */ {
        padc = ch;
      } goto reswitch;
      case '*': /* indirect width field */ {
        precision = va_arg(aq, int);
      } goto process_precision;
      case '1': case '2': case '3':
      case '4': case '5': case '6':
      case '7': case '8': case '9': /* width field */ {
        for (precision = 0;; ++fmt) {
          precision = precision * 10 + ch - '0';
          if ((ch = *fmt) - '0' > 9) break;
        }
  process_precision:
        if (width < 0) {
          width = precision;
          precision = -1;
        }
      } goto reswitch;
      case '.': {
        width = MAX(0, width);
      } goto reswitch;
      case '#': {
        altflag = 1;
      } goto reswitch;
      case 'l': /* long flag (doubled for long long) */ {
        lflag++;
        goto reswitch;
      }
      case 'c': /* character */ {
        putch(va_arg(aq, int), putdat);
      } break;
      case 'i': /* error message */ {
        int err = va_arg(aq, int);
        err = MAX(err, -err);
        const char *p;
        if (err >= MAXERROR || !(p = error_string[err]))
          printfmt(putch, putdat, "error %d", err);
        else
          printfmt(putch, putdat, "%s", p);
      } break;
      case 's': /* string */ {
        const char *ptr = va_arg(aq, char *);
        if (!ptr) ptr = "(null)";
        if (width > 0 && padc != '-') {
          width -= strnlen(ptr, precision);
          for (; width > 0; width--) {
            putch(padc, putdat);
          }
        }
        for (; (ch = *ptr++) && (precision < 0 || --precision >= 0); width--) {
          if (altflag && (ch < ' ' || ch > '~')) putch('?', putdat);
          else putch(ch, putdat);
        }
        for (; width > 0; width--) putch(' ', putdat);
        break;
      case 'd': /* (signed) decimal */ {
        num = getint(&aq, lflag);
        if ((long long)num < 0) {
          putch('-', putdat);
          num = -(long long)num;
        }
        /* base = 10; */
      } goto number;
      case 'u': /* unsigned decimal */ {
        num  = getuint(&aq, lflag);
        /* base = 10; */
      } goto number;
      case 'o': /* (unsigned) octal */ {
        // LAB 1: Your code here:
        num  = getuint(&aq, lflag);
        base = 8;
      } goto number;
      case 'p': /* pointer */ {
        putch('0', putdat);
        putch('x', putdat);
        num  = (unsigned long long)(uintptr_t)va_arg(aq, void *);
        base = 16;
      } goto number;
      case 'x':
      case 'X': /* (unsigned) hexadecimal */ {
        num  = getuint(&aq, lflag);
        base = 16;
  number:
        printnum(putch, putdat, num, base, width, padc);
      } break;
      case '%': /* escaped '%' character */ {
        putch(ch, putdat);
      } break;
      default: /* unrecognized escape sequence - just print it literally */
        putch('%', putdat);
        while ((--fmt)[-1] != '%') /* nothing */;
      }
    }
  }
}

void
printfmt(void (*putch)(int, void *), void *putdat, const char *fmt, ...) {
  va_list ap;

  va_start(ap, fmt);
  vprintfmt(putch, putdat, fmt, ap);
  va_end(ap);
}

struct sprintbuf {
  char *buf;
  char *ebuf;
  int cnt;
};

static void
sprintputch(int ch, struct sprintbuf *b) {
  b->cnt++;
  if (b->buf < b->ebuf) *b->buf++ = ch;
}

int
vsnprintf(char *buf, int n, const char *fmt, va_list ap) {
  struct sprintbuf b = {buf, buf + n - 1, 0};

  if (!buf || n < 1) return -E_INVAL;

  /* print the string to the buffer */
  vprintfmt((void *)sprintputch, &b, fmt, ap);

  /* null terminate the buffer */
  *b.buf = '\0';

  return b.cnt;
}

int
snprintf(char *buf, int n, const char *fmt, ...) {
  va_list ap;

  va_start(ap, fmt);
  int rc = vsnprintf(buf, n, fmt, ap);
  va_end(ap);

  return rc;
}
