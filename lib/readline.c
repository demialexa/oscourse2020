#include <inc/stdio.h>
#include <inc/error.h>
#include <inc/types.h>

#define BUFLEN 1024

static char buf[BUFLEN];

char *
readline(const char *prompt) {
  if (prompt) cprintf("%s", prompt);

  bool echo = iscons(0);

  for (size_t i = 0;;) {
    int c = getchar();

    if (c < 0) {
      cprintf("read error: %i\n", c);
      return NULL;
    }

    if ((c == '\b' || c == '\x7F') && i) {
      if (echo) {
        cputchar('\b');
        cputchar(' ');
        cputchar('\b');
      }
      i--;
    } else if (c >= ' ' && i < BUFLEN - 1) {
      if (echo) {
        cputchar(c);
      }
      buf[i++] = (char)c;
    } else if (c == '\n' || c == '\r') {
      if (echo) {
        cputchar('\n');
      }
      buf[i] = 0;
      return buf;
    }
  }
}
