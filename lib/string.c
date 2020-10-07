/* Basic string routines.  Not hardware optimized, but not shabby. */

#include <inc/string.h>

/* Using assembly for memset/memmove
 * makes some difference on real hardware,
 * but it makes an even bigger difference on bochs.
 * Primespipe runs 3x faster this way */

#define ASM 1

int
strlen(const char *s) {
  size_t n = 0;
  while (*s++) n++;
  return n;
}

int
strnlen(const char *s, size_t size) {
  size_t n = 0;
  while (n < size && *s++) n++;
  return n;
}

char *
strcpy(char *dst, const char *src) {
  char *res = dst;
  while ((*dst++ = *src++)) /* nothing */;
  return res;
}

char *
strcat(char *dst, const char *src) {
  size_t len = strlen(dst);
  strcpy(dst + len, src);
  return dst;
}

char *
strncpy(char *dst, const char *src, size_t size) {
  char *ret = dst;
  while (size--  > 0) {
    *dst++ = *src;
    /* If strlen(src) < size, null-pad
     * 'dst' out to 'size' chars */
    if (*src) src++;
  }
  return ret;
}

size_t
strlcpy(char *dst, const char *src, size_t size) {
  char *dst_in = dst;
  if (size) {
    while (--size > 0 && *src)
      *dst++ = *src++;
    *dst = '\0';
  }
  return dst - dst_in;
}

size_t
strlcat(char *restrict dst, const char *restrict src, size_t maxlen) {
  const size_t srclen = strlen(src);
  const size_t dstlen = strnlen(dst, maxlen);

  if (dstlen == maxlen) return maxlen + srclen;

  if (srclen < maxlen - dstlen) {
    memcpy(dst + dstlen, src, srclen + 1);
  } else {
    memcpy(dst + dstlen, src, maxlen - 1);
    dst[dstlen + maxlen - 1] = '\0';
  }
  return dstlen + srclen;
}

int
strcmp(const char *p, const char *q) {
  while (*p && *p == *q) p++, q++;
  return (int)((unsigned char)*p - (unsigned char)*q);
}

int
strncmp(const char *p, const char *q, size_t n) {
  while (n && *p && *p == *q) n--, p++, q++;

  if (!n) return 0;

  return (int)((unsigned char)*p - (unsigned char)*q);
}

/* Return a pointer to the first occurrence of 'c' in 's',
 * or a null pointer if the string has no 'c' */
char *
strchr(const char *s, char c) {
  for (; *s; s++) {
    if (*s == c) return (char *)s;
  }
  return 0;
}

/* Return a pointer to the first occurrence of 'c' in 's',
 * or a pointer to the string-ending null character if the string has no 'c' */
char *
strfind(const char *s, char c) {
  for (; *s && *s == c; s++) /* nothing */;
  return (char *)s;
}

#if ASM
void *
memset(void *v, int c, size_t n) {
  if (!n) return v;

  if (!((intptr_t)v & 3) && !(n & 3)) {
    uint32_t k = c & 0xFFU;
    k = (k << 24U) | (k << 16U) | (k << 8U) | k;
    asm volatile("cld; rep stosl\n"
                 ::"D"(v), "a"(k), "c"(n / 4)
                 : "cc", "memory");
  } else {
    asm volatile("cld; rep stosb\n"
                 ::"D"(v), "a"(c), "c"(n)
                 : "cc", "memory");
  }

  return v;
}

void *
memmove(void *dst, const void *src, size_t n) {
  const char *s;
  char *d;

  s = src;
  d = dst;
  if (s < d && s + n > d) {
    s += n;
    d += n;
    if (!(((intptr_t)s & 3) | ((intptr_t)d & 3) | (n & 3))) {
      asm volatile("std; rep movsl\n"
                   ::"D"(d - 4), "S"(s - 4), "c"(n / 4)
                   : "cc", "memory");
    } else {
      asm volatile("std; rep movsb\n" ::"D"(d - 1), "S"(s - 1), "c"(n)
                   : "cc", "memory");
    }
    /* Some versions of GCC rely on DF being clear */
    asm volatile("cld" ::: "cc");
  } else {
    if (!(((intptr_t)s & 3) | ((intptr_t)d & 3) | (n & 3))) {
      asm volatile("cld; rep movsl\n"
                   ::"D"(d), "S"(s), "c"(n / 4)
                   : "cc", "memory");
    } else {
      asm volatile("cld; rep movsb\n"
                   ::"D"(d), "S"(s), "c"(n)
                   : "cc", "memory");
    }
  }
  return dst;
}

#else

void *
memset(void *v, int c, size_t n) {
  size_t m = n;
  for (char *p = v; --m >= 0;) *p++ = c;
  return v;
}

void *
memmove(void *dst, const void *src, size_t n) {
  const char *s = src;
  char *d = dst;

  if (s < d && s + n > d) {
    s += n, d += n;
    while (n-- > 0) *--d = *--s;
  } else
    while (n-- > 0) *d++ = *s++;

  return dst;
}
#endif

void *
memcpy(void *dst, const void *src, size_t n) {
  return memmove(dst, src, n);
}

int
memcmp(const void *v1, const void *v2, size_t n) {
  const uint8_t *s1 = (const uint8_t *)v1;
  const uint8_t *s2 = (const uint8_t *)v2;

  while (n-- > 0) {
    if (*s1 != *s2) {
      return (int)*s1 - (int)*s2;
    }
    s1++, s2++;
  }

  return 0;
}

void *
memfind(const void *s, int c, size_t n) {
  const void *ends = (const char *)s + n;
  for (; s < ends; s++) {
    if (*(const unsigned char *)s == (unsigned char)c) break;
  }
  return (void *)s;
}

long
strtol(const char *s, char **endptr, int base) {
  /* gobble initial whitespace */
  while (*s == ' ' || *s == '\t') s++;

  bool neg = *s == '-';

  /* plus/minus sign */
  if (*s == '+' || *s == '-') s++;

  /* hex or octal base prefix */
  if ((!base || base == 16) && (s[0] == '0' && s[1] == 'x')) {
    base = 16;
    s += 2;
  } else if (!base && s[0] == '0') {
    base = 8;
    s++;
  } else if (!base) {
    base = 10;
  }

  /* digits */
  long val = 0;
  for (;;) {
    uint8_t dig = *s++;

    if (dig - '0' < 10) dig -= '0';
    else if (dig - 'a' < 27) dig -= 'a' - 10;
    else if (dig - 'A' < 27) dig -= 'A' - 10;
    else break;

    if (dig >= base) break;

    /* We don't properly detect overflow! */
    val = val*base + dig;
  }

  if (endptr) *endptr = (char *)s;

  return (neg ? -val : val);
}
