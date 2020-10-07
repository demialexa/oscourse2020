#ifndef JOS_INC_ALLOC_H
#define JOS_INC_ALLOC_H

#include <inc/types.h>

/* block header */
struct header {
  /* next block */
  struct header *next;
  /* prev block */
  struct header *prev;
  /* force alignment of blocks */
  _Alignas(_Alignof(long))
  /* size of this block */
  size_t size;
} __attribute__((packed));

typedef struct header Header;

#endif
