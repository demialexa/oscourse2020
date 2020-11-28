#include <inc/x86.h>
#include <inc/string.h>

#include "fs.h"

static char *msg = "This is the NEW message of the day!\n\n";

void check_dir(struct File *dir);

static inline void
check_consistency(void) {
    check_dir(&super->s_root);
}

void
check_dir(struct File *dir) {
    uint32_t *blk;
    struct File *files;

    uint32_t nblock = dir->f_size / BLKSIZE;
    for (uint32_t i = 0; i < nblock; ++i) {
        if (file_block_walk(dir, i, &blk, 0) < 0) continue;

        files = (struct File *)diskaddr(*blk);

        for (uint32_t j = 0; j < BLKFILES; ++j) {
            struct File *f = &(files[j]);
            if (strcmp(f->f_name, "\0") != 0) {
                uint32_t *pdiskbno = NULL;

                cprintf("checking consistency of %s\n", f->f_name);

                for (uint32_t k = 0; k < (f->f_size + BLKSIZE - 1) / BLKSIZE; ++k) {
                    if (f->f_type == FTYPE_DIR) {
                        check_dir(f);
                    }
                    if (file_block_walk(f, k, &pdiskbno, 0) < 0 || pdiskbno == NULL || *pdiskbno == 0) {
                        continue;
                    }
                    assert(!block_is_free(*pdiskbno));
                }
            }
        }
    }
}

void
fs_test(void) {
    struct File *f;
    int r;
    char *blk;
    uint32_t *bits;

    /* Back up bitmap */
    if ((r = sys_page_alloc(0, (void *)PAGE_SIZE, PTE_P | PTE_U | PTE_W)) < 0)
        panic("sys_page_alloc: %i", r);
    bits = (uint32_t *)PAGE_SIZE;
    memmove(bits, bitmap, PAGE_SIZE);
    /* Allocate block */
    if ((r = alloc_block()) < 0)
        panic("alloc_block: %i", r);
    /* Check that block was free */
    assert(bits[r / 32] & (1U << (r % 32)));
    /* And is not free any more */
    assert(!(bitmap[r / 32] & (1U << (r % 32))));
    cprintf("alloc_block is good\n");
    check_consistency();
    cprintf("fs consistency is good\n");

    if ((r = file_open("/not-found", &f)) < 0 && r != -E_NOT_FOUND)
        panic("file_open /not-found: %i", r);
    else if (r == 0)
        panic("file_open /not-found succeeded!");
    if ((r = file_open("/newmotd", &f)) < 0)
        panic("file_open /newmotd: %i", r);
    cprintf("file_open is good\n");

    if ((r = file_get_block(f, 0, &blk)) < 0)
        panic("file_get_block: %i", r);
    if (strcmp(blk, msg) != 0)
        panic("file_get_block returned wrong data");
    cprintf("file_get_block is good\n");

    *(volatile char *)blk = *(volatile char *)blk;
    assert((uvpt[VPT(blk)] & PTE_D));
    file_flush(f);
    assert(!(uvpt[VPT(blk)] & PTE_D));
    cprintf("file_flush is good\n");

    if ((r = file_set_size(f, 0)) < 0)
        panic("file_set_size: %i", r);
    assert(f->f_direct[0] == 0);
    assert(!(uvpt[VPT(f)] & PTE_D));
    cprintf("file_truncate is good\n");

    if ((r = file_set_size(f, strlen(msg))) < 0)
        panic("file_set_size 2: %i", r);
    assert(!(uvpt[VPT(f)] & PTE_D));
    if ((r = file_get_block(f, 0, &blk)) < 0)
        panic("file_get_block 2: %i", r);
    strcpy(blk, msg);
    assert((uvpt[VPT(blk)] & PTE_D));
    file_flush(f);
    assert(!(uvpt[VPT(blk)] & PTE_D));
    assert(!(uvpt[VPT(f)] & PTE_D));
    cprintf("file rewrite is good\n");
}
