/* See COPYRIGHT for copyright information. */

#include <inc/assert.h>
#include <inc/trap.h>

#include <kern/picirq.h>

/* Current IRQ mask.
 * Initial IRQ mask has interrupt 2 enabled (for slave 8259A) */
static uint16_t irq_mask_8259A = 0xFFFF & ~(1 << IRQ_SLAVE);
static bool pic_initilalized;


/* ICW1:  0001g0hi
 *    g:  0 = edge triggering, 1 = level triggering
 *    h:  0 = cascaded PICs, 1 = master only
 *    i:  0 = no ICW4, 1 = ICW4 required */
#define ICW1_ICW4 0x01       /* ICW4 (not) needed */
#define ICW1_SINGLE 0x02     /* Single (cascade) mode */
#define ICW1_INTERVAL4 0x04  /* Call address interval 4 (8) */
#define ICW1_LEVEL 0x08      /* Level triggered (edge) mode */
#define ICW1_INIT 0x10       /* Initialization - required! */

/* ICW4:  000nbmap
 *    n:  1 = special fully nested mode
 *    b:  1 = buffered mode
 *    m:  0 = slave PIC, 1 = master PIC
 *      (ignored when b is 0, as the master/slave role can be hardwired).
 *    a:  1 = Automatic EOI mode
 *    p:  0 = MCS-80/85 mode, 1 = intel x86 mode
 * NOTE Automatic EOI mode doesn't tend to work on the slave.
 * Linux source code says it's "to be investigated" */
#define ICW4_8086 0x01       /* 8086/88 (MCS-80/85) mode */
#define ICW4_AUTO 0x02       /* Auto (normal) EOI */
#define ICW4_BUF_SLAVE 0x08  /* Buffered mode/slave */
#define ICW4_BUF_MASTER 0x0C /* Buffered mode/master */
#define ICW4_SFNM 0x10       /* Special fully nested (not) */

/* OCW3:  0ef01prs
 *   ef:  0x = NOP, 10 = clear specific mask, 11 = set specific mask
 *    p:  0 = no polling, 1 = polling mode
 *   rs:  0x = NOP, 10 = read IRR, 11 = read ISR */
#define OCW3 0x08
#define OCW3_CLEAR 0x40
#define OCW3_SET 0x60
#define OCW3_POLL 0x04
#define OCW3_IRR 0x02
#define OCW3_ISR 0x03

static void
set_irq_mask(uint16_t mask) {
    outb(IO_PIC1_DATA, (uint8_t)mask);
    outb(IO_PIC2_DATA, (uint8_t)(mask >> 8));
}

static void print_irq_mask(uint16_t mask) {
    cprintf("enabled interrupts:");
    for (int i = 0; i < 16; i++) {
        if (~mask & (1 << i))
            cprintf(" %d", i);
    }
    cprintf("\n");
}


/* Initialize the 8259A interrupt controllers. */
void
pic_init(void) {

    /* mask all interrupts */
    set_irq_mask(0xFFFF);

    /* Set up master (8259A-1) */

    /* ICW1: Initialize, wait for icw4 */
    outb(IO_PIC1_CMND, ICW1_INIT | ICW1_ICW4);
    /* ICW2:  Vector offset */
    outb(IO_PIC1_DATA, IRQ_OFFSET);
    /* ICW3:  bit mask of IR lines connected to slave PICs (master PIC),
     *        3-bit No of IR line at which slave connects to master(slave PIC) */
    outb(IO_PIC1_DATA, 1 << IRQ_SLAVE);
    /* ICW4: 8086 mode */
    outb(IO_PIC1_DATA, ICW4_8086);

    /* Set up slave (8259A-2) */

    /* ICW1 */
    outb(IO_PIC2_CMND, ICW1_INIT | ICW1_ICW4);
    /* ICW2 */
    outb(IO_PIC2_DATA, IRQ_OFFSET + 8);
    /* ICW3 */
    outb(IO_PIC2_DATA, IRQ_SLAVE);
    /* ICW4 */
    outb(IO_PIC2_DATA, ICW4_8086);

    /* OCW3 */
    /* Clear specific mask */
    outb(IO_PIC1_CMND, OCW3 | OCW3_SET);
    /* Read IRR by default */
    outb(IO_PIC1_CMND, OCW3 | OCW3_IRR);

    /* OCW3 */
    outb(IO_PIC2_CMND, OCW3 | OCW3_SET);
    outb(IO_PIC2_CMND, OCW3 | OCW3_IRR);

    pic_initilalized = 1;

    if (irq_mask_8259A != 0xFFFF)
        set_irq_mask(irq_mask_8259A);
    print_irq_mask(irq_mask_8259A);
}

void
pic_irq_mask(uint8_t irq) {
    irq_mask_8259A |= (1 << irq);
    if (pic_initilalized) {
        set_irq_mask(irq_mask_8259A);
        print_irq_mask(irq_mask_8259A);
    }
}

void
pic_irq_unmask(uint8_t irq) {
    irq_mask_8259A &= ~(1 << irq);
    if (pic_initilalized) {
        set_irq_mask(irq_mask_8259A);
        print_irq_mask(irq_mask_8259A);
    }
}

void
pic_send_eoi(uint8_t irq) {
    if (irq > 7) outb(IO_PIC2_CMND, PIC_EOI);
    outb(IO_PIC1_CMND, PIC_EOI);
}
