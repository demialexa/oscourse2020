/* See COPYRIGHT for copyright information. */

#ifndef JOS_KERN_PICIRQ_H
#define JOS_KERN_PICIRQ_H
#ifndef JOS_KERNEL
#    error "This is a JOS kernel header; user programs should not #include it"
#endif

/* Number of IRQs */
#define MAX_IRQS 16

/* I/O Addresses of the two 8259A programmable interrupt controllers */
/* Master (IRQs 0-7) */
#define IO_PIC1 0x20
/* Slave (IRQs 8-15) */
#define IO_PIC2 0xA0

#define IO_PIC1_CMND IO_PIC1
#define IO_PIC1_DATA IO_PIC1 + 1

#define IO_PIC2_CMND IO_PIC2
#define IO_PIC2_DATA IO_PIC2 + 1

/* IRQ at which slave connects to master */
#define IRQ_SLAVE 2

#define PIC_EOI 0x20

#ifndef __ASSEMBLER__

#include <inc/types.h>
#include <inc/x86.h>

void pic_init(void);
void pic_send_eoi(uint8_t irq);
void pic_irq_mask(uint8_t mask);
void pic_irq_unmask(uint8_t mask);

#endif // !__ASSEMBLER__

#endif // !JOS_KERN_PICIRQ_H
