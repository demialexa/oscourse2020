/* See COPYRIGHT for copyright information. */

#include <inc/x86.h>
#include <kern/kclock.h>
#include <kern/timer.h>
#include <kern/trap.h>
#include <kern/picirq.h>

static void
rtc_timer_init(void) {
  pic_init();
  rtc_init();
}

static void
rtc_timer_pic_interrupt(void) {
  irq_setmask_8259A(irq_mask_8259A & ~(1 << IRQ_CLOCK));
}

static void
rtc_timer_pic_handle(void) {
  rtc_check_status();
  pic_send_eoi(IRQ_CLOCK);
}

struct Timer timer_rtc = {
    .timer_name        = "rtc",
    .timer_init        = rtc_timer_init,
    .enable_interrupts = rtc_timer_pic_interrupt,
    .handle_interrupts = rtc_timer_pic_handle,
};

void
rtc_init(void) {
  nmi_disable();
  // LAB 4: Your code here
  uint8_t reg_a = 0, reg_b = 0;

  outb(IO_RTC_CMND, RTC_AREG | NMI_LOCK); // keep nmi disabled
  reg_a = inb(IO_RTC_DATA);

  reg_a = reg_a | 0x0F; // set low 4 bits => 500 ms (2 Gz)

  outb(IO_RTC_CMND, RTC_AREG | NMI_LOCK); // keep nmi disabled
  outb(IO_RTC_DATA, reg_a);

  //  task 1 - set bit PIE in rtc register B
  outb(IO_RTC_CMND, RTC_BREG | NMI_LOCK); // keep nmi disabled
  reg_b = inb(IO_RTC_DATA);

  reg_b = reg_b | RTC_PIE;

  outb(IO_RTC_CMND, RTC_BREG | NMI_LOCK); // keep nmi disabled
  outb(IO_RTC_DATA, reg_b);

  nmi_enable();
}

uint8_t
rtc_check_status(void) {
  uint8_t status = 0;
  // LAB 4 task 1: Your code here

  outb(IO_RTC_CMND, RTC_CREG | NMI_LOCK);
  status = inb(IO_RTC_DATA);
  nmi_enable();

  return status;
}
