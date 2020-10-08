/* See COPYRIGHT for copyright information. */

#include <inc/x86.h>
#include <kern/kclock.h>
#include <kern/timer.h>
#include <kern/trap.h>
#include <kern/picirq.h>

static void
rtc_timer_init(void) {
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

  // LAB 4: Your code here:

  outb(IO_RTC_CMND, RTC_AREG);
  uint8_t rga = inb(IO_RTC_DATA);
  outb(IO_RTC_CMND, RTC_AREG);
  outb(IO_RTC_DATA, SET_NEW_RATE(rga, RTC_500MS_RATE));

  outb(IO_RTC_CMND, RTC_BREG);
  uint8_t rgb = inb(IO_RTC_DATA);
  outb(IO_RTC_CMND, RTC_BREG);
  outb(IO_RTC_DATA, rgb | RTC_PIE);

  nmi_enable();
}

uint8_t
rtc_check_status(void) {
  // LAB 4: Your code here:

  outb(IO_RTC_CMND, RTC_CREG);
  uint8_t status = inb(IO_RTC_DATA);

  return status;
}
