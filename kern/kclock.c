/* See COPYRIGHT for copyright information. */

#include <inc/x86.h>
#include <kern/kclock.h>

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
