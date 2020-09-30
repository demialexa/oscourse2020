/* See COPYRIGHT for copyright information. */

#include <inc/x86.h>
#include <kern/kclock.h>

void
rtc_init(void) {
  nmi_disable();

  uint8_t val;

  // LAB 4: Your code here
  outb(IO_RTC_CMND, RTC_AREG);
  val = inb(IO_RTC_DATA);

  outb(IO_RTC_CMND, RTC_AREG);
  outb(IO_RTC_DATA, SET_NEW_RATE(val, RTC_500MS_RATE));

  outb(IO_RTC_CMND, RTC_BREG);
  val = inb(IO_RTC_DATA);

  outb(IO_RTC_CMND, RTC_BREG);
  outb(IO_RTC_DATA, val | RTC_PIE);
}

uint8_t
rtc_check_status(void) {
  uint8_t status = 0;
  // LAB 4: Your code here

  outb(IO_RTC_CMND, RTC_CREG);
  status = inb(IO_RTC_DATA);

  return status;
}
