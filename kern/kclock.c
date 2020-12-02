/* See COPYRIGHT for copyright information. */

#include <inc/x86.h>
#include <inc/time.h>
#include <kern/kclock.h>
#include <kern/timer.h>
#include <kern/trap.h>
#include <kern/picirq.h>

uint8_t
cmos_read8(uint8_t reg) {
    /* MC146818A controller */
    outb(CMOS_CMD, reg | CMOS_NMI_LOCK);
    uint8_t res = inb(CMOS_DATA);
    nmi_enable();
    return res;
}

void
cmos_write8(uint8_t reg, uint8_t value) {
    outb(CMOS_CMD, reg | CMOS_NMI_LOCK);
    outb(CMOS_DATA, value);
    nmi_enable();
}

uint16_t
cmos_read16(uint8_t reg) {
    return cmos_read8(reg) | (cmos_read8(reg + 1) << 8);
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
        .timer_name = "rtc",
        .timer_init = rtc_timer_init,
        .enable_interrupts = rtc_timer_pic_interrupt,
        .handle_interrupts = rtc_timer_pic_handle,
};

static int
get_time(void) {
    struct tm time;

    time.tm_sec = BCD2BIN(cmos_read8(RTC_SEC));
    time.tm_min = BCD2BIN(cmos_read8(RTC_MIN));
    time.tm_hour = BCD2BIN(cmos_read8(RTC_HOUR));
    time.tm_mday = BCD2BIN(cmos_read8(RTC_DAY));
    time.tm_mon = BCD2BIN(cmos_read8(RTC_MON));
    time.tm_year = BCD2BIN(cmos_read8(RTC_YEAR));

    return timestamp(&time);
}

int
gettime(void) {
    // LAB 12: your code here
    int res;

    do {
        while (cmos_read8(RTC_AREG) &
               RTC_UPDATE_IN_PROGRESS) {
            asm volatile("pause");
        }
        res = get_time();
    } while (res != get_time());

    return res;
}

void
rtc_timer_init(void) {
    // LAB 4: Your code here

    uint8_t rga = cmos_read8(RTC_AREG);
    cmos_write8(RTC_AREG, RTC_SET_NEW_RATE(rga, RTC_500MS_RATE));

    uint8_t rgb = cmos_read8(RTC_BREG);
    cmos_write8(RTC_BREG, rgb | RTC_PIE);
}

uint8_t
rtc_check_status(void) {
    // LAB 4: Your code here

    return cmos_read8(RTC_CREG);
}
