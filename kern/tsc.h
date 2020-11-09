/* See COPYRIGHT for copyright information. */

#ifndef JOS_KERN_TSC_H
#define JOS_KERN_TSC_H
#ifndef JOS_KERNEL
#error "This is a JOS kernel header; user programs should not #include it"
#endif

extern unsigned long cpu_freq;

uint64_t tsc_calibrate(void);
void timer_start(const char *name);
void timer_stop(void);
void timer_cpu_frequency(const char *name);
uint64_t get_tsc();

#endif // !JOS_KERN_TSC_H
