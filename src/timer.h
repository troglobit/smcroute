/* Timer helper functions */
#ifndef SMCROUTE_TIMER_H_
#define SMCROUTE_TIMER_H_

int timer_init (void);
int timer_add  (int period, void (*cb)(void *), void *arg);

#endif /* SMCROUTE_TIMER_H_ */
