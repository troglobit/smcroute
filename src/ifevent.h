/* Kernel interface event listener.
 *
 * On platforms that support it (currently Linux netlink), ifevent_init()
 * subscribes to interface arrival/removal/flag events and refreshes the
 * iface list plus drains the pending list on each event.  On other
 * platforms it is a no-op stub.
 */
#ifndef SMCROUTE_IFEVENT_H_
#define SMCROUTE_IFEVENT_H_

void ifevent_init(void);
void ifevent_exit(void);

#endif /* SMCROUTE_IFEVENT_H_ */
