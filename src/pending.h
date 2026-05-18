/* Pending routes/groups whose inbound interface is not yet available. */
#ifndef SMCROUTE_PENDING_H_
#define SMCROUTE_PENDING_H_

#include "show.h"

void pending_init       (void);
void pending_exit       (void);

int  pending_add_mroute (const char *iif, const char *source, const char *group,
			 char *const oif[], int num);
int  pending_add_mgroup (const char *iif, const char *source, const char *group);

/* Empty the list, e.g. before re-reading the config. */
void pending_clear      (void);

/* Walk the list, retry each entry, drop the successful ones. */
void pending_drain      (void);

int  pending_show       (int sd, enum show_mode mode);

#endif /* SMCROUTE_PENDING_H_ */
