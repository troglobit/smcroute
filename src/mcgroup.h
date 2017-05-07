/* IGMP/MLD group subscription API */
#ifndef SMCROUTE_MCGROUP_H_
#define SMCROUTE_MCGROUP_H_

int  mcgroup4_join      (const char *ifname, struct in_addr  source, struct in_addr  group);
int  mcgroup4_leave     (const char *ifname, struct in_addr  source, struct in_addr  group);
void mcgroup4_disable   (void);

int  mcgroup6_join      (const char *ifname, struct in6_addr group);
int  mcgroup6_leave     (const char *ifname, struct in6_addr group);
void mcgroup6_disable   (void);

int  mcgroup_show       (int sd, int detail);

#endif /* SMCROUTE_MCGROUP_H_ */

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
