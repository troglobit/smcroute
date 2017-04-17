/* Physical and virtual interface API */
#ifndef SMCROUTE_IFVC_H_
#define SMCROUTE_IFVC_H_

void          iface_init            (void);
void          iface_exit            (void);
struct iface *iface_find_by_name    (const char *ifname);
struct iface *iface_find_by_index   (unsigned int ifindex);
struct iface *iface_find_by_vif     (int vif);
int           iface_get_vif         (struct iface *iface);
int           iface_get_mif         (struct iface *iface);
int           iface_get_vif_by_name (const char *ifname);
int           iface_get_mif_by_name (const char *ifname);

#endif /* SMCROUTE_IFVC_H_ */

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
