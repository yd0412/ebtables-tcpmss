#ifndef __LINUX_BRIDGE_EBT_TCPMSS_T_H
#define __LINUX_BRIDGE_EBT_TCPMSS_T_H

struct ebt_tcpmss_t_info
{
	__u16 mss;
};
#define EBT_TCPMSS_TARGET "tcpmss"

#endif
