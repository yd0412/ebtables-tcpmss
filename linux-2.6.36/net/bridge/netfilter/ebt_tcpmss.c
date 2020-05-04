/*
 *  ebt_tcpmss
 */
#include <linux/ip.h>
#include <net/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <net/tcp.h>

#include <linux/module.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter_bridge/ebtables.h>
#include <linux/netfilter_bridge/ebt_tcpmss_t.h>
#include <linux/if_ether.h>

#if 0
#define DBG_PRINTK printk
#else
#define DBG_PRINTK( a... )
#endif
static inline __be16 vlan_proto(const struct sk_buff *skb)
{
    return vlan_eth_hdr(skb)->h_vlan_encapsulated_proto;
}
static inline __be16 pppoe_proto(const struct sk_buff *skb)
{
    return *((__be16 *)(skb_mac_header(skb) + ETH_HLEN +
                sizeof(struct pppoe_hdr)));
}

static inline unsigned int
optlen(const u_int8_t *opt, unsigned int offset)
{
    /* Beware zero-length options: make finite progress */
    if (opt[offset] <= TCPOPT_NOP || opt[offset+1] == 0)
        return 1;
    else
        return opt[offset+1];
}

static int
tcpmss_mangle_packet(struct sk_buff *skb,
             const struct ebt_tcpmss_t_info *info,
             unsigned int in_mtu,
             unsigned int tcphoff)
{
    struct tcphdr *tcph;
    unsigned int tcplen, i;
    __be16 oldval;
    u16 newmss;
    u8 *opt;
	
	DBG_PRINTK("tcpmss_mangle_packet\n");
	DBG_PRINTK("tcpmss_mangle_packet %d %d \n",skb->len, tcphoff);
	tcplen = skb->len - tcphoff;
    tcph = (struct tcphdr *)(skb_network_header(skb) + tcphoff);

	if(tcph->syn)
	{
		if (info->mss == 0xffff) {
        	newmss = in_mtu-tcphoff-sizeof(struct tcphdr);
    	} else
        	newmss = info->mss;

		DBG_PRINTK("mss = %d \n",newmss);
		opt = (u_int8_t *)tcph;

		for (i = sizeof(struct tcphdr); i < tcph->doff*4; i += optlen(opt, i)) {
        	if (opt[i] == TCPOPT_MSS && tcph->doff*4 - i >= TCPOLEN_MSS &&
            	opt[i+1] == TCPOLEN_MSS) {
            	u_int16_t oldmss;

            	oldmss = (opt[i+2] << 8) | opt[i+3];

            	/* Never increase MSS, even when setting it, as
             	* doing so results in problems for hosts that rely
             	* on MSS being set correctly.
             	*/
				DBG_PRINTK("oldmss=%d\n",oldmss);
            	if (oldmss <= newmss)
                	return 0;

            	opt[i+2] = (newmss & 0xff00) >> 8;
            	opt[i+3] = newmss & 0x00ff;

            	inet_proto_csum_replace2(&tcph->check, skb,
                         htons(oldmss), htons(newmss),
                         0);
            	return 0;
        	}
    	}
	}

	return 0;
}
static unsigned int
ebt_tcpmss_tg(struct sk_buff *skb, const struct xt_action_param *par)
{
	const struct ebt_tcpmss_t_info *info = par->targinfo;
    const struct iphdr *ih;
    struct iphdr _iph;
	unsigned int offset=0;
    unsigned short eth_proto = eth_hdr(skb)->h_proto;

	DBG_PRINTK("ebt_tcpmss_tg\n");
    if(skb->protocol == htons(ETH_P_IP))
        ih = skb_header_pointer(skb, 0, sizeof(_iph), &_iph);
    else if((skb->protocol == htons(ETH_P_8021Q)) && (vlan_proto(skb) == htons(ETH_P_IP)))
        ih = (struct iphdr *)(skb_mac_header(skb) + VLAN_ETH_HLEN);
    else if((skb->protocol == htons(ETH_P_PPP_SES)) && (pppoe_proto(skb) == htons(0x0021)))
        ih = (struct iphdr *)(skb_mac_header(skb) + ETH_HLEN +PPPOE_SES_HLEN);
    else
        ih = skb_header_pointer(skb, 0, sizeof(_iph), &_iph);
	
	if (ih == NULL)
		return EBT_CONTINUE;
	
	DBG_PRINTK("%d %d %d %u.%u.%u.%u -- %u.%u.%u.%u\n",skb->len,skb->data_len,ih->protocol,NIPQUAD(ih->saddr), NIPQUAD(ih->daddr));
	if(ih->protocol==IPPROTO_TCP)
	{
		DBG_PRINTK("dev name %s %s\n",par->in?par->in->name:"none",par->out?par->out->name:"none");
		int min_mtu = min(par->in?par->in->mtu:0,par->out?par->out->mtu:0);
		if(min_mtu>0)
			tcpmss_mangle_packet(skb, par->targinfo,min_mtu,ih->ihl * 4);
	}

	return EBT_CONTINUE;
}

static int ebt_tcpmss_tg_check(const struct xt_tgchk_param *par)
{
	return 0;
}

static struct xt_target ebt_tcpmss_tg_reg __read_mostly = {
	.name		= "tcpmss",
	.revision	= 0,
	.family		= NFPROTO_BRIDGE,
	.target		= ebt_tcpmss_tg,
	.checkentry	= ebt_tcpmss_tg_check,
	.targetsize	= sizeof(struct ebt_tcpmss_t_info),
	.me		= THIS_MODULE,
};

static int __init ebt_tcpmss_init(void)
{
	return xt_register_target(&ebt_tcpmss_tg_reg);
}

static void __exit ebt_tcpmss_fini(void)
{
	xt_unregister_target(&ebt_tcpmss_tg_reg);
}

module_init(ebt_tcpmss_init);
module_exit(ebt_tcpmss_fini);
MODULE_DESCRIPTION("Ebtables: Packet tcpmss modification");
MODULE_LICENSE("GPL");
