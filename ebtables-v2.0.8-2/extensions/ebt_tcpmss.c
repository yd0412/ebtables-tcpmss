#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include "../include/ebtables_u.h"
#include <linux/netfilter_bridge/ebt_tcpmss_t.h>

static int tcpmss_supplied;

#define TCPMSS_TARGET  '1'
#define TCPMSS_SETTCPMSS '2'
#define TCPMSS_ORTCPMSS  '3'
#define TCPMSS_ANDTCPMSS '4'
#define TCPMSS_XORTCPMSS '5'
static struct option opts[] =
{
	 {.name = "set-mss",           .has_arg = 1,  .val = '1'},
	 {.name = "clamp-mss-to-pmtu", .has_arg = 0, .val = '2'},
	{ 0 }
};

static void print_help()
{
    printf(
"TCPMSS target mutually-exclusive options:\n"
"  --set-mss value               explicitly set MSS option to specified value\n"
"  --clamp-mss-to-pmtu           automatically clamp MSS value to (path_MTU - %d)\n");
}

static void init(struct ebt_entry_target *target)
{
	struct ebt_tcpmss_t_info *tcpmssinfo =
	   (struct ebt_tcpmss_t_info *)target->data;

	tcpmssinfo->mss = 0xffff;
	tcpmss_supplied = 0;
}

static int parse(int c, char **argv, int argc,
   const struct ebt_u_entry *entry, unsigned int *flags,
   struct ebt_entry_target **target)
{
	struct ebt_tcpmss_t_info *tcpmssinfo =
	   (struct ebt_tcpmss_t_info *)(*target)->data;
	unsigned int mssval;
	char *end;

	switch (c) {
		case '1':
			if (*flags)
				ebt_print_error2("TCPMSS target: Only one option may be specified");
		    tcpmssinfo->mss = strtoul(optarg, &end, 0);
     		if (*end != '\0' || end == optarg)
	        	ebt_print_error2("Bad TCPMSS value '%s'", optarg);

			*flags = 1;
			break;
		case '2':
            if (*flags)
                ebt_print_error2("TCPMSS target: Only one option may be specified");
			tcpmssinfo->mss=0xffff;

            *flags = 1;
            break;

		default:
			return 0;
	}
	tcpmss_supplied = 1;
	return 1;
}

static void final_check(const struct ebt_u_entry *entry,
   const struct ebt_entry_target *target, const char *name,
   unsigned int hookmask, unsigned int time)
{
	struct ebt_tcpmss_t_info *tcpmssinfo =
	   (struct ebt_tcpmss_t_info *)target->data;

	if (time == 0 && tcpmss_supplied == 0) {
		ebt_print_error("No tcpmss value supplied");
	} 
}

static void print(const struct ebt_u_entry *entry,
   const struct ebt_entry_target *target)
{
	struct ebt_tcpmss_t_info *tcpmssinfo =
	   (struct ebt_tcpmss_t_info *)target->data;

	if(tcpmssinfo->mss == 0xffff)
        printf("TCPMSS clamp to PMTU ");
    else
        printf("TCPMSS set %u ", tcpmssinfo->mss);

}

static int compare(const struct ebt_entry_target *t1,
   const struct ebt_entry_target *t2)
{
	struct ebt_tcpmss_t_info *tcpmssinfo1 =
	   (struct ebt_tcpmss_t_info *)t1->data;
	struct ebt_tcpmss_t_info *tcpmssinfo2 =
	   (struct ebt_tcpmss_t_info *)t2->data;

	return  tcpmssinfo1->mss == tcpmssinfo2->mss;
}

static struct ebt_u_target tcpmss_target =
{
	.name		= EBT_TCPMSS_TARGET,
	.size		= sizeof(struct ebt_tcpmss_t_info),
	.help		= print_help,
	.init		= init,
	.parse		= parse,
	.final_check	= final_check,
	.print		= print,
	.compare	= compare,
	.extra_ops	= opts,
};

void _init(void)
{
	ebt_register_target(&tcpmss_target);
}
