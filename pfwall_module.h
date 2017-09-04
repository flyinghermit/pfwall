/*
This is a header file for kernel module. All header decelerations and includes are invoked here
*/

#ifndef __PF_MODULE_H__
#define __PF_MODULE_H__

#include <linux/module.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/list.h>
#include <linux/sysfs.h>

#include "pfwall_public.h"

/* Function prototypes */

static int rule_show(struct PF_rule *, char *, int);

static void rule_free(struct PF_rule *);

static int parse_packet(const struct sk_buff *, struct PF_rule *);

static int rule_match(const struct PF_rule *, const struct PF_rule *);

static int rules_index_exists(unsigned int);

static unsigned int rules_index_new(void);

static unsigned int packet_handle(const struct sk_buff *, __u8);

#endif
