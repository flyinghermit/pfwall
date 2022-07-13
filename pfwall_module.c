/*
Main kernel module core working is defined here
*/


//For separation in shared header include with userspace.
#define PF_KERNELSPACE

#include "pfwall_module.h"
#include <linux/version.h>

// Rules linked list
static LIST_HEAD(rules_list);

// Netfilter hook structures: Incoming and Outgoing traffic.
static struct nf_hook_ops nfhi;
static struct nf_hook_ops nfho;

// Incoming traffic hook.
unsigned int pfwall_hook_in(void *priv_unused,
			    struct sk_buff *skb,
			    const struct nf_hook_state *state_unused)
{
	return packet_handle(skb, DIRECTION_IN);
}

// Outgoing traffic hook.
unsigned int pfwall_hook_out(void *priv_unused,
			     struct sk_buff *skb,
			     const struct nf_hook_state *state_unused)
{
	return packet_handle(skb, DIRECTION_OUT);
}

// Socket buffer receives packets and buffer it. it copies the raw packet into the memory and calls packet handler to parse it
//direction value are defined here (Incoming and Outgoing)
//returns NF_* value based on rules list matching
unsigned int packet_handle(const struct sk_buff *skb, __u8 direction)
{
	struct PF_rule *rule, packet_info;

	// Get packet info in a PF_rule style structure
	memset(&packet_info, '\0', sizeof(packet_info));
	packet_info.direction = direction;
	if (parse_packet(skb, &packet_info))
		return NF_ACCEPT;

	// Match packet with every rule
	list_for_each_entry(rule, &rules_list, list)
		if (rule_match(rule, &packet_info)) {
			switch(rule->action) {
			case ACT_DROP:
				printk("Pfwall: #%d -> Drop packet.\n",
				       rule->index);
				return NF_DROP;
			case ACT_PASS:
				printk("Pfwall: #%d -> Pass packet.\n",
				       rule->index);
				return NF_STOP;
			case ACT_LOG:
				printk("Pfwall: #%d -> Log packet (XXX).\n",
				       rule->index);
				return NF_ACCEPT;
			}
		}

	/* Default is to accept packet. */
	return NF_ACCEPT;
}


 // Extracts relevant information from sk_buff to PF_rule
static int parse_packet(const struct sk_buff *skb, struct PF_rule *packet_info)
{
	struct iphdr *ip_header;

	if (!packet_info || !skb)
		return 1;

	ip_header = (struct iphdr *) skb_network_header(skb);
	packet_info->srcip = ip_header->saddr;
	packet_info->dstip = ip_header->daddr;

	// Network Protocol
	if (ip_header->protocol == IPPROTO_TCP) {
		struct tcphdr *tcp_header;

		packet_info->proto = PROTO_TCP;
		tcp_header = (struct tcphdr *) ((char *) ip_header
						+ (ip_header->ihl * 4));
		packet_info->srcport = ntohs(tcp_header->source);
		packet_info->dstport = ntohs(tcp_header->dest);
	}
	else if (ip_header->protocol == IPPROTO_UDP) {
		struct udphdr *udp_header;

		packet_info->proto = PROTO_UDP;
		udp_header = (struct udphdr *) ((char *) ip_header
						+ (ip_header->ihl * 4));
		packet_info->srcport = ntohs(udp_header->source);
		packet_info->dstport = ntohs(udp_header->dest);
	}
	else
		packet_info->proto = PROTO_ALL;

	return 0;
}

// Check whether rule matches
static int rule_match(const struct PF_rule *rule,
		      const struct PF_rule *pinfo)
{
	if (rule->direction != DIRECTION_ALL
	    && rule->direction != pinfo->direction)
		return 0;

	if (rule->proto != PROTO_ALL
	    && rule->proto != pinfo->proto)
		return 0;

	if (rule->srcip && rule->srcip != pinfo->srcip)
		return 0;

	if (rule->dstip && rule->dstip != pinfo->dstip)
		return 0;

	if (rule->srcport && rule->srcport != pinfo->srcport)
		return 0;

	if (rule->dstport && rule->dstport != pinfo->dstport)
		return 0;

	return 1;
}

static struct PF_rule* rule_create(const char *buffer, size_t size)
{
	int cmd, action, index, direction, proto, srcport, dstport;
	struct PF_rule *new_rule;
	__u32 srcip, dstip;

	if (sscanf(buffer, "%d %d %d %d %d %u %u %d %d", &cmd, &index, &action,
		   &direction, &proto, &srcip, &dstip, &srcport, &dstport)
	    != 9) {
		printk("Pfwall: sscanf() failed.\n");
		return NULL;
	}

	if (cmd != CMD_ADD)
		return NULL;
	if (action < 0 || action >= ACT_MAX)
		return NULL;
	if (index < 0)
		return NULL;

	// Default index: Higher than all current rules in list.
	if (index == 0)
		index = rules_index_new();

	if (direction < 0 || direction >= DIRECTION_MAX)
		return NULL;
	if (proto < 0 || proto > PROTO_MAX)
		return NULL;
	if (srcport < 0 || srcport > PORT_MAX)
		return NULL;
	if (dstport < 0 || dstport > PORT_MAX)
		return NULL;

	new_rule = kmalloc(sizeof(*new_rule), GFP_KERNEL);
	if (!new_rule)
		return NULL;

	new_rule->index = index;
	new_rule->action = action;
	new_rule->direction = direction;
	new_rule->proto = proto;
	new_rule->srcip = srcip;
	new_rule->dstip = dstip;
	new_rule->srcport = srcport;
	new_rule->dstport = dstport;

	return new_rule;
}

static void rule_add(struct PF_rule *newrule)
{
	struct PF_rule *rule = NULL;

	// Find where to insert new rule.
	list_for_each_entry(rule, &rules_list, list) {
		if (rule->index > newrule->index)
			break;
	}

	// Insert rule
	if (rule)
		list_add_tail(&newrule->list, &rule->list);
	// Either list is empty, or new index is higher than all others.
	else
		list_add_tail(&newrule->list, &rules_list);

	printk("Pfwall: #%d added.\n", newrule->index);
}

static int rule_delete(const char *buffer, size_t size, int *index)
{
	int cmd;
	struct PF_rule *rule, *tmp;

	if (!index)
		return -1;

	sscanf(buffer, "%d %d", &cmd, index);
	if (cmd != CMD_DEL)
		return -1;

	list_for_each_entry_safe(rule, tmp, &rules_list, list)
		if (rule->index == *index) {
			printk("Pfwall: #%d deleted.\n", rule->index);
			list_del(&rule->list);
			rule_free(rule);
			return 0;
		}

	return 1;
}

static int rule_show(struct PF_rule *rule, char *buf, int size)
{
	return snprintf(buf, size, "#%d: %s %s %pI4->%pI4 %s:%d->%d\n",
			rule->index,
			action_to_str(rule->action),
			direction_to_str(rule->direction),
			&rule->srcip,
			&rule->dstip,
			proto_to_str(rule->proto),
			rule->srcport,
			rule->dstport);
}


//Check if a rule already exists
static int rules_index_exists(unsigned int index)
{
	struct PF_rule *rule;

	list_for_each_entry(rule, &rules_list, list)
		if (rule->index == index)
			return 1;

	return 0;
}

// Get rule index
static unsigned int rules_index_new()
{
	struct PF_rule *rule;

	//Last index is highest
	if (rules_list.prev != &rules_list) {
	    rule = list_entry(rules_list.prev, struct PF_rule, list);
	    return rule->index + 1;
	}

	return 1;
}

// Delete rules
static void rules_delete(void)
{
	struct PF_rule *rule, *tmp;

	list_for_each_entry_safe(rule, tmp, &rules_list, list) {
		list_del(&rule->list);
		rule_free(rule);
	}
}

// Free rule memory
static void rule_free(struct PF_rule *rule)
{
	kfree(rule);
}

static ssize_t PF_show(struct class *cls, struct class_attribute *attr,
			char *buf)
{
	struct PF_rule *rule;
	int index = 0;

	list_for_each_entry(rule, &rules_list, list) {
		index += rule_show(rule, buf + index, PAGE_SIZE - index);
		if (index >= PAGE_SIZE) {
			// XXX
			printk("Pfwall: Rules print higher than page size.\n");
			break;
		}
	}

	return index;
}

static ssize_t PF_store(struct class *cls,
			 struct class_attribute *attr,
			 const char *buffer, size_t count)
{
	struct PF_rule *rule;
	int command;
	unsigned int index;

	sscanf(buffer, "%d", &command);
	printk("Pfwall: %s CMD.\n", cmd_to_str(command));

	switch(command) {
	case CMD_ADD:
		// Scan buffer and create rule structure.
		rule = rule_create(buffer, count);
		if (!rule) {
			printk("Pfwall: Rule creation failed.\n");
			return count;
		}
		// Check that the index is unique.
		if (rules_index_exists(rule->index)) {
			printk("Pfwall: #%d exists already.\n",
			       rule->index);

			rule_free(rule);
			return count;
		}
		// Add rule to rules list.
		rule_add(rule);
		return count;

	case CMD_DEL:
		if (rule_delete(buffer, count, &index))
			printk("Pfwall: #%d not found.\n", index);

		return count;

	case CMD_FLUSH:
		rules_delete();
		return count;

	default:
		printk("Pfwall: Unknown command value %d.\n", command);
		return count;
	}
}

// Sysfs class declaration
static struct class *PF_class;
static const struct class_attribute PF_attr = {
	.attr = {
		.name = "pfwall_file",
		.mode = S_IWUSR | S_IRUGO,
	},
	.show = PF_show,
	.store = PF_store,
};

// Crete Sysfs virtual file
int sysfs_init(void)
{
	PF_class = class_create(THIS_MODULE, "pfwall");
	if (IS_ERR(PF_class)) {
		pr_err("Couldn't create Sysfs class.\n");
		return PTR_ERR(PF_class);
	}

	return class_create_file(PF_class, &PF_attr);
}

// Initialize module
int pfwall_init(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
	struct net *n;
#endif
	printk("Pfwall: module inserted.\n");

	//Register Netfilter hooks.
	// Incoming
	nfhi.hook = pfwall_hook_in;
	nfhi.hooknum = NF_INET_PRE_ROUTING;
	nfhi.pf = PF_INET;
	nfhi.priority = NF_IP_PRI_FIRST;

	// Outgoing
	nfho.hook = pfwall_hook_out;
	nfho.hooknum = NF_INET_POST_ROUTING;
	nfho.pf = PF_INET;
	nfho.priority = NF_IP_PRI_FIRST;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
	for_each_net(n)
		nf_register_net_hook(n, &nfhi);
	for_each_net(n)
		nf_register_net_hook(n, &nfho);
#else
	nf_register_hook(&nfhi);
	nf_register_hook(&nfho);
#endif

	// Create sysfs class
	return sysfs_init();
}

// Remove module
void pfwall_exit(void)
{
	// Unregister Netfilter hooks.
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
	struct net *n;
	for_each_net(n)
		nf_unregister_net_hook(n, &nfhi);
	for_each_net(n)
		nf_unregister_net_hook(n, &nfho);
#else
	nf_unregister_hook(&nfhi);
	nf_unregister_hook(&nfho);
#endif

	// Destroy sysfs class
	class_destroy(PF_class);

	// Free rules
	rules_delete();

	printk("Pfwall: module removed.\n");
}

module_init(pfwall_init);
module_exit(pfwall_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Sakshyam Shah");
MODULE_DESCRIPTION("proxyfirewall");
