/*
All the admin actions are performed here
*/

#include "pfwall_admin.h"
#include "pfwall_public.h"

#define SYSFS_PATH "/sys/class/pfwall/pfwall_file"

void out_help()
{
	//  Help for various commands.
	printf("Help.\n");
}

void out_list()
{
	char buff[1024];
	FILE *f = fopen(SYSFS_PATH, "r");

	if (!f) {
		fprintf(stderr, "Can't open %s\n.", SYSFS_PATH);
		return;
	}

	while (fgets(buff, sizeof(buff) - 1, f) != NULL)
		fputs(buff, stdout);

	fclose(f);
}

void out_error()
{
	//  Take int argument for different error messages.
	printf("Errors be here.\n");
}

// Initialize a PF_rule structure.
//backlash is used in order to separate different statement tht has to be written on single line
//part of awk GNU interpretation 
#define PF_rule_new(pfrule)					\
	do {							\
		pfrule = calloc(1, sizeof(*pfrule));		\
		if (!pfrule)					\
			return 1;				\
	} while (0);

// Rule structure -1: Error. 0: Output help. 1: Add rule. 2: Delete rule. 3: List rules. 4: Flush rules.
int parse_args(int argc, char **argv, struct PF_rule *pfrule)
{
	int opt, arg_index;

	// Command-line options.
	struct option PF_options[] = {
		{ "index", required_argument, NULL, 'x' },
		{ "delete", required_argument, NULL, 'd' },
		{ "action", required_argument, NULL, 'c' },
		{ "direction", required_argument, NULL, 'e' },
		{ "proto", required_argument, NULL, 'r' },
		{ "srcip", required_argument, NULL, 'i' },
		{ "dstip", required_argument, NULL, 'I' },
		{ "srcport", required_argument, NULL, 'p' },
		{ "dstport", required_argument, NULL, 'P' },
		{ "list", no_argument, NULL, 'l' },
		{ "flush", no_argument, NULL, 'f' },
		{ "help", no_argument, NULL, 'h' },
		{ 0, 0, 0, 0 }
	};

	if (!argv || !pfrule || argc < 2)
		return -1;

	// Parse arguments
	opt = getopt_long(argc, argv, "lh", PF_options, &arg_index);
	while (opt != -1) 
	{
		int port, index;
		__u32 ip;

		switch (opt) 
		{

			// index
			case 'x':
				index = atoi(optarg);
				if (index < 0)
					return -1;
				pfrule->index = index;
				break;

			// direction 
			case 'e':
				if (!strcasecmp(optarg, DIRECTION_ALL_STR))
					pfrule->direction = DIRECTION_ALL;
				else if (!strcasecmp(optarg, DIRECTION_IN_STR))
					pfrule->direction = DIRECTION_IN;
				else if (!strcasecmp(optarg, DIRECTION_OUT_STR))
					pfrule->direction = DIRECTION_OUT;
				else
					return -1;
				break;

			// protocol
			case 'r':
				if (!strcasecmp(optarg, PROTO_ALL_STR))
					pfrule->proto = PROTO_ALL;
				else if (!strcasecmp(optarg, PROTO_TCP_STR))
					pfrule->proto = PROTO_TCP;
				else if (!strcasecmp(optarg, PROTO_UDP_STR))
					pfrule->proto = PROTO_UDP;
				else
					return -1;
				break;

			// source IP
			case 'i':
				if (inet_pton(AF_INET, optarg, &ip) <= 0)
					return -1;
				pfrule->srcip = ip;
				break;

			// destination IP
			case 'I':
				if (inet_pton(AF_INET, optarg, &ip) <= 0)
					return -1;
				pfrule->dstip = ip;
				break;

			// sourceport
			case 'p':
				port = atoi(optarg);
				if (port < 0 || port > PORT_MAX)
					return -1;
				pfrule->srcport = port;
				break;

			// destination port
			case 'P':
				port = atoi(optarg);
				if (port < 0 || port > PORT_MAX)
					return -1;
				pfrule->dstport = port;
				break;

			// action
			case 'c':
				if (!strcasecmp(optarg, ACT_DROP_STR))
					pfrule->action = ACT_DROP;
				else if (!strcasecmp(optarg, ACT_PASS_STR))
					pfrule->action = ACT_PASS;
				else if (!strcasecmp(optarg, ACT_LOG_STR))
					pfrule->action = ACT_LOG;
				else
					return -1;
				break;

			// delete
			case 'd':
				index = atoi(optarg);
				if (index < 0)
					return -1;
				pfrule->index = index;
				return 2;

			// list
			case 'l':
				return 3;

			// flush
			case 'f':
				return 4;

			// help
			case 'h':
				return 0;

			// error
			case '?':
			default:
				return -1;
		}
		opt = getopt_long(argc, argv, "lh", PF_options, &arg_index);
	}

	// Default: Add rule
	return 1;
}

// return error
int handle_cmd(int cmd, struct PF_rule *pfrule)
{
	FILE *sysfs_file;
	if (!pfrule)
		return -1;

	sysfs_file = fopen(SYSFS_PATH, "w");

	if (!sysfs_file) {
		fprintf(stderr, "Can't open %s\n.", SYSFS_PATH);
		return -1;
	}

	switch (cmd) 
	{
		case CMD_ADD:
		
			// CMD_ADD INDEX ACT DIR PROTO SRCIP DSTIP SRCPORT DSTPORT
			fprintf(sysfs_file, "%d %d %d %d %d %u %u %d %d", CMD_ADD,
				pfrule->index, pfrule->action, pfrule->direction,
				pfrule->proto, pfrule->srcip, pfrule->dstip,
				pfrule->srcport, pfrule->dstport);
			break;
		case CMD_DEL:
		
			// CMD_DEL INDEX
			fprintf(sysfs_file, "%d %d", CMD_DEL, pfrule->index);
			break;
		case CMD_FLUSH:
		
			// CMD_FLUSH 
			fprintf(sysfs_file, "%d", CMD_FLUSH);
			break;
		default:
			fprintf(stderr, "Ambiguos command value %d.\n", cmd);
			return -1;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	struct PF_rule *pfrule;
	PF_rule_new(pfrule);

	switch (parse_args(argc, argv, pfrule)) 
	{
	
		// Error
		case -1:
			out_error();
			break;
			
		// Output help
		case 0:
			out_help();
			break;
			
		// Add rule 
		case 1:
			return handle_cmd(CMD_ADD, pfrule);
			
		// Delete rule 
		case 2:
			return handle_cmd(CMD_DEL, pfrule);
			
		// List rules 
		case 3:
			out_list();
			break;
			
		// List rules 
		case 4:
			return handle_cmd(CMD_FLUSH, pfrule);
		default:
			fprintf(stderr, "Unknown parse_args() return value.\n");
			return -1;
	}

	return 0;
}

