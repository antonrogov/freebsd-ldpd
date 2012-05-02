#include "ldpd.h"


void handleSignal(int sig, short event, void *arg)
{
	switch(sig) {
	case SIGTERM:
	case SIGINT:
		Control_Shutdown();
		Config_Save();
		Kernel_Shutdown();
		Interfaces_Shutdown();
		LDP_Shutdown();
		mpls_shutdown();
		exit(0);
		break;
	case SIGHUP:
		Config_Reload();
		break;
	default:
		fprintf(stderr, "unexpected signal");
		exit(1);
	}
}   


int main(int argc, char *argv[])
{
	struct event eventINT, eventTERM, eventHUP;
	int debug;
	char *config, c;

	debug = 0;
	config = NULL;
	while((c = getopt(argc, argv, "df:v")) != -1) {
		switch (c) {
		case 'd':
			debug = 1;
			break;
		case 'f':
			config = optarg;
			break;
		case 'v':
			if(ldp_traceflags & LDP_TRACE_FLAG_DEBUG)
				ldp_traceflags = LDP_TRACE_FLAG_ALL;
			else
				ldp_traceflags |= LDP_TRACE_FLAG_DEBUG;
			break;
		default:
			fprintf(stderr, "usage: %s [-dv] [-f file]\n", argv[0]);
			exit(1);
		}
	}

	if(geteuid()) {
		fprintf(stderr, "need root privileges");
		exit(1);
	}

	if(!debug) {
		ldp_traceflags = 0;
		daemon(1, 0);
	}

	event_init();

	signal_set(&eventINT, SIGINT, handleSignal, NULL);
	signal_set(&eventTERM, SIGTERM, handleSignal, NULL);
	signal_set(&eventHUP, SIGHUP, handleSignal, NULL);
	signal_add(&eventINT, NULL);
	signal_add(&eventTERM, NULL);
	signal_add(&eventHUP, NULL);

	mpls_init();
	LDP_Init();
	Interfaces_Init();
	Kernel_Init();
	Config_Load(config);
	Control_Init();

	event_dispatch();

	return 0;
}
