#include "ldpd.h"

#include <sys/param.h>
#include <sys/errno.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ctype.h>

#include <net/if.h>
#include <net/if_types.h>
#include <net/if_arp.h>
#include <net/if_var.h>
#include <net/ethernet.h>

#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>

#include <netgraph.h>

#include <stdio.h>
#include <stdarg.h>

#include "control.h"


static int32_t label = 100;

int32_t mpls_alloc_label()
{
	return label++;
}

static int mpls_connect()
{
}

/* mpls_netgraph_request */
static struct ng_mesg *mpls_netgraph_request(const char *name, int cookie, int command, const void *request, int size, int need_result)
{
	int token, s;
	struct ng_mesg *reply;

	if(size < 0) {
		return NULL;
	}

	s = mpls_connect();
	if(!s) {
		return NULL;
	}

	/* send request */
	token = NgSendMsg(s, name, cookie, command, request, size);
	if(token == -1) {
		printf("mpls_netgraph_request: Cannot send message %u (%s)\n", command, strerror(errno));
		close(s);
		return NULL;
	}

	if(!need_result) {
		close(s);
		return NULL;
	}

	/* read reply */
	reply = NULL;
	if(NgAllocRecvMsg(s, &reply, NULL) == -1 || !reply) {
		printf("mpls_netgraph_request: Cannot receive message\n");
		close(s);
		return NULL;
	}

	if(reply->header.token != token) {
		printf("mpls_netgraph_request: Token mismatch\n");
		free(reply);
		close(s);
		return NULL;
	}

	close(s);

	return reply;
}


/* mpls_request */
static struct ng_mesg *mpls_request(int command, const void *request, int size, int need_result)
{
}


/*
==============
MPLS_Disable
==============
*/
void mpls_disable()
{
  printf("MPLS DISABLE\n");
}


/* mpls_enable_interface */
void mpls_enable_interface(const char *name)
{
  printf("MPLS ENABLE %s\n", name);
}

/* mpls_disable_interface */
void mpls_disable_interface(const char *name)
{
  printf("MPLS DISABLE %s\n", name);
}


/* mpls_get_label_by_prefix */
int32_t mpls_get_label_by_prefix(struct in_addr *prefix_in, int length)
{
  printf("MPLS GET LABEL %s/%i\n", inet_ntoa(prefix_in->s_addr), length);
  return 0;
}


/* mpls_add_local: adds an ILM entry */
void mpls_add_local(int32_t label, struct in_addr *prefix, int length)
{
  printf("MPLS ADD LOCAL %i %s/%i\n", label, inet_ntoa(prefix->s_addr), length);
}


/* mpls_delete_local: removes an ILM entry by label */
void mpls_delete_local(int32_t label)
{
  printf("MPLS DEL LOCAL %i\n", label);
}


/* mpls_add_remote: adds a NHLFE entry */
void mpls_add_remote(int32_t label, struct in_addr *prefix, int length, const char *ifname, struct in_addr *nexthop)
{
  printf("MPLS ADD REMOTE %i %s/%i %s %s\n", label, inet_ntoa(prefix->s_addr), length, ifname, inet_ntoa(nexthop));
}


/* mpls_remove_remote: removes a NHLFE entry */
void mpls_remove_remote(int32_t label, struct in_addr *prefix, int length, const char *ifname, struct in_addr *nexthop)
{
  printf("MPLS DEL REMOTE %i %s/%i %s %s\n", label, inet_ntoa(prefix->s_addr), length, ifname, inet_ntoa(nexthop));
}


/* mpls_add_xc: connects ILM and NHLFE entries */
void mpls_add_xc(int32_t local, int32_t remote)
{
  printf("MPLS ADD XC %i %i\n", local, remote);
}


/* mpls_delete_xc: removes a connection between ILM and FTN entries */
void mpls_delete_xc(int local, int remote)
{
  printf("MPLS DEL XC %i %i\n", local, remote);
}


/* mpls_add_vpn: adds a VPN entry */
void mpls_add_vpn(int type, const char *ifname, struct in_addr *destination, int32_t label)
{
  printf("MPLS ADD VPN %i %i %s %s\n", label, type, ifname, inet_ntoa(destination->s_addr));
}


/*
==============
MPLS_ShowLIB
==============
*/
void MPLS_ShowLIB(int fd)
{
}


/* mpls_init */
void mpls_init()
{
}


/* mpls_shutdown */
void mpls_shutdown()
{
	mpls_disable();
}
