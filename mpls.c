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
#include "../ng_mpls/public.h"


static int32_t label = 100;

int32_t mpls_alloc_label()
{
	return label++;
}

static int mpls_connect()
{
	int s;

	if(NgMkSockNode("mplsctl", &s, NULL) == -1) {
		printf("mpls_connect: Cannot create control socket (may be already exists)\n");
		return -1;
	}

	return s;
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
	return mpls_netgraph_request("mpls:", NGM_MPLS_COOKIE, command, request, size, need_result);
}


/*
==============
MPLS_Disable
==============
*/
void mpls_disable()
{
	int s;

	s = mpls_connect();
	if(!s) { 
		return;
	}

	NgSendMsg(s, "mpls:", NGM_GENERIC_COOKIE, NGM_SHUTDOWN, NULL, 0);
	close(s);
}


/* mpls_enable_interface */
void mpls_enable_interface(const char *name)
{
	int s;
	char path[IFNAMSIZ + NG_HOOKSIZ + 2];
	struct ngm_mkpeer make_peer;
	struct ngm_name set_name;
	struct ngm_connect node_connect;

	memset(path, 0, sizeof(path));
	strcpy(path, name);
	strcat(path, ":");

	s = mpls_connect();
	if(!s) {
		return;
	}

	if(NgSendMsg(s, "mpls:", NGM_GENERIC_COOKIE, NGM_NODEINFO, NULL, 0) == -1) {
		if(errno != 2) {
			printf("mpls_enable_interface: MPLS node not found (%s)\n", strerror(errno));
			close(s);
			return;
		}

		/* mkpeer {ifname}: mpls lower lower_{ifname} */
		strcpy(make_peer.type, "mpls");
		strcpy(make_peer.ourhook, "lower");
		strcpy(make_peer.peerhook, NG_MPLS_HOOK_LOWER);
		strcat(make_peer.peerhook, name);
		mpls_netgraph_request(path, NGM_GENERIC_COOKIE, NGM_MKPEER, &make_peer, sizeof(make_peer), 0);

		/* name {ifname}.lower mpls */
		strcat(path, "lower");
		strcpy(set_name.name, "mpls");
		mpls_netgraph_request(path, NGM_GENERIC_COOKIE, NGM_NAME, &set_name, sizeof(set_name), 0);
	} else {
		/* connect {ifname}: mpls: lower lower_{ifname} */
		strcpy(node_connect.path, "mpls:");
		strcpy(node_connect.ourhook, "lower");
		strcpy(node_connect.peerhook, NG_MPLS_HOOK_LOWER);
		strcat(node_connect.peerhook, name);
		mpls_netgraph_request(path, NGM_GENERIC_COOKIE, NGM_CONNECT, &node_connect, sizeof(node_connect), 0);
	}

	/* connect {ifname}: mpls: upper upper_{ifname} */
	strcpy(path, name);
	strcat(path, ":");
	strcpy(node_connect.path, "mpls:");
	strcpy(node_connect.ourhook, "upper");
	strcpy(node_connect.peerhook, NG_MPLS_HOOK_UPPER);
	strcat(node_connect.peerhook, name);
	mpls_netgraph_request(path, NGM_GENERIC_COOKIE, NGM_CONNECT, &node_connect, sizeof(node_connect), 0);

	close(s);
}


/* mpls_disable_interface */
void mpls_disable_interface(const char *name)
{
	
}


/* mpls_get_label_by_prefix */
int32_t mpls_get_label_by_prefix(struct in_addr *prefix_in, int length)
{
	int label;
	struct ng_mesg *reply;
	struct ng_mpls_prefix prefix;

	if(!prefix_in) {
		return -1;
	}

	prefix.prefix.s_addr = prefix_in->s_addr;
	prefix.length = length;
	reply = mpls_request(NGM_MPLS_GET, &prefix, sizeof(prefix), 1);
	if(!reply) {
		return -1;
	}
	label = *((int32_t *)reply->data);
	free(reply);

	return label;
}


/* mpls_add_local: adds an ILM entry */
void mpls_add_local(int32_t label, struct in_addr *prefix, int length)
{
	struct ng_mpls_lib_entry entry;

	if(label < 16) {
		return;
	}

	memset(&entry, 0, sizeof(entry));
	entry.type = LIB_IN;
	entry.local = label;
	entry.remote = -1;
	entry.prefix.prefix.s_addr = prefix->s_addr;
	entry.prefix.length = length;

	mpls_request(NGM_MPLS_ADD, &entry, sizeof(entry), 0);
}


/* mpls_delete_local: removes an ILM entry by label */
void mpls_delete_local(int32_t label)
{
	struct ng_mpls_lib_entry entry;

	memset(&entry, 0, sizeof(entry));
	entry.type = LIB_NORMAL;
	entry.local = label;

	mpls_request(NGM_MPLS_DELETE_LOCAL, &entry, sizeof(entry), 0);
}


/* mpls_add_remote: adds a NHLFE entry */
void mpls_add_remote(int32_t label, struct in_addr *prefix, int length, const char *ifname, struct in_addr *nexthop)
{
	struct ng_mpls_lib_entry entry;

	if(!prefix || !ifname || !nexthop) {
		return;
	}

	/* or it would better to place this in ng_mpls */
	if(label == 3) {
		label = -1;
	}

	memset(&entry, 0, sizeof(entry));
	entry.type = LIB_NORMAL;
	entry.local = -1;
	entry.remote = label;
	entry.prefix.prefix.s_addr = prefix->s_addr;
	entry.prefix.length = length;
	strcpy(entry.if_name, ifname);
	entry.nexthop.s_addr = nexthop->s_addr;

	mpls_request(NGM_MPLS_ADD, &entry, sizeof(entry), 0);
}


/* mpls_remove_remote: removes a NHLFE entry */
void mpls_remove_remote(int32_t label, struct in_addr *prefix, int length, const char *ifname, struct in_addr *nexthop)
{
	struct ng_mpls_lib_entry entry;

	if(!prefix || !ifname || !nexthop) {
		return;
	}

	memset(&entry, 0, sizeof(entry));
	entry.type = LIB_NORMAL;
	entry.local = -1;
	entry.remote = label;
	entry.prefix.prefix.s_addr = prefix->s_addr;
	entry.prefix.length = length;
	strcpy(entry.if_name, ifname);
	entry.nexthop.s_addr = nexthop->s_addr;

	mpls_request(NGM_MPLS_DELETE_REMOTE, &entry, sizeof(entry), 0);
}


/* mpls_add_xc: connects ILM and NHLFE entries */
void mpls_add_xc(int32_t local, int32_t remote)
{
	struct ng_mpls_lib_entry entry;

	if(local < 16) {
		return;
	}

	/* or it would better to place this in ng_mpls */
	if(remote == 3) {
		remote = -1;
	}

	memset(&entry, 0, sizeof(entry));
	entry.type = LIB_NORMAL;
	entry.local = local;
	entry.remote = remote;

	mpls_request(NGM_MPLS_ADD_XC, &entry, sizeof(entry), 0);
}


/* mpls_delete_xc: removes a connection between ILM and FTN entries */
void mpls_delete_xc(int local, int remote)
{
	struct ng_mpls_lib_entry entry;

	memset(&entry, 0, sizeof(entry));
	entry.type = LIB_NORMAL;
	entry.local = local;
	entry.remote = remote;

	mpls_request(NGM_MPLS_DELETE_XC, &entry, sizeof(entry), 0);
}


/* mpls_add_vpn: adds a VPN entry */
void mpls_add_vpn(int type, const char *ifname, struct in_addr *destination, int32_t label)
{
	struct ng_mpls_lib_entry entry;

	if(!destination || !ifname) {
		return;
	}

	memset(&entry, 0, sizeof(entry));
	entry.type = (type == 2) ? LIB_L2VPN : LIB_L3VPN;
	entry.local = label;
	entry.remote = -1;
	strcpy(entry.if_name, ifname);
	entry.nexthop.s_addr = destination->s_addr;

	mpls_request(NGM_MPLS_ADD, &entry, sizeof(entry), 0);
}


/*
==============
MPLS_ShowLIB
==============
*/
void MPLS_ShowLIB(int fd)
{
	uint32_t i, size;
	struct ng_mesg *reply;
	struct ng_mpls_lib *lib;
	struct ng_mpls_lib_entry *info;
	msgLIBEntry_t entry;

	reply = mpls_request(NGM_MPLS_SHOW, NULL, 0, 1);
	if(!reply) {
		size = 0;
		write(fd, &size, sizeof(size));
		return;
	}

	lib = (struct ng_mpls_lib *)reply->data;
	size = lib->size;
	write(fd, &size, sizeof(size));

	info = &lib->entries[0];
	for(i = 0; i < size; i++) {
		entry.type = info->type;
		entry.local = info->local;
		entry.outgoing = info->remote;
		entry.prefix = info->prefix.prefix.s_addr;
		entry.length = info->prefix.length;
		strlcpy(entry.iface, info->if_name, sizeof(entry.iface));
		entry.nexthop = info->nexthop.s_addr;
		info++;
		write(fd, &entry, sizeof(entry));
	}

	free(reply);
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
