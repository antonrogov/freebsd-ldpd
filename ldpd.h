#ifndef _LDPD_H_
#define _LDPD_H_

#include <sys/types.h>
#include <sys/param.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/tree.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_var.h>
#include <net/if_types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>

#include <event.h>

#include "mpls_handle_type.h"
#include "mpls_assert.h"
#include "mpls_refcnt.h"
#include "mpls_bitfield.h"
#include "mpls_mm_impl.h"
#include "mpls_list.h"
#include "mpls_struct.h"
#include "mpls_fib_impl.h"
#include "mpls_ifmgr_impl.h"
#include "mpls_lock_impl.h"
#include "mpls_mpls_impl.h"
#include "mpls_policy_impl.h"
#include "mpls_socket_impl.h"
#include "mpls_timer_impl.h"
#include "mpls_trace_impl.h"
#include "mpls_tree_impl.h"

#include "ldp_struct.h"
#include "ldp_cfg.h"


typedef struct prefix_s {
	unsigned char	length;
	struct in_addr	prefix;
} prefix_t;


/* filter FECs this LSR will send mappings for */
typedef enum {
	LDP_EGRESS_ALL,			/* all */
	LDP_EGRESS_LSRID,		/* LSR-ID only */
	LDP_EGRESS_CONNECTED	/* all connected subnets */
} egressMode_t;

/* addresses this LSR will announce */
typedef enum {
	LDP_ADDRESS_ALL,	/* all */
	LDP_ADDRESS_LSRID,	/* LSR-ID only */
	LDP_ADDRESS_LDP		/* only LDP interfaces */
} addressMode_t;

/* global transport address */
typedef enum {
	LDP_TRANS_ADDR_NONE = 0,			/* none */
	LDP_TRANS_ADDR_INTERFACE,			/* use the IP address on configured interfaces */
	LDP_TRANS_ADDR_LSRID,				/* use the LSR-ID */
	LDP_TRANS_ADDR_STATIC_IP,			/* specify an IP address */
	LDP_TRANS_ADDR_STATIC_INTERFACE,	/* name of interface from which to use the primary IP address */
} transAddrMode_t;


#define LDP_DEF_EGRESS_POLICY LDP_EGRESS_CONNECTED
#define LDP_DEF_ADDRESS_POLICY LDP_ADDRESS_ALL
#define LDP_DEF_TRANSPORT_ADDRESS_POLICY LDP_TRANS_ADDR_INTERFACE

/* interface address */
typedef struct address_s {
	prefix_t				address;
	struct in_addr			broadcast;
	TAILQ_ENTRY(address_s)	entry;
} address_t;

TAILQ_HEAD(addressList_s, address_s);
typedef struct addressList_s addressList_t;


/* interface object */
typedef struct interface_s {
	int							index;				/* system interface index */
	char						name[IFNAMSIZ + 1];	/* system interface name */
	int							mtu;				/* system interface mtu */
	int							systemUp;			/* is up */
	int							labelspace;			/* mpls label space */
	addressList_t				addresses;			/* configured addresses */
	int							vpnType;			/* vpn type */
	struct in_addr				vpnDest;			/* vpn destination */
	int							vpnLabel;			/* vpn tunnel label */
	int							configUp;			/* is up in config */
	ldp_entity					entity;				/* ldp-portable entity */
	ldp_if						interface;			/* ldp-portable interface */
	mpls_bool					up;					/* is administrative up */
	TAILQ_ENTRY(interface_s)	entry;				/* linked list */
} interface_t;

TAILQ_HEAD(interfaceList_s, interface_s);
typedef struct interfaceList_s interfaceList_t;


/* layer 2 over MPLS VPN endpoint */
typedef struct peer_s {
	ldp_entity			entity;		/* ldp-portable entity */
	ldp_peer			peer;		/* ldp-portable peer */
	mpls_bool			up;			/* is administrative up */
	LIST_ENTRY(peer_s)	entry;		/* linked list */
} peer_t;

LIST_HEAD(peerList_s, peer_s);
typedef struct peerList_s peerList_t;


/* ldp object */
typedef struct ldp_s {
	struct event	ev;
	peerList_t		peers;							/* list of L2VPN entities */
	mpls_cfg_handle	config;							/* ldp-portable config handle */
	mpls_bool		configured;						/* is configured (have config been read?) */
	mpls_bool		up;								/* is administrative up */
	mpls_bool		isStaticLSRID;					/* is using specified static LSR-ID */
	struct in_addr	lsrID;
	egressMode_t	egress;							/* FEC filter policy */
	addressMode_t	address;						/* address filter policy */
	transAddrMode_t	transAddr;						/* transport address type */
	char			transAddrIfName[IFNAMSIZ + 1];	/* transport interface name */
	mpls_bool		useLSRIDForGlobalTransAddr;		/* is using LSR-ID for transport address */
	mpls_bool		useIfAddrForLocalTransAddr;		/* is using interface address for transport address */
	mpls_bool		implicitNull;					/* use imp-null label (3) to enable penultimate hop popping */
} ldp_t;


extern struct in_addr	routerID;
extern ldp_t			*ldp;
extern interfaceList_t	interfaces;


/* config.c */
void Config_Load(char *path);
void Config_Reload();
void Config_Save();

/* ldp.c */
int LDP_Init();
void LDP_Shutdown();
int LDP_Enable();
int LDP_Disable();
void LDP_UpdateLSRID();

/* interface.c */
int Interfaces_Init();
void Interfaces_Shutdown();
void Interfaces_Enable();
interface_t *Interface_Create();
void Interface_Destroy(interface_t *iface);
void Interface_Init(interface_t *iface);
void Interface_Shutdown(interface_t *iface);
void Interface_Enable(interface_t *iface);
void Interface_Disable(interface_t *iface);
void Interface_AddAddress(interface_t *iface, address_t *addr);
void Interface_DelAddress(interface_t *iface, address_t *addr);
unsigned int Interface_GetAddress(interface_t *iface);
interface_t *Interface_FindByIndex(int index);
interface_t *Interface_FindByName(const char *name);
interface_t *Interface_FindByAddress(struct in_addr addr);

/* peer.c */
peer_t *Peer_Find(struct mpls_dest *dest);
peer_t *Peer_Create(struct mpls_dest *dest);
void Peer_Destroy(peer_t *peer);
void Peer_Enable(peer_t *peer);
void Peer_Disable(peer_t *peer);

/* kernel.c */
void Kernel_Init();
void Kernel_Shutdown();

/* mpls.c */
void MPLS_Disable();
void MPLS_EnableInterface(const char *name);
void MPLS_DisableInterface(const char *name);
int MPLS_Get(struct in_addr *prefix, int prefixLen);
void MPLS_AddIn(int label, struct in_addr *prefix, int prefixLen);
void MPLS_DelIn(int label);
void MPLS_AddOut(int label, struct in_addr *prefix, int prefixLen, const char *iface, struct in_addr *nextHop);
void MPLS_DelOut(int label, struct in_addr *prefix, int prefixLen, const char *iface, struct in_addr *nextHop);
void MPLS_AddCrossConnect(int local, int outgoing);
void MPLS_DelCrossConnect(int local, int outgoing);
void MPLS_AddVPN(int type, const char *iface, struct in_addr *dest, int label);
void MPLS_ShowLIB(int fd);
void MPLS_Init();
void MPLS_Shutdown();


#endif
