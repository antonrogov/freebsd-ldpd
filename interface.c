#include "ldpd.h"


typedef struct addressNode_s {
	struct in_addr			addr;
	struct addressNode_s	*prev;
	struct addressNode_s	*next;
} addressNode_t;

static addressNode_t *listHead, *listTail;

static int fd;
static struct event ev;
interfaceList_t interfaces;


/*
==============
AddAddress
	add given address to sorted list for track of router-id
==============
*/
static void AddAddress(struct in_addr addr)
{
	int update;
	addressNode_t *node, *n;

	update = 0;

	for(node = listHead; node && addr.s_addr < node->addr.s_addr; node = node->next);

	if(node && node->addr.s_addr == addr.s_addr)
		return;

	n = calloc(1, sizeof(addressNode_t));
	n->addr.s_addr = addr.s_addr;

	if(!node) {
		if(!listHead) {
			listHead = n;
			update = 1;
		} else
			n->prev = listTail;
		listTail = n;
	} else {
		if(node == listHead) {
			listHead = n;
			update = 1;
		}
		n->prev = node->prev;
		n->next = node;
		node->prev = n;
	}

	if(update && listHead) {
		routerID.s_addr = listHead->addr.s_addr;
		LDP_UpdateLSRID();
	}
}


/*
==============
DelAddress
	delete given address from sorted list for track of router-id
==============
*/
static void DelAddress(struct in_addr addr)
{
	int update;
	addressNode_t *node;

	update = 0;

	node = listHead;
	while(node && node->addr.s_addr != addr.s_addr)
		node = node->next;

	if(!node)
		return;

	if(node == listHead) {
		listHead = listHead->next;
		update = 1;
	}

	if(node == listTail)
		listTail = listTail->prev;

	if(node->prev)
		node->prev->next = node->next;
	if(node->next)
		node->next->prev = node->prev;
	free(node);

	if(update && listHead) {
		routerID.s_addr = listHead->addr.s_addr;
		LDP_UpdateLSRID();
	}
}


/*
==============
Interfaces_Init
==============
*/
int Interfaces_Init()
{
	TAILQ_INIT(&interfaces);

	return 1;
}


/*
==============
Interfaces_Shutdown
==============
*/
void Interfaces_Shutdown()
{
	interface_t *iface;

	while(!TAILQ_EMPTY(&interfaces)) {
		iface = TAILQ_FIRST(&interfaces);
		Interface_Destroy(iface);
	}	
}


/*
==============
Interfaces_Enable
==============
*/
void Interfaces_Enable()
{
	interface_t *iface;
	TAILQ_FOREACH(iface, &interfaces, entry)
		Interface_Init(iface);
}


/*
==============
Interface_Create
	Allocate and initialze a new interface instnace
==============
*/
interface_t *Interface_Create()
{
	interface_t *iface;

	MPLS_ASSERT(ldp);

	iface = calloc(1, sizeof(struct interface_s));
	if(!iface)
		return NULL;

	TAILQ_INIT(&iface->addresses);

	TAILQ_INSERT_TAIL(&interfaces, iface, entry);

	ldp_entity_set_defaults(&iface->entity);
	if(iface->labelspace < 0)
		iface->labelspace = 0;
	iface->interface.label_space = iface->labelspace;
	iface->interface.handle = iface;
	iface->up = MPLS_BOOL_FALSE;
	iface->vpnLabel = -1;

	ldp_cfg_if_set(ldp->config, &iface->interface, LDP_CFG_ADD | LDP_IF_CFG_LABEL_SPACE);
	ldp_cfg_if_get(ldp->config, &iface->interface, 0xFFFFFFFF);

	return iface;
}


/*
==============
Interface_Destroy
==============
*/
void Interface_Destroy(interface_t *iface)
{
	address_t *addr;

	MPLS_ASSERT(iface);
	MPLS_ASSERT(ldp);
	MPLS_ASSERT(iface->interface.index);

	Interface_Disable(iface);

	ldp_cfg_if_set(ldp->config, &iface->interface, LDP_CFG_DEL);
	iface->interface.index = 0;

	TAILQ_REMOVE(&interfaces, iface, entry);

	while(!TAILQ_EMPTY(&iface->addresses)) {
		addr = TAILQ_FIRST(&iface->addresses);
		TAILQ_REMOVE(&iface->addresses, addr, entry);
		free(addr);
	}

	free(iface);
}


void prefix2mpls_inet_addr(prefix_t *prefix, struct mpls_inet_addr *addr)
{
	addr->type = MPLS_FAMILY_IPV4;
	addr->u.ipv4 = (uint32_t)ntohl(prefix->prefix.s_addr);
}


/*
==============
Interface_UpdateTransportAddress
==============
*/
static void Interface_UpdateTransportAddress(interface_t *iface)
{
	ldp_global g;

	MPLS_ASSERT(ldp);
	MPLS_ASSERT(iface);

	if(ldp->transAddr == LDP_TRANS_ADDR_STATIC_INTERFACE && !strncmp(ldp->transAddrIfName, iface->name, IFNAMSIZ + 1)) {
		g.transport_address.u.ipv4 = ntohl(Interface_GetAddress(iface));
		g.transport_address.type = g.transport_address.u.ipv4 ? MPLS_FAMILY_IPV4 : MPLS_FAMILY_NONE;
		LDP_Disable();
		ldp_cfg_global_set(ldp->config, &g, LDP_GLOBAL_CFG_TRANS_ADDR);
		LDP_Enable();
	} else if(ldp->transAddr == LDP_TRANS_ADDR_INTERFACE) {
		iface->entity.transport_address.u.ipv4 = ntohl(Interface_GetAddress(iface));
		iface->entity.transport_address.type = iface->entity.transport_address.u.ipv4 ? MPLS_FAMILY_IPV4 : MPLS_FAMILY_NONE;
		if(iface->entity.index) {
			ldp_cfg_global_set(ldp->config, &g, LDP_GLOBAL_CFG_TRANS_ADDR);
			LDP_Disable();
			ldp_cfg_entity_set(ldp->config, &iface->entity, LDP_ENTITY_CFG_TRANS_ADDR);
			LDP_Enable();
		}
	}
}


/*
==============
Interface_AddAddress
==============
*/
void Interface_AddAddress(interface_t *iface, address_t *addr)
{
	ldp_global g;
	struct ldp_addr ldpAddr;
	address_t *address;

	MPLS_ASSERT(ldp);
	MPLS_ASSERT(iface);
	MPLS_ASSERT(addr);

	address = calloc(1, sizeof(struct address_s));
	if(!address)
		return;

	AddAddress(addr->address.prefix);

	memcpy(address, addr, sizeof(struct address_s));

	TAILQ_INSERT_TAIL(&iface->addresses, address, entry);

	/* Notify LDP module */
	if(addr->address.prefix.s_addr != htonl(INADDR_LOOPBACK)) {
		prefix2mpls_inet_addr(&addr->address, &ldpAddr.address);
		ldp_cfg_if_addr_set(ldp->config, &iface->interface, &ldpAddr, LDP_CFG_ADD);

		Interface_UpdateTransportAddress(iface);		
	}
}


/*
==============
Interface_DelAddress
==============
*/
void Interface_DelAddress(interface_t *iface, address_t *addr)
{
	ldp_global g;
	struct ldp_addr ldpAddr;
	address_t *address;

	MPLS_ASSERT(ldp);
	MPLS_ASSERT(iface);
	MPLS_ASSERT(addr);

	DelAddress(addr->address.prefix);

	TAILQ_FOREACH(address, &iface->addresses, entry)
		if(address->address.prefix.s_addr == addr->address.prefix.s_addr) {
			TAILQ_REMOVE(&iface->addresses, address, entry);
			free(address);
			break;
		}

	/* Notify LDP module */
	if(addr->address.prefix.s_addr != htonl(INADDR_LOOPBACK)) {
		prefix2mpls_inet_addr(&addr->address, &ldpAddr.address);
		ldp_cfg_if_addr_set(ldp->config, &iface->interface, &ldpAddr, LDP_CFG_DEL);
			    
		Interface_UpdateTransportAddress(iface);		
	}
}


/*
==============
Interface_Enable
	Administratively enable given interface
==============
*/
void Interface_Enable(interface_t *iface)
{
	MPLS_ASSERT(ldp);
	MPLS_ASSERT(iface);
	MPLS_ASSERT(iface->interface.index);
	MPLS_ASSERT(iface->entity.index);

	if(iface->configUp && iface->up == MPLS_BOOL_FALSE) {
		iface->up = MPLS_BOOL_TRUE;
		iface->entity.admin_state = MPLS_ADMIN_ENABLE;
		ldp_cfg_entity_set(ldp->config, &iface->entity, LDP_ENTITY_CFG_ADMIN_STATE);

		mpls_enable_interface(iface->name);
		if(iface->vpnLabel > 0) {
			mpls_add_vpn(iface->vpnType, iface->name, &iface->vpnDest.s_addr, iface->vpnLabel);
		}
	}
}


/*
==============
Interface_Disable
	Administratively disable given interface
==============
*/
void Interface_Disable(interface_t *iface)
{
	MPLS_ASSERT(iface);
	MPLS_ASSERT(ldp);
	MPLS_ASSERT(iface->interface.index);
	MPLS_ASSERT(iface->entity.index);

	if(iface->configUp && iface->up == MPLS_BOOL_TRUE) {
		iface->up = MPLS_BOOL_FALSE;
		iface->entity.admin_state = MPLS_ADMIN_DISABLE;
		ldp_cfg_entity_set(ldp->config, &iface->entity, LDP_ENTITY_CFG_ADMIN_STATE);
	}
}


/*
==============
Interface_FindByIndex
==============
*/
interface_t *Interface_FindByIndex(int index)
{
	interface_t *iface;

	TAILQ_FOREACH(iface, &interfaces, entry)
		if(index == iface->index)
			return iface;

	return NULL;
}


/*
==============
Interface_FindByName
==============
*/
interface_t *Interface_FindByName(const char *name)
{
	interface_t *iface;

	TAILQ_FOREACH(iface, &interfaces, entry)
		if(!strncmp(name, iface->name, sizeof(iface->name) - 1))
			return iface;

	return NULL;
}


/*
==============
Interface_FindByAddress
==============
*/
interface_t *Interface_FindByAddress(struct in_addr addr)
{
	address_t *address;
	interface_t *iface;

	TAILQ_FOREACH(iface, &interfaces, entry) {
		address = TAILQ_FIRST(&iface->addresses);
		if(address && addr.s_addr == address->address.prefix.s_addr)
			return iface;
	}

	return NULL;
}


/*
==============
Interface_GetAddress
	Get first interface address
==============
*/
in_addr_t Interface_GetAddress(interface_t *iface)
{
	address_t *addr;

	MPLS_ASSERT(iface);

	addr = TAILQ_FIRST(&iface->addresses);
	if(addr)
		return addr->address.prefix.s_addr;

	return 0;
}


/*
==============
Interface_Init
	Configure(put into processing) and enable given interface
==============
*/
void Interface_Init(interface_t *iface)
{
	MPLS_ASSERT(ldp);
	MPLS_ASSERT(iface);
	MPLS_ASSERT(iface->interface.index);
	
	iface->configUp = 1;
	iface->entity.sub_index = iface->interface.index;
	iface->entity.entity_type = LDP_DIRECT;
	iface->entity.admin_state = MPLS_ADMIN_DISABLE;
	if(ldp->transAddr == LDP_TRANS_ADDR_INTERFACE) {
		iface->entity.transport_address.type = MPLS_FAMILY_IPV4;
		iface->entity.transport_address.u.ipv4 = ntohl(Interface_GetAddress(iface));
	} else
		iface->entity.transport_address.type = MPLS_FAMILY_NONE;

	ldp_cfg_entity_set(ldp->config, &iface->entity, LDP_CFG_ADD | LDP_ENTITY_CFG_SUB_INDEX | LDP_ENTITY_CFG_ADMIN_STATE | LDP_ENTITY_CFG_TRANS_ADDR);
	ldp_cfg_entity_get(ldp->config, &iface->entity, 0xFFFFFFFF);

	Interface_Enable(iface);
}


/*
==============
Interface_Shutdown
	Delete from processing and disable given interface
==============
*/
void Interface_Shutdown(interface_t *iface)
{
	MPLS_ASSERT(iface);

	iface->configUp = 0;
	iface->entity.admin_state = MPLS_ADMIN_DISABLE;
	if(ldp) {
		Interface_Disable(iface);
		if(iface->entity.index)
			ldp_cfg_entity_set(ldp->config, &iface->entity, LDP_CFG_DEL);
	}
	iface->entity.index = 0;
}
