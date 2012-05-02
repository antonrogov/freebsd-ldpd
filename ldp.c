#include "ldpd.h"


struct in_addr	routerID;
ldp_t			*ldp;
uint32_t		ldp_traceflags = 0;
uint8_t			trace_buffer[16834];
int				trace_buffer_len;


/*
==============
LDP_Disable
==============
*/
int LDP_Disable()
{
	ldp_global g;

	if(!ldp || !ldp->configured)
		return MPLS_FAILURE;

	if(ldp->up == MPLS_BOOL_TRUE) {
		g.admin_state = MPLS_ADMIN_DISABLE;
		return ldp_cfg_global_set(ldp->config, &g, LDP_GLOBAL_CFG_ADMIN_STATE);
	}

	return MPLS_SUCCESS;
}


/*
==============
LDP_Enable
==============
*/
int LDP_Enable()
{
	ldp_global g;

	if(!ldp || !ldp->configured)
		return MPLS_FAILURE;

	if(ldp->up == MPLS_BOOL_TRUE) {
		g.admin_state = MPLS_ADMIN_ENABLE;
		return ldp_cfg_global_set(ldp->config, &g, LDP_GLOBAL_CFG_ADMIN_STATE);
	}

	return MPLS_SUCCESS;
}


/*
==============
LDP_UpdateRouterID
==============
*/
void LDP_UpdateLSRID()
{
	ldp_global g;

	if(!ldp->isStaticLSRID)
		ldp->lsrID = routerID;

	g.lsr_identifier.type = MPLS_FAMILY_IPV4;
	g.lsr_identifier.u.ipv4 = ntohl(ldp->lsrID.s_addr);

	g.transport_address.type = MPLS_FAMILY_NONE;
	g.transport_address.u.ipv4 = 0;
	if(ldp->transAddr == LDP_TRANS_ADDR_LSRID) {
		g.transport_address.type = MPLS_FAMILY_IPV4;
		g.transport_address.u.ipv4 = ntohl(ldp->lsrID.s_addr);
	}

	ldp_cfg_global_set(ldp->config, &g, LDP_GLOBAL_CFG_LSR_IDENTIFIER | LDP_GLOBAL_CFG_TRANS_ADDR);
}


/*
==============
LDP_Init
==============
*/
int LDP_Init()
{
    ldp_global g;
    
	ldp = calloc(1, sizeof(struct ldp_s));

	ldp->config = ldp_cfg_open(ldp);
	ldp->up = MPLS_BOOL_TRUE;
	ldp->isStaticLSRID = MPLS_BOOL_FALSE;
	ldp->transAddr = LDP_DEF_TRANSPORT_ADDRESS_POLICY;
	ldp->egress = LDP_DEF_EGRESS_POLICY;
	ldp->address = LDP_DEF_ADDRESS_POLICY;
	ldp->implicitNull = MPLS_BOOL_TRUE;
	LIST_INIT(&ldp->peers);

	LDP_UpdateLSRID();

	g.admin_state = MPLS_ADMIN_DISABLE;
	ldp_cfg_global_set(ldp->config, &g, LDP_GLOBAL_CFG_LSR_HANDLE | LDP_GLOBAL_CFG_ADMIN_STATE);

	return 1;
}


/*
==============
LDP_Shutdown
==============
*/
void LDP_Shutdown()
{
	peer_t	*peer;

	LDP_Disable();

	ldp_cfg_close(ldp->config);

	while(!LIST_EMPTY(&ldp->peers)) {
		peer = LIST_FIRST(&ldp->peers);
		Peer_Destroy(peer);
	}

	free(ldp);
	ldp = NULL;
}
