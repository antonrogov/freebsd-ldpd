#include "ldpd.h"


static void mpls_fec2zebra_prefix(mpls_fec *fec, prefix_t *prefix)
{
	switch(fec->type) {
	case MPLS_FEC_PREFIX:
		prefix->length = fec->u.prefix.length;
		prefix->prefix.s_addr = htonl(fec->u.prefix.network.u.ipv4);
		break;
	case MPLS_FEC_HOST:
		prefix->length = 32;
		prefix->prefix.s_addr = htonl(fec->u.host.u.ipv4);
		break;
	default:
		MPLS_ASSERT(0);
		break;
	}
}


static int prefix_same(const prefix_t *a, const prefix_t *b)
{
	if(a->length == b->length)
		return memcmp(&a->prefix, &b->prefix, 4) == 0;
	return 0;
}


mpls_bool mpls_policy_import_check(mpls_instance_handle handle, mpls_fec *fec, mpls_nexthop *nexthop)
{
	return MPLS_BOOL_TRUE;
}


mpls_bool mpls_policy_ingress_check(mpls_instance_handle handle, mpls_fec *fec, mpls_nexthop *nexthop)
{
	return MPLS_BOOL_TRUE;
}


mpls_bool mpls_policy_egress_check(mpls_instance_handle handle, mpls_fec *fec, mpls_nexthop *nexthop)
{
	mpls_bool result;
	prefix_t prefix;

	if(handle != ldp)
		return MPLS_BOOL_FALSE;

	result = MPLS_BOOL_FALSE;
	switch(ldp->egress) {
	case LDP_EGRESS_ALL:
		result = MPLS_BOOL_TRUE;
		break;
	case LDP_EGRESS_LSRID:
		mpls_fec2zebra_prefix(fec, &prefix);
		if(!memcmp(&routerID, &prefix.prefix, 4))
			result = MPLS_BOOL_TRUE;
		break;
	case LDP_EGRESS_CONNECTED:
		if(nexthop->attached == MPLS_BOOL_TRUE)
			result = MPLS_BOOL_TRUE;
		break;
	default:
		break;
	}

	return result;
}


mpls_bool mpls_policy_export_check(mpls_instance_handle handle, mpls_fec *fec, mpls_nexthop *nexthop)
{
	return MPLS_BOOL_TRUE;
}


mpls_bool mpls_policy_address_export_check(mpls_instance_handle handle, mpls_inet_addr *addr)
{
	struct in_addr in;
	mpls_bool flag;

	if(!addr || handle != ldp)
		return MPLS_BOOL_FALSE;

	in.s_addr = htonl(addr->u.ipv4);

	flag = MPLS_BOOL_FALSE; 
	switch(ldp->address) {
	case LDP_ADDRESS_LDP:
		if(Interface_FindByAddress(in))
			flag = MPLS_BOOL_TRUE;
		/* fall through */
	case LDP_ADDRESS_LSRID:
		if(in.s_addr == routerID.s_addr)
			flag = MPLS_BOOL_TRUE;
		break;
	case LDP_ADDRESS_ALL:
		flag = MPLS_BOOL_TRUE;
		break;
	}

	return flag;
}
