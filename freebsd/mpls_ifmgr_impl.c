#include "ldpd.h"


static int opened = 0;


mpls_ifmgr_handle mpls_ifmgr_open(mpls_instance_handle handle, mpls_cfg_handle cfg)
{
	opened = 1;
	return 0xdeadbeef;
}


void mpls_ifmgr_close(mpls_ifmgr_handle ifmgr_handle)
{
	opened = 0;
}


mpls_return_enum mpls_ifmgr_get_mtu(mpls_ifmgr_handle ifmgr_handle, mpls_if_handle iface, int *mtu)
{
	*mtu = iface->mtu;
	return MPLS_SUCCESS;
}


mpls_return_enum mpls_ifmgr_get_name(const mpls_ifmgr_handle handle, const mpls_if_handle iface, char *name, int len)
{
	strlcpy(name, iface->name, len);
	return MPLS_SUCCESS;
}


mpls_return_enum mpls_ifmgr_compare(const mpls_ifmgr_handle handle, const mpls_if_handle a, const mpls_if_handle b)
{
	if(a && b && a->index == b->index)
		return MPLS_SUCCESS;
	return MPLS_FAILURE;
}
