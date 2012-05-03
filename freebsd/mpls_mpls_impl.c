#include "ldpd.h"
#include "../ng_mpls/public.h"

static void PrintAddress(in_addr_t ina)
{
	uint32_t a;

	a = (uint32_t)ina;
	printf("%u.%u.%u.%u", a & 0xff, (a >> 8) & 0xff, (a >> 16) & 0xff, (a >> 24) & 0xff);
}


mpls_mpls_handle mpls_mpls_open(mpls_instance_handle user_data)
{
	return MPLS_SUCCESS;
}


void mpls_mpls_close(mpls_mpls_handle handle)
{
}


mpls_return_enum mpls_mpls_outsegment_add(mpls_mpls_handle handle, mpls_outsegment *outSegment)
{
	return MPLS_SUCCESS;
}


void mpls_mpls_outsegment_del(mpls_mpls_handle handle, mpls_outsegment *outSegment)
{
}


mpls_return_enum mpls_mpls_insegment_add(mpls_mpls_handle handle, mpls_insegment *in, mpls_fec *fec)
{
	int length;
	struct in_addr addr;

	addr.s_addr = htonl(fec->u.prefix.network.u.ipv4);
	length = fec->u.prefix.length;

	if(in->label.type == MPLS_LABEL_TYPE_NONE) {
		in->label.type = MPLS_LABEL_TYPE_GENERIC;
		if(ldp->implicitNull == MPLS_BOOL_TRUE && in->npop == -1) {
			/* Implicit NULL */
			in->label.u.gen = MPLS_IMPLICIT_NULL;
		} else {
			/* Allocate new */
			in->label.u.gen = mpls_alloc_label();
		}
	}

	mpls_add_local(in->label.u.gen, &addr, length);

	return MPLS_SUCCESS;
}


void mpls_mpls_insegment_del(mpls_mpls_handle handle, mpls_insegment *in)
{
	mpls_delete_local(in->label.u.gen);
}


mpls_return_enum mpls_mpls_xconnect_add(mpls_mpls_handle handle, mpls_insegment *in, mpls_outsegment *out)
{
	/* mpls_add_xc(in->label.u.gen, out->label.u.gen);*/

	return MPLS_SUCCESS;
}


void mpls_mpls_xconnect_del(mpls_mpls_handle handle, mpls_insegment *in, mpls_outsegment *out)
{
	/* mpls_delete_xc(in->label.u.gen, out->label.u.gen);*/
}


mpls_return_enum mpls_mpls_fec2out_add(mpls_mpls_handle handle, mpls_fec *fec, mpls_outsegment *out)
{
	struct in_addr prefix, nexthop;

	prefix.s_addr = ntohl(fec->u.prefix.network.u.ipv4);
	nexthop.s_addr =  htonl(out->nexthop.ip.u.ipv4);
	mpls_add_remote(out->label.u.gen, &prefix, fec->u.prefix.length, out->nexthop.if_handle->name, &nexthop);

	return MPLS_SUCCESS;
}


void mpls_mpls_fec2out_del(mpls_mpls_handle handle, mpls_fec *fec, mpls_outsegment *out)
{
	struct in_addr prefix, nexthop;

	prefix.s_addr = ntohl(fec->u.prefix.network.u.ipv4);
	nexthop.s_addr =  htonl(out->nexthop.ip.u.ipv4);
	mpls_remove_remote(out->label.u.gen, &prefix, fec->u.prefix.length, out->nexthop.if_handle->name, &nexthop);
}


mpls_return_enum mpls_mpls_get_label_space_range(mpls_mpls_handle handle, mpls_range *range)
{
  range->type = MPLS_LABEL_RANGE_GENERIC;
  range->min.u.gen = 16;
  range->max.u.gen = 0xFFFFF;

  return MPLS_SUCCESS;
}
