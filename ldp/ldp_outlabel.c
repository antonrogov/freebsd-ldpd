
/*
 *  Copyright (C) James R. Leu 2000
 *  jleu@mindspring.com
 *
 *  This software is covered under the LGPL, for more
 *  info check out http://www.gnu.org/copyleft/lgpl.html
 */

#include <stdlib.h>
#include "ldp_struct.h"
#include "ldp_addr.h"
#include "ldp_if.h"
#include "ldp_attr.h"
#include "ldp_fec.h"
#include "ldp_nexthop.h"
#include "ldp_outlabel.h"
#include "ldp_inlabel.h"
#include "ldp_session.h"
#include "ldp_tunnel.h"
#include "ldp_global.h"

#include "mpls_mm_impl.h"
#include "mpls_trace_impl.h"

static uint32_t _ldp_outlabel_next_index = 1;

/*
 * even through we're trying to mimic what FECs/addrs/interfaces are doing
 * with respect to being added to the global list upon create and
 * automagically be removed from the global list upon delete, we have to
 * change thing up for outlabels.  We want the global add/delete to call
 * the porting layer to install the segments, but an outlabel needs more
 * info then just being allocated before the porting layer can add it.
 * so ldp_outlabel_create is not in charge of adding to the global list.
 * Instead the only entrance to creating a outlabel is
 * ldp_outlabel_create_complete which uses ldp_outlabel_create just to
 * allocate and initialize the memory, then after all of the necessary info
 * has been attached, it is added to the global list, which calls the
 * porting layer
 */

static ldp_outlabel *ldp_outlabel_create(ldp_global * g)
{
  ldp_outlabel *o = (ldp_outlabel *) mpls_malloc(sizeof(ldp_outlabel));

  if (o) {
    memset(o, 0, sizeof(ldp_outlabel));
    MPLS_REFCNT_INIT(o, 0);
    MPLS_LIST_INIT(&o->inlabel_root, ldp_inlabel);
    MPLS_LIST_INIT(&o->tunnel_root, ldp_tunnel);
    MPLS_LIST_INIT(&o->nh_root, ldp_nexthop);
    MPLS_LIST_ELEM_INIT(o, _global);
    MPLS_LIST_ELEM_INIT(o, _session);
    o->index = _ldp_outlabel_get_next_index();
    o->info.label.type = MPLS_LABEL_TYPE_NONE;
    o->switching = MPLS_BOOL_FALSE;
  }
  return o;
}

ldp_outlabel *ldp_outlabel_create_complete(ldp_global * g, ldp_session * s,
  ldp_attr * a, ldp_nexthop *nh)
{
  ldp_outlabel *out = ldp_outlabel_create(g);

  if (out != NULL) {
    ldp_outlabel_add_nexthop2(out, nh);
    ldp_session_add_outlabel(s, out);

    out->info.push_label = MPLS_BOOL_TRUE;
    out->info.owner = MPLS_OWNER_LDP;

    ldp_attr2mpls_label_struct(a, &out->info.label);
    ldp_attr_add_outlabel(a, out);

    /* _ldp_global_add_outlabel must be last so the porting layer has all the
     * info needed for installing the label */
    _ldp_global_add_outlabel(g, out);
  }
  return out;
}

void ldp_outlabel_delete(ldp_global * g, ldp_outlabel * o)
{
  LDP_PRINT(g->user_data,"outlabel delete");
  MPLS_REFCNT_ASSERT(o, 0);
  if (o->nh) {
    ldp_outlabel_del_nexthop2(g, o);
  }
  _ldp_global_del_outlabel(g, o);
  mpls_free(o);
}

#if 0
void ldp_outlabel_delete_complete(ldp_global * g, ldp_outlabel * out)
{
  ldp_attr_del_outlabel(g, out->attr);
  if (out->session) {
    ldp_session_del_outlabel(g, out->session, out);
  }
  _ldp_global_del_outlabel(g, out);
  ldp_outlabel_del_nexthop2(g, out);
}
#endif

void _ldp_outlabel_add_inlabel(ldp_outlabel * o, ldp_inlabel * i)
{
  MPLS_ASSERT(o && i);
  MPLS_REFCNT_HOLD(i);
  o->merge_count++;
  MPLS_LIST_ADD_HEAD(&o->inlabel_root, i, _outlabel, ldp_inlabel);
}

void _ldp_outlabel_del_inlabel(ldp_global * g,ldp_outlabel * o, ldp_inlabel * i)
{
  MPLS_ASSERT(o && i);
  MPLS_LIST_REMOVE(&o->inlabel_root, i, _outlabel);
  o->merge_count--;
  MPLS_REFCNT_RELEASE2(g, i, ldp_inlabel_delete);
}

void _ldp_outlabel_add_attr(ldp_outlabel * o, ldp_attr * a)
{
  MPLS_ASSERT(o && a);
  MPLS_REFCNT_HOLD(a);
  o->attr = a;
}

void _ldp_outlabel_del_attr(ldp_global *g, ldp_outlabel * o)
{
  MPLS_ASSERT(o && o->attr);
  MPLS_REFCNT_RELEASE2(g, o->attr, ldp_attr_delete);
  o->attr = NULL;
}

/*
 * We do not hold a ref to the nexthop.  The nexthop holds a ref to the
 * outlabel.  Nexthop creation calls ldp_outlabel_add_nexthop, nexthop
 * deletion calls ldp_outlabel_del_nexthop.  There is no way a nexthop can
 * be deleted without removing the outlabels ref to the nexthop.
 *
 * this is for the nexthops outlabel used 
 * for describing hierachy
 */
void ldp_outlabel_add_nexthop(ldp_outlabel * o, ldp_nexthop * nh)
{
  ldp_nexthop *np = NULL;

  MPLS_ASSERT(o && nh);

  ldp_nexthop_add_outlabel(nh,o);

  np = MPLS_LIST_HEAD(&o->nh_root);
  while (np != NULL) {
    if (np->index > nh->index) {
       MPLS_LIST_INSERT_BEFORE(&o->nh_root, np, nh, _outlabel);
       return;
    }
    np = MPLS_LIST_NEXT(&o->nh_root, np, _outlabel);
  }
  MPLS_LIST_ADD_TAIL(&o->nh_root, nh, _outlabel, ldp_nexthop);
}

/*
 * this is for the nexthops outlabel used 
 * for describing hierachy
 */
void ldp_outlabel_del_nexthop(ldp_global *g, ldp_outlabel * o, ldp_nexthop * nh)
{
  MPLS_ASSERT(o && nh);
  MPLS_LIST_REMOVE(&o->nh_root, nh, _outlabel);
  ldp_nexthop_del_outlabel(g, nh);
}

/* this is for the outlabels nexthops, not the nexthop's outlabel
 * used to describe hierarchy */
void ldp_outlabel_add_nexthop2(ldp_outlabel * o, ldp_nexthop * nh)
{
  MPLS_ASSERT(o && nh);
  MPLS_REFCNT_HOLD(nh);
  o->nh = nh;
  ldp_nexthop_add_outlabel2(nh, o);
}

/* this is for the outlabels nexthops, not the nexthop's outlabel
 * used to describe hierarchy */
void ldp_outlabel_del_nexthop2(ldp_global *g, ldp_outlabel * o)
{
  MPLS_ASSERT(o);
  ldp_nexthop_del_outlabel2(g, o->nh, o);
  MPLS_REFCNT_RELEASE2(g, o->nh, ldp_nexthop_delete);
  o->nh = NULL;
}

void _ldp_outlabel_add_session(ldp_outlabel * o, ldp_session * s)
{
  MPLS_ASSERT(o && s);
  MPLS_REFCNT_HOLD(s);
  o->session = s;
}

void _ldp_outlabel_del_session(ldp_outlabel * o)
{
  MPLS_ASSERT(o && o->session);
  MPLS_REFCNT_RELEASE(o->session, ldp_session_delete);
  o->session = NULL;
}

void _ldp_outlabel_add_tunnel(ldp_outlabel * o, ldp_tunnel * t)
{
  MPLS_ASSERT(o && t);
  MPLS_REFCNT_HOLD(t);
  o->merge_count++;
  MPLS_LIST_ADD_HEAD(&o->tunnel_root, t, _outlabel, ldp_tunnel);
}

void _ldp_outlabel_del_tunnel(ldp_outlabel * o, ldp_tunnel * t)
{
  MPLS_ASSERT(o && t);
  MPLS_LIST_REMOVE(&o->tunnel_root, t, _outlabel);
  o->merge_count--;
  MPLS_REFCNT_RELEASE(t, ldp_tunnel_delete);
}

uint32_t _ldp_outlabel_get_next_index()
{
  uint32_t retval = _ldp_outlabel_next_index;

  _ldp_outlabel_next_index++;
  if (retval > _ldp_outlabel_next_index) {
    _ldp_outlabel_next_index = 1;
  }
  return retval;
}
