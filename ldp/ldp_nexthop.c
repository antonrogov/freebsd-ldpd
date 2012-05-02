
/*
 *  Copyright (C) James R. Leu 2003
 *  jleu@mindspring.com
 *
 *  This software is covered under the LGPL, for more
 *  info check out http://www.gnu.org/copyleft/lgpl.html
 */

#include "ldp_struct.h"
#include "ldp_fec.h"
#include "ldp_if.h"
#include "ldp_addr.h"
#include "ldp_session.h"
#include "ldp_outlabel.h"
#include "ldp_global.h"
#include "mpls_assert.h"
#include "mpls_compare.h"
#include "mpls_mm_impl.h"
#include "mpls_tree_impl.h"
#include "mpls_policy_impl.h"
#include "mpls_trace_impl.h"

#if MPLS_USE_LSR
#include "lsr_cfg.h"
#else
#include "mpls_mpls_impl.h"
#endif

static uint32_t _ldp_nexthop_next_index = 1;
static uint32_t _ldp_nexthop_get_next_index();

void mpls_nexthop2ldp_nexthop(mpls_nexthop *mnh, ldp_nexthop *lnh)
{
  memcpy(&lnh->info, mnh, sizeof(mpls_nexthop));
}

ldp_nexthop *ldp_nexthop_for_fec_session(ldp_fec *fec, ldp_session *s)
{
  ldp_nexthop *nh = MPLS_LIST_HEAD(&fec->nh_root);
  ldp_session *sp;

  LDP_ENTER(g->user_data, "ldp_nexthop_for_fec_session");

  while (nh) {
    sp = ldp_session_for_nexthop(nh);
    if (sp && (sp->index == s->index)) {
      LDP_EXIT(g->user_data, "ldp_nexthop_for_fec_session: %p", nh);
      return nh;
    }
    nh = MPLS_LIST_NEXT(&fec->nh_root, nh, _fec);
  }
  LDP_EXIT(g->user_data, "ldp_nexthop_for_fec_session: NULL");
  return NULL;
}

void ldp_nexthop_delete(ldp_global *g, ldp_nexthop *nh)
{
  LDP_PRINT(g->user_data, "nexthop delete: %p", nh);
  MPLS_REFCNT_ASSERT(nh, 0);

  if (nh->addr) {
    ldp_addr_del_nexthop(g, nh->addr, nh);
  }
  if (nh->iff) {
    ldp_if_del_nexthop(g, nh->iff, nh);
  }
  if (nh->outlabel) {
    ldp_outlabel_del_nexthop(g, nh->outlabel, nh);
  }

  _ldp_global_del_nexthop(g, nh);
  mpls_free(nh);
}

ldp_nexthop *ldp_nexthop_create(ldp_global *g, mpls_nexthop *n)
{
  ldp_nexthop *nh = (ldp_nexthop *) mpls_malloc(sizeof(ldp_nexthop));

  if (nh != NULL) {
    memset(nh, 0, sizeof(ldp_nexthop));
    MPLS_REFCNT_INIT(nh, 0);
    MPLS_LIST_INIT(&nh->outlabel_root, ldp_outlabel);
    MPLS_LIST_ELEM_INIT(nh, _global);
    MPLS_LIST_ELEM_INIT(nh, _fec);
    MPLS_LIST_ELEM_INIT(nh, _addr);
    MPLS_LIST_ELEM_INIT(nh, _if);
    MPLS_LIST_ELEM_INIT(nh, _outlabel);
    nh->index = _ldp_nexthop_get_next_index();
    mpls_nexthop2ldp_nexthop(n, nh);

    if (nh->info.type & MPLS_NH_IP) {
      ldp_addr *addr = NULL;
      if (!(addr = ldp_addr_find(g, &nh->info.ip))) {
        if (!(addr = ldp_addr_insert(g, &nh->info.ip))) {
          goto ldp_nexthop_create_error;
        }
      }
      ldp_addr_add_nexthop(addr, nh);
    }

    if (nh->info.type & MPLS_NH_IF) {
      ldp_if *iff = NULL;
      if ((iff = ldp_global_find_if_handle(g, nh->info.if_handle))) {
        ldp_if_add_nexthop(iff, nh);
      } else {
        goto ldp_nexthop_create_error;
      }
    }

    if (nh->info.type & MPLS_NH_OUTSEGMENT) {
      ldp_outlabel *out = NULL;
      MPLS_ASSERT((out = ldp_global_find_outlabel_handle(g,
        nh->info.outsegment_handle)));
      ldp_outlabel_add_nexthop(out, nh);
    }

    _ldp_global_add_nexthop(g, nh);
  }
  return nh;

ldp_nexthop_create_error:
  ldp_nexthop_delete(g, nh);
  return NULL;
}

void ldp_nexthop_add_if(ldp_nexthop * nh, ldp_if * i)
{
  MPLS_ASSERT(nh && i);
  MPLS_REFCNT_HOLD(i);
  nh->info.if_handle = i->handle;
  nh->iff = i;
}

void ldp_nexthop_del_if(ldp_global *g, ldp_nexthop * nh)
{
  MPLS_ASSERT(nh);
  MPLS_REFCNT_RELEASE2(g, nh->iff, ldp_if_delete);
  nh->iff = NULL;
}

void ldp_nexthop_add_addr(ldp_nexthop * nh, ldp_addr * a)
{
  MPLS_ASSERT(nh && a);
  MPLS_REFCNT_HOLD(a);
  nh->addr = a;
}

void ldp_nexthop_del_addr(ldp_global *g, ldp_nexthop * nh)
{
  MPLS_ASSERT(nh);
  MPLS_REFCNT_RELEASE2(g, nh->addr, ldp_addr_delete);
  nh->addr = NULL;
}

/* this is for a nexthops outlabel used to describe hierarchy */
void ldp_nexthop_add_outlabel(ldp_nexthop * nh, ldp_outlabel * o)
{
  MPLS_ASSERT(nh && o);
  MPLS_REFCNT_HOLD(o);
  nh->outlabel = o;
}

/* this is for a nexthops outlabel used to describe hierarchy */
void ldp_nexthop_del_outlabel(ldp_global * g,ldp_nexthop * nh)
{
  MPLS_ASSERT(nh);
  MPLS_REFCNT_RELEASE2(g, nh->outlabel, ldp_outlabel_delete);
  nh->outlabel = NULL;
}

/*
 * just like addrs with respect to NHs,  NHs do not need to hold a ref to
 * outlabels (upper).
 */

/* this is for the outlabels nexthops, not the nexthop's outlabel
 * used to describe hierarchy */
void ldp_nexthop_add_outlabel2(ldp_nexthop * n, ldp_outlabel * o)
{
  MPLS_ASSERT(n && o);
  MPLS_LIST_ADD_HEAD(&n->outlabel_root, o, _nexthop, ldp_outlabel);
  memcpy(&o->info.nexthop, &n->info, sizeof(mpls_nexthop));
}

/* this is for the outlabels nexthops, not the nexthop's outlabel
 * used to describe hierarchy */
void ldp_nexthop_del_outlabel2(ldp_global *g, ldp_nexthop * n, ldp_outlabel * o)
{
  MPLS_ASSERT(n && o);
  MPLS_LIST_REMOVE(&n->outlabel_root, o, _nexthop);
}

void ldp_nexthop_add_fec(ldp_nexthop *nh, ldp_fec *f)
{
  MPLS_ASSERT(nh && f);
  MPLS_REFCNT_HOLD(f);
  nh->fec = f;
}

void ldp_nexthop_del_fec(ldp_global *g, ldp_nexthop * nh)
{
  MPLS_ASSERT(nh);
  MPLS_REFCNT_RELEASE2(g, nh->fec, ldp_fec_delete);
  nh->fec = NULL;
}

static uint32_t _ldp_nexthop_get_next_index()
{
  uint32_t retval = _ldp_nexthop_next_index;

  _ldp_nexthop_next_index++;
  if (retval > _ldp_nexthop_next_index) {
    _ldp_nexthop_next_index = 1;
  }
  return retval;
}
