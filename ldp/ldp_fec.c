
/*
 *  Copyright (C) James R. Leu 2000
 *  jleu@mindspring.com
 *
 *  This software is covered under the LGPL, for more
 *  info check out http://www.gnu.org/copyleft/lgpl.html
 */

#include "ldp_struct.h"
#include "ldp_fec.h"
#include "ldp_if.h"
#include "ldp_attr.h"
#include "ldp_addr.h"
#include "ldp_nexthop.h"
#include "ldp_session.h"
#include "ldp_inlabel.h"
#include "ldp_outlabel.h"
#include "ldp_global.h"
#include "ldp_label_mapping.h"
#include "ldp_label_request.h"
#include "ldp_label_abort.h"
#include "ldp_label_rel_with.h"
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

static uint32_t _ldp_fec_next_index = 1;

static mpls_return_enum ldp_fec_insert(ldp_global *g, ldp_fec * fec)
{
  mpls_return_enum retval = MPLS_SUCCESS;
  uint32_t key;
  uint8_t len;

  MPLS_ASSERT(g && fec);
  LDP_ENTER(g->user_data, "ldp_fec_insert");

  switch(fec->info.type) {
    case MPLS_FEC_PREFIX:
      key = fec->info.u.prefix.network.u.ipv4;
      len = fec->info.u.prefix.length;
      break;
    case MPLS_FEC_HOST:
      key = fec->info.u.host.u.ipv4;
      len = 32;
      break;
    case MPLS_FEC_L2CC:
      /* they had better insert it into the global list */
      LDP_EXIT(g->user_data, "ldp_fec_insert: l2cc");
      return MPLS_SUCCESS;
    default:
      MPLS_ASSERT(0);
  }

  LDP_PRINT(g->user_data, "ldp_fec_insert: 0x%08x/%d\n", key, len);

  if (mpls_tree_insert(g->fec_tree, key, len, (void *)fec) != MPLS_SUCCESS) {
    LDP_PRINT(g->user_data, "ldp_fec_insert: error adding fec\n");
    retval = MPLS_FATAL;
  }

  LDP_EXIT(g->user_data, "ldp_fec_insert");
  return retval;
}

static void ldp_fec_remove(ldp_global *g, mpls_fec *fec)
{
  ldp_fec *f = NULL;
  uint32_t key;
  uint8_t len;

  MPLS_ASSERT(g && fec);
  LDP_ENTER(g->user_data, "ldp_fec_remove");

  switch(fec->type) {
    case MPLS_FEC_PREFIX:
      key = fec->u.prefix.network.u.ipv4;
      len = fec->u.prefix.length;
      break;
    case MPLS_FEC_HOST:
      key = fec->u.host.u.ipv4;
      len = 32;
      break;
    case MPLS_FEC_L2CC:
      /* they had better remove it from the global list */
      LDP_EXIT(g->user_data, "ldp_fec_remove");
      return;
    default:
      MPLS_ASSERT(0);
  }

  LDP_PRINT(g->user_data, "ldp_fec_remove: 0x%08x/%d\n", key, len);
  mpls_tree_remove(g->fec_tree, key, len, (void **)&f);

  MPLS_ASSERT(f);

  LDP_EXIT(g->user_data, "ldp_fec_remove");
}

static uint32_t _ldp_fec_get_next_index()
{
  uint32_t retval = _ldp_fec_next_index;

  _ldp_fec_next_index++;
  if (retval > _ldp_fec_next_index) {
    _ldp_fec_next_index = 1;
  }
  return retval;
}

ldp_fec *ldp_fec_create(ldp_global *g, mpls_fec *f)
{
  ldp_fec *fec = (ldp_fec *) mpls_malloc(sizeof(ldp_fec));

  if (fec != NULL) {
    memset(fec, 0, sizeof(ldp_fec));
    /*
     * note: this is init to 1 for a reason!
     * We're placing it in the global list, so this is our refcnt
     * when this refcnt gets to zero, it will be removed from the
     * global list and deleted
     */
    /*
     * TESTING: jleu 6/7/2004, since I want the FEC to be cleaned up
     * when it no longer has a nexthop, addr, or label, the only things that
     * should increment the ref are those (nh, addr, label etc), not global
     * nor inserting into the tree.  I also added this comment in
     * _ldp_global_add_fec()
    MPLS_REFCNT_INIT(fec, 1);
     */
    MPLS_REFCNT_INIT(fec, 0);
    MPLS_LIST_ELEM_INIT(fec, _global);
    MPLS_LIST_ELEM_INIT(fec, _inlabel);
    MPLS_LIST_ELEM_INIT(fec, _outlabel);
    MPLS_LIST_ELEM_INIT(fec, _fec);
    MPLS_LIST_INIT(&fec->nh_root, ldp_nexthop);
    MPLS_LIST_INIT(&fec->fs_root_us, ldp_fs);
    MPLS_LIST_INIT(&fec->fs_root_ds, ldp_fs);
    fec->index = _ldp_fec_get_next_index();
    fec->is_route = MPLS_BOOL_FALSE;
    mpls_fec2ldp_fec(f,fec);

    _ldp_global_add_fec(g, fec);
    ldp_fec_insert(g, fec);
  }
  return fec;
}

void ldp_fec_delete(ldp_global *g, ldp_fec * fec)
{
  LDP_PRINT(g->user_data, "fec delete: %08x/%d",
    fec->info.u.prefix.network.u.ipv4, fec->info.u.prefix.length);
  ldp_fec_remove(g, &fec->info);
  _ldp_global_del_fec(g, fec);
  mpls_free(fec);
}

ldp_fec *ldp_fec_find(ldp_global *g, mpls_fec *fec)
{
  ldp_fec *f = NULL;
  uint32_t key;
  uint8_t len;

  switch(fec->type) {
    case MPLS_FEC_PREFIX:
      key = fec->u.prefix.network.u.ipv4;
      len = fec->u.prefix.length;
      break;
    case MPLS_FEC_HOST:
      key = fec->u.host.u.ipv4;
      len = 32;
      break;
    case MPLS_FEC_L2CC:
      if (ldp_global_find_fec(g, fec, &f) == MPLS_SUCCESS) {
	return f;
      }
      return NULL;
    default:
      MPLS_ASSERT(0);
  }

  LDP_PRINT(g->user_data, "ldp_fec_find: 0x%08x/%d\n", key, len);
  if (mpls_tree_get(g->fec_tree, key, len, (void **)&f) != MPLS_SUCCESS) {
    return NULL;
  }
  return f;
}

ldp_fec *ldp_fec_find2(ldp_global *g, mpls_fec *fec)
{
  ldp_fec *f = NULL;
  f = ldp_fec_find(g, fec);
  if (!f) {
    f = ldp_fec_create(g, fec);
  }
  return f;
}

ldp_nexthop *ldp_fec_nexthop_find(ldp_fec *f, mpls_nexthop *n)
{
  ldp_nexthop *nh = NULL;

  MPLS_ASSERT(f && n);

  nh = MPLS_LIST_HEAD(&f->nh_root);
  while (nh) {
    if (!mpls_nexthop_compare(&nh->info, n)) {
      return nh;
    }
    nh = MPLS_LIST_NEXT(&f->nh_root, nh, _fec);
  }

  return NULL;
}

mpls_return_enum ldp_fec_find_nexthop_index(ldp_fec *f, int index,
  ldp_nexthop **n)
{
  ldp_nexthop *nh = NULL;

  MPLS_ASSERT(f);

  if (index > 0) {

    /* because we sort our inserts by index, this lets us know
       if we've "walked" past the end of the list */

    nh = MPLS_LIST_TAIL(&f->nh_root);
    if (!nh || nh->index < index) {
      *n = NULL;
      return MPLS_END_OF_LIST;
    }

    nh = MPLS_LIST_HEAD(&f->nh_root);
    do {
      if (nh->index == index) {
        *n = nh;
        return MPLS_SUCCESS;
      }
    } while((nh = MPLS_LIST_NEXT(&f->nh_root, nh, _fec)));
  }
  *n = NULL;
  return MPLS_FAILURE;
}

mpls_return_enum ldp_fec_add_nexthop(ldp_global *g, ldp_fec * f,
  ldp_nexthop * nh)
{
  MPLS_ASSERT(f && nh);

  LDP_ENTER(g->user_data, "ldp_fec_add_nexthop");

  MPLS_REFCNT_HOLD(nh);
  MPLS_LIST_ADD_HEAD(&f->nh_root, nh, _fec, ldp_nexthop);

  ldp_nexthop_add_fec(nh, f);

  LDP_EXIT(g->user_data, "ldp_fec_add_nexthop: success");
  return MPLS_SUCCESS;

ldp_fec_add_nexthop_error:

  ldp_fec_del_nexthop(g, f, nh);
  LDP_EXIT(g->user_data, "ldp_fec_add_nexthop: fail");
  return MPLS_FATAL;
}

void ldp_fec_del_nexthop(ldp_global *g, ldp_fec * f, ldp_nexthop *nh)
{
  MPLS_ASSERT(f && nh);

  MPLS_LIST_REMOVE(&f->nh_root, nh, _fec);
  ldp_nexthop_del_fec(g, nh);
  MPLS_REFCNT_RELEASE2(g, nh, ldp_nexthop_delete);
}

mpls_return_enum ldp_fec_process_add(ldp_global * g, ldp_fec * f,
  ldp_nexthop *nh, ldp_session *nh_session)
{
  ldp_session *peer = NULL;
  ldp_attr *ds_attr = NULL;
  ldp_attr *us_attr = NULL;
  mpls_bool egress;
  ldp_outlabel *out;

  LDP_ENTER(g->user_data, "ldp_fec_process_add");

  /*
   * find the info about the next hop for this FEC
   */
  if (!nh_session) {
    nh_session = ldp_get_next_hop_session_for_fec2(f, nh);
  }

  if (nh_session) {
    /* check if we've received and retainted a label from nh_session for f */
    ds_attr = ldp_attr_find_downstream_state2(g, nh_session, f,
      LDP_LSP_STATE_MAP_RECV);
    if (ds_attr && !ds_attr->outlabel) {
      /* if so, and we have not installed that label, install it now */
      out = ldp_outlabel_create_complete(g, nh_session, ds_attr, nh);
      if (!out) {
        return MPLS_FAILURE;
      }
      ds_attr->outlabel = out;
    }
  }

  /* are we willing to egress for this FEC */
  egress = mpls_policy_egress_check(g->user_data, &f->info, &nh->info);

  /*
   * for every peer except the nh hop peer, check to see if we need to
   * send a mapping
   */
  peer = MPLS_LIST_HEAD(&g->session);
  while (peer != NULL) {        /* FEC.1 */
    if ((peer->state != LDP_STATE_OPERATIONAL) ||
      (nh_session && peer->index == nh_session->index)) {
      goto next_peer;
    }
    /* have I already sent a mapping for FEC to peer */
    if ((us_attr = ldp_attr_find_upstream_state2(g, peer, f,
      LDP_LSP_STATE_MAP_SENT))) {
      /* yep, don't send another */
      if (ds_attr) {
	/* we need to XC the label we sent with the one we already have */
        if (ldp_inlabel_add_outlabel(g, us_attr->inlabel,
          ds_attr->outlabel) != MPLS_SUCCESS) {
	  return MPLS_FAILURE;
	}
      }
      goto next_peer;
    }

    /* we need to send a label */
    if (peer->oper_distribution_mode == LDP_DISTRIBUTION_UNSOLICITED) {
      if (g->lsp_control_mode == LDP_CONTROL_INDEPENDENT) {
	/* if we have received a pending request, give that as input to
	 * ldp_label_mapping_with_xc */
        us_attr =
          ldp_attr_find_upstream_state2(g, peer, f, LDP_LSP_STATE_REQ_RECV);

        /* FEC.1.DUI3,4 */
        if (ldp_label_mapping_with_xc(g, peer, f, &us_attr, ds_attr) !=
          MPLS_SUCCESS) {
          if (us_attr->in_tree) {
            ldp_attr_remove_complete(g, us_attr, MPLS_BOOL_FALSE);
          }
          goto next_peer;
        }
      } else {
        /*
         *LDP_CONTROL_ORDERED
         */

        if (ds_attr || (egress == MPLS_BOOL_TRUE)) { /* FEC.1.DUO2 */
          /* FEC.1.DUO3-4 */

	  /*
	   * ldp_label_mapping_with_xc will create a us_attr if
	   * one does not exist yet
	   */
          if (ldp_label_mapping_with_xc(g, peer, f, &us_attr, ds_attr) !=
            MPLS_SUCCESS) {
            return MPLS_FAILURE;
          }
        }
      }
    }
  next_peer:
    peer = MPLS_LIST_NEXT(&g->session, peer, _global);
  }

  if (ds_attr) {                /* FEC.2 */
    /* does this send an updated mapping? */
    if (ldp_label_mapping_process(g, nh_session, NULL, NULL, ds_attr, f) ==
      MPLS_FAILURE) { /* FEC.5 */
      return MPLS_FAILURE;
    }
    return MPLS_SUCCESS;
  }

  /*
   * LDP_DISTRIBUTION_ONDEMAND
   */
  /* FEC.3 */
  if (nh_session &&
      nh_session->oper_distribution_mode == LDP_DISTRIBUTION_ONDEMAND) {
    /* assume we're always "request when needed" */
    ds_attr = NULL;
    if (ldp_label_request_for_xc(g, nh_session, &f->info, NULL, &ds_attr) ==
      MPLS_FAILURE) { /* FEC.4 */
      return MPLS_FAILURE;
    }
  }

  LDP_EXIT(g->user_data, "ldp_fec_process_add");

  return MPLS_SUCCESS;           /* FEC.6 */
}

mpls_return_enum ldp_fec_process_change(ldp_global * g, ldp_fec * f,
  ldp_nexthop *nh, ldp_nexthop *nh_old, ldp_session *nh_session_old) {
  ldp_session *peer = NULL;
  ldp_attr *us_attr = NULL;
  ldp_attr *ds_attr = NULL;
  ldp_session *nh_session = NULL;

  LDP_ENTER(g->user_data,
    "ldp_fec_process_change: fec %p nh %p nh_old %p nh_session_old %p",
    f, nh, nh_old, nh_session_old);

  if (!nh_session_old) {
    nh_session_old = ldp_session_for_nexthop(nh_old);
  }

  /*
   * NH 1-5 decide if we need to release an existing mapping
   */
  ds_attr = ldp_attr_find_downstream_state2(g, nh_session_old, f,
      LDP_LSP_STATE_MAP_RECV);
  if (!ds_attr) {               /* NH.1 */
    goto Detect_Change_Fec_Next_Hop_6;
  }

  if (ds_attr->ingress == MPLS_BOOL_TRUE) {

#if MPLS_USE_LSR
    lsr_ftn ftn;
    ftn.outsegment_index = ds_attr->outlabel->info.handle;
    memcpy(&ftn.fec, &f->info, sizeof(mpls_fec));
    lsr_cfg_ftn_set2(g->lsr_handle, &ftn, LSR_CFG_DEL);
#else
    mpls_mpls_fec2out_del(g->mpls_handle, &f->info, &ds_attr->outlabel->info);
#endif
    ds_attr->ingress = MPLS_BOOL_FALSE;
    ds_attr->outlabel->merge_count--;
  }

  if (g->label_retention_mode == LDP_RETENTION_LIBERAL) { /* NH.3 */
    ldp_attr *us_temp;
    us_attr = MPLS_LIST_HEAD(&ds_attr->us_attr_root);
    while (us_attr) {
      /* need to walk the list in such a way as not to
       * "pull the rug out from under me self"
       */
      us_temp = MPLS_LIST_NEXT(&ds_attr->us_attr_root, us_attr, _ds_attr);
      if (us_attr->state == LDP_LSP_STATE_MAP_SENT) {
        ldp_inlabel_del_outlabel(g, us_attr->inlabel);  /* NH.2 */
        ldp_attr_del_us2ds(g, us_attr, ds_attr);
      }
      us_attr = us_temp;
    }
    goto Detect_Change_Fec_Next_Hop_6;
  }

  ldp_label_release_send(g, nh_session_old, ds_attr, LDP_NOTIF_NONE); /* NH.4 */
  ldp_attr_remove_complete(g, ds_attr, MPLS_BOOL_FALSE); /* NH.2,5 */

Detect_Change_Fec_Next_Hop_6:

  /*
   * NH 6-9 decides is we need to send a label request abort
   */
  ds_attr = ldp_attr_find_downstream_state2(g, nh_session_old, f,
    LDP_LSP_STATE_REQ_SENT);
  if (ds_attr) {               /* NH.6 */
    if (g->label_retention_mode != LDP_RETENTION_CONSERVATIVE) { /* NH.7 */
      /* NH.8,9 */
      if (ldp_label_abort_send(g, nh_session_old, ds_attr) != MPLS_SUCCESS) {
        return MPLS_FAILURE;
      }
    }
  }

  /*
   * NH 10-12 decides if we can use a mapping from our database
   */
  if ((!nh) || (!(nh_session = ldp_get_next_hop_session_for_fec2(f,nh)))) {
    goto Detect_Change_Fec_Next_Hop_16;
  }
  
  ds_attr = ldp_attr_find_downstream_state2(g, nh_session, f,
    LDP_LSP_STATE_MAP_RECV);
  if (!ds_attr) {               /* NH.11 */
    goto Detect_Change_Fec_Next_Hop_13;
  }

  if (ldp_label_mapping_process(g, nh_session, NULL, NULL, ds_attr, f) !=
    MPLS_SUCCESS) { /* NH.12 */
    return MPLS_FAILURE;
  }
  goto Detect_Change_Fec_Next_Hop_20;

Detect_Change_Fec_Next_Hop_13:

  /*
   * NH 13-15 decides if we need to make a label request
   */
  if (nh_session->oper_distribution_mode == LDP_DISTRIBUTION_ONDEMAND &&
    g->label_retention_mode == LDP_RETENTION_CONSERVATIVE) {
    /* NH.14-15 */
    if (ldp_label_request_for_xc(g, nh_session, &f->info, NULL, &ds_attr) !=
        MPLS_SUCCESS) {
      return MPLS_FAILURE;
    }
  }
  goto Detect_Change_Fec_Next_Hop_20;

Detect_Change_Fec_Next_Hop_16:

  peer = MPLS_LIST_HEAD(&g->session);
  while (peer) {
    if (peer->state == LDP_STATE_OPERATIONAL) {
      us_attr = ldp_attr_find_upstream_state2(g, peer, f,
	LDP_LSP_STATE_MAP_SENT);
      if (us_attr) {	/* NH.17 */
	mpls_return_enum retval;
	MPLS_REFCNT_HOLD(us_attr);
        ldp_attr_remove_complete(g, us_attr, MPLS_BOOL_FALSE);
        retval = ldp_label_withdraw_send(g, peer, us_attr, LDP_NOTIF_NONE);
	MPLS_REFCNT_RELEASE2(g, us_attr, ldp_attr_delete);
        if (retval != MPLS_SUCCESS) { /* NH.18 */
	  /*
	   * I think it is best to exit out immediatly with an error
	   * and let the caller do something about it, the only real
	   * option is a global reset of LDP
	   */
          return MPLS_FAILURE;
        }
      }
    }
    peer = MPLS_LIST_NEXT(&g->session, peer, _global);
  }

Detect_Change_Fec_Next_Hop_20:

  LDP_EXIT(g->user_data, "ldp_fec_process_change");

  return MPLS_SUCCESS;
}

void mpls_fec2ldp_fec(mpls_fec * a, ldp_fec * b)
{
  memcpy(&b->info, a, sizeof(mpls_fec));
}

void mpls_fec2fec_tlv(mpls_fec * lf, mplsLdpFecTlv_t * tlv, int i)
{
  tlv->fecElArray[i].addressEl.addressFam = 1;

  switch (lf->type) {
    case MPLS_FEC_PREFIX:
      tlv->fecElArray[i].addressEl.type = MPLS_PREFIX_FEC;
      tlv->fecElArray[i].addressEl.preLen = lf->u.prefix.length;
      tlv->fecElArray[i].addressEl.address = lf->u.prefix.network.u.ipv4;
      tlv->fecElemTypes[i] = MPLS_PREFIX_FEC;
      break;
    case MPLS_FEC_HOST:
      tlv->fecElArray[i].addressEl.type = MPLS_HOSTADR_FEC;
      tlv->fecElArray[i].addressEl.preLen = MPLS_IPv4LEN;
      tlv->fecElArray[i].addressEl.address = lf->u.host.u.ipv4;
      tlv->fecElemTypes[i] = MPLS_HOSTADR_FEC;
      break;
    default:
      MPLS_ASSERT(0);
  }
}

void fec_tlv2mpls_fec(mplsLdpFecTlv_t * tlv, int i, mpls_fec * lf) {
  switch (tlv->fecElemTypes[i]) {
    case MPLS_PREFIX_FEC:
      lf->type = MPLS_FEC_PREFIX;
      lf->u.prefix.length = tlv->fecElArray[i].addressEl.preLen;
      lf->u.prefix.network.u.ipv4 = tlv->fecElArray[i].addressEl.address;
      lf->u.prefix.network.type = MPLS_FAMILY_IPV4;
      break;
    case MPLS_HOSTADR_FEC:
      lf->type = MPLS_FEC_HOST;
      lf->u.host.u.ipv4 = tlv->fecElArray[i].addressEl.address;
      lf->u.host.type = MPLS_FAMILY_IPV4;
      break;
    default:
      MPLS_ASSERT(0);
  }
}

mpls_bool ldp_fec_empty(ldp_fec *fec)
{
  if (MPLS_LIST_EMPTY(&fec->fs_root_us) && 
      MPLS_LIST_EMPTY(&fec->nh_root) &&
      MPLS_LIST_EMPTY(&fec->fs_root_ds)) {
    return MPLS_BOOL_TRUE;
  }
  return MPLS_BOOL_FALSE;
}

