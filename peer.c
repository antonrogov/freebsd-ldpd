#include "ldpd.h"


peer_t *Peer_Find(struct mpls_dest *dest)
{
	peer_t *peer;

	if(!dest)
		return NULL;

	LIST_FOREACH(peer, &ldp->peers, entry) {
		peer->peer.dest.if_handle = 0;
		dest->if_handle = 0;
		if(!mpls_dest_compare(&peer->peer.dest, dest))
			return peer;
	}

	return NULL;
}


peer_t *Peer_Create(struct mpls_dest *dest)
{
	struct in_addr addr;
	char addrBuf[64];
	peer_t *peer;

	MPLS_ASSERT(ldp);
	if(!dest)
		return NULL;

	peer = calloc(1, sizeof(peer_t));
	if(!peer)
		return NULL;

	LIST_INSERT_HEAD(&ldp->peers, peer, entry);

	peer->up = MPLS_BOOL_FALSE;
	ldp_entity_set_defaults(&peer->entity);

	addr.s_addr = htonl(dest->addr.u.ipv4);
	if(!inet_ntop(AF_INET, &addr, addrBuf, sizeof(addrBuf)))
		addrBuf[0] = '\0';
	strncpy(peer->peer.peer_name, addrBuf, IFNAMSIZ);
	peer->peer.label_space = 0;
	memcpy(&peer->peer.dest, dest, sizeof(struct mpls_dest));
	ldp_cfg_peer_set(ldp->config, &peer->peer, LDP_CFG_ADD | LDP_IF_CFG_LABEL_SPACE | LDP_PEER_CFG_DEST_ADDR | LDP_PEER_CFG_PEER_NAME);

	peer->entity.sub_index = peer->peer.index;
	peer->entity.entity_type = LDP_INDIRECT;
	peer->entity.admin_state = MPLS_ADMIN_DISABLE;
	peer->entity.transport_address.type = MPLS_FAMILY_IPV4;
	peer->entity.transport_address.u.ipv4 = (uint32_t)ntohl(routerID.s_addr);
	ldp_cfg_entity_set(ldp->config, &peer->entity, LDP_CFG_ADD | LDP_ENTITY_CFG_SUB_INDEX | LDP_ENTITY_CFG_ADMIN_STATE | LDP_ENTITY_CFG_TRANS_ADDR);

	ldp_cfg_entity_get(ldp->config, &peer->entity, 0xFFFFFFFF);
	ldp_cfg_peer_get(ldp->config, &peer->peer, 0xFFFFFFFF);

	Peer_Enable(peer);

	return peer;
}


void Peer_Destroy(peer_t *peer)
{
	MPLS_ASSERT(peer);

	peer->entity.admin_state = MPLS_ADMIN_DISABLE;

	if(ldp) {
		Peer_Disable(peer);
		ldp_cfg_entity_set(ldp->config, &peer->entity, LDP_CFG_DEL);
		ldp_cfg_peer_set(ldp->config, &peer->peer, LDP_CFG_DEL);
		LIST_REMOVE(peer, entry);
	}
	peer->entity.index = 0;
	peer->peer.index = 0;

	free(peer);
}


void Peer_Enable(peer_t *peer)
{
	MPLS_ASSERT(ldp);
	MPLS_ASSERT(peer);

	if(!peer->peer.index || peer->up == MPLS_BOOL_TRUE)
		return;

	peer->up = MPLS_BOOL_TRUE;
	peer->entity.admin_state = MPLS_ADMIN_ENABLE;
	ldp_cfg_entity_set(ldp->config, &peer->entity, LDP_ENTITY_CFG_ADMIN_STATE);
}


void Peer_Disable(peer_t *peer)
{
	MPLS_ASSERT(ldp);
	MPLS_ASSERT(peer);

	if(!peer->peer.index || peer->up == MPLS_BOOL_FALSE)
		return;

	peer->up = MPLS_BOOL_FALSE;
	peer->entity.admin_state = MPLS_ADMIN_DISABLE;
	ldp_cfg_entity_set(ldp->config, &peer->entity, LDP_ENTITY_CFG_ADMIN_STATE);
}
