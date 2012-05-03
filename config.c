#include "ldpd.h"


#define MAX_CONFIG_LINE_LENGTH	1024
#define MAX_CONFIG_LINE_WORDS	32

static char *config = "/usr/local/etc/ldpd.conf";
static int argc;
static char *argv[MAX_CONFIG_LINE_WORDS];
static char line[MAX_CONFIG_LINE_LENGTH];


static int Config_ReadLine(FILE *file)
{
	char *end;
	int pos, length;

	while(1) {
		if(!fgets(line, sizeof(line), file))
			return 0;

		pos = 0;
		length = strlen(line) - 1;
		line[length] = '\0';
		if(!length)
			return 0;

		while(line[pos] == ' ' || line[pos] == '\t')
			pos++;

		if(line[pos] == '#')
			continue;
		break;
	}

	argc = 0;
	while(pos < length) {
		argv[argc] = &line[pos];
		end = strchr(&line[pos], ' ');
		if(end)
			*end = '\0';
		else
			end = &line[length];
		pos += end - ((char *)&line[pos]) + 1;
		argc++;
	}

	return 1;
}


void Config_Load(char *path)
{
	int globalFlags, entityFlags, up, label, changed;
	FILE *file;
	ldp_global g;
	ldp_entity *e;
	struct in_addr addr;
	struct mpls_dest dest;
	interface_t *iface;
	peer_t *peer;

	if(ldp->configured == MPLS_BOOL_FALSE) {
		ldp->configured = MPLS_BOOL_TRUE;
		LDP_Enable();
	}

	while(!LIST_EMPTY(&ldp->peers)) {
		peer = LIST_FIRST(&ldp->peers);
		Peer_Destroy(peer);
	}

	if(path)
		config = path;

	file = fopen(config, "r");
	if(!file)
		return;

	ldp->isStaticLSRID = MPLS_BOOL_FALSE;

	changed = 0;
	globalFlags = 0;
	while(!feof(file)) {
		if(!Config_ReadLine(file))
			continue;

		if(!strcmp(argv[0], "vrf")) {
		
		} else if(!strcmp(argv[0], "interface")) {
			/* interface configuration */
			iface = Interface_FindByName(argv[1]);
			if(iface) {
				e = &iface->entity;
				entityFlags = 0;
				up = 0;
				label = -1;
				while(Config_ReadLine(file)) {
					if(!strcmp(argv[0], "mpls")) {
						if(!strcmp(argv[1], "ip"))
							up = 1;
					} else if(!strcmp(argv[0], "l2transport")) {
						/* only one vpn per interfaces is allowed */
						if(iface->vpnLabel > 0) {
							continue;
						}

						if(inet_aton(argv[1], &addr)) {
							iface->vpnType = 2;
							iface->vpnDest.s_addr = addr.s_addr;
							iface->vpnLabel = mpls_alloc_label();
						} else {
							iface->vpnLabel = -1;
						}
					} else if(!strcmp(argv[0], "vrf")) {
					} else if(!strcmp(argv[0], "distribution-mode")) {
						/* distribution-mode dod or du */
						if(!strcmp(argv[1], "dod"))
							e->label_distribution_mode = LDP_DISTRIBUTION_ONDEMAND;
						else
							e->label_distribution_mode = LDP_DISTRIBUTION_UNSOLICITED;
						entityFlags |= LDP_ENTITY_CFG_DISTRIBUTION_MODE;
					} else if(!strcmp(argv[0], "remote-tcp-port")) {
						/* remote-tcp-port */
						e->remote_tcp_port = atoi(argv[1]);
						entityFlags |= LDP_ENTITY_CFG_REMOTE_TCP;
					} else if(!strcmp(argv[0], "remote-udp-port")) {
						/* remote-udp-port */
						e->remote_udp_port = atoi(argv[1]);
						entityFlags |= LDP_ENTITY_CFG_REMOTE_UDP;
					} else if(!strcmp(argv[0], "max-pdu")) {
						/* max-pdu */
						e->max_pdu = atoi(argv[1]);
						entityFlags |= LDP_ENTITY_CFG_MAX_PDU;
					} else if(!strcmp(argv[0], "hello-interval")) {
						/* hello-interval */
						e->hellotime_interval = atoi(argv[1]);
						entityFlags |= LDP_ENTITY_CFG_HELLOTIME_INTERVAL;
					} else if(!strcmp(argv[0], "keepalive-interval")) {
						/* keepalive-interval */
						e->keepalive_interval = atoi(argv[1]);
						entityFlags |= LDP_ENTITY_CFG_KEEPALIVE_INTERVAL;
					} else if(!strcmp(argv[0], "max-session-attempt")) {
						/* max-session_attempt */
						e->session_setup_count = atoi(argv[1]);
						entityFlags |= LDP_ENTITY_CFG_SESSION_SETUP_COUNT;
					} else if(!strcmp(argv[0], "max-path-vector")) {
						/* max-path-vector */
						e->path_vector_limit = atoi(argv[1]);
						entityFlags |= LDP_ENTITY_CFG_PATHVECTOR_LIMIT;
					} else if(!strcmp(argv[0], "max-hop-count")) {
						/* max-hop-count */
						e->hop_count_limit = atoi(argv[1]);
						entityFlags |= LDP_ENTITY_CFG_HOPCOUNT_LIMIT;
					} else if(!strcmp(argv[0], "max-label-requests")) {
						/* max-label-requests */
						e->label_request_count = atoi(argv[1]);
						entityFlags |= LDP_ENTITY_CFG_REQUEST_COUNT;
					}
				}

				/* configure or shutdown interface */
				if(iface->configUp && !up) {
					Interface_Shutdown(iface);
					/* TODO move to Interface_Shutdown */
					mpls_disable_interface(iface->name);
				} else if(!iface->configUp && up) {
					Interface_Init(iface);
					/* TODO move to Interface_Init */
					mpls_enable_interface(iface->name);
					if(iface->vpnLabel > 0) {
						mpls_add_vpn(iface->vpnType, iface->name, &iface->vpnDest, iface->vpnLabel);
					}
				}

				/* apply config */
				if(iface->entity.index) {
					Interface_Disable(iface);
					ldp_cfg_entity_set(ldp->config, e, entityFlags);
					Interface_Enable(iface);
				}
			}

		} else if(!strcmp(argv[0], "lsr-id")) {
			/* lsr-id ADDR */
			if(inet_aton(argv[1], &addr)) {
				ldp->isStaticLSRID = MPLS_BOOL_TRUE;
				ldp->lsrID.s_addr = addr.s_addr;
			} else {
				printf("unknown address format\n");
				continue;
			}
			changed = 1;
		} else if(!strcmp(argv[0], "edge-inlabel")) {
			/* edge-inlabel on or off */
			if(!strcmp(argv[1], "on"))
				g.edge_inlabel = MPLS_BOOL_TRUE;
			else if(!strcmp(argv[1], "off"))
				g.edge_inlabel = MPLS_BOOL_FALSE;
			else
				continue;
			globalFlags |= LDP_GLOBAL_CFG_EDGE_INLABEL;
		} else if(!strcmp(argv[0], "implicit-null")) {
			/* edge-inlabel on or off */
			if(!strcmp(argv[1], "on"))
				ldp->implicitNull = MPLS_BOOL_TRUE;
			else if(!strcmp(argv[1], "off"))
				ldp->implicitNull = MPLS_BOOL_FALSE;
			else
				continue;
			changed = 1;
		} else if(!strcmp(argv[0], "lsp-control-mode")) {
			/* lsp-control-mode independent or ordered*/
			if(!strcmp(argv[1], "independent"))
				g.lsp_control_mode = LDP_CONTROL_INDEPENDENT;
			else if(!strcmp(argv[1], "ordered"))
				g.lsp_control_mode = LDP_CONTROL_ORDERED;
			else
				continue;
			globalFlags |= LDP_GLOBAL_CFG_CONTROL_MODE;
		} else if(!strcmp(argv[0], "label-retention-mode")) {
			/* label-retention-mode liberal or conservative */
			if(!strcmp(argv[1], "liberal"))
				g.label_retention_mode = LDP_RETENTION_LIBERAL;
			else if(!strcmp(argv[1], "conservative"))
				g.label_retention_mode = LDP_RETENTION_CONSERVATIVE;
			else
				continue;
			globalFlags |= LDP_GLOBAL_CFG_RETENTION_MODE;
		} else if(!strcmp(argv[0], "lsp-repair-mode")) {
			/* lsp-repair-mode local or global */
			if(!strcmp(argv[1], "local"))
				g.lsp_repair_mode = LDP_REPAIR_LOCAL;
			else if(!strcmp(argv[1], "global"))
				g.lsp_repair_mode = LDP_REPAIR_GLOBAL;
			else
				continue;
			globalFlags |= LDP_GLOBAL_CFG_REPAIR_MODE;
		} else if(!strcmp(argv[0], "propagate-release")) {
			/* propagate-release on or off */
			if(!strcmp(argv[1], "on"))
				g.propagate_release = MPLS_BOOL_TRUE;
			else if(!strcmp(argv[1], "off"))
				g.propagate_release = MPLS_BOOL_FALSE;
			else
				continue;
			globalFlags |= LDP_GLOBAL_CFG_PROPOGATE_RELEASE;
		} else if(!strcmp(argv[0], "label-merge")) {
			/* label-merge */
			if(!strcmp(argv[1], "on"))
				g.label_merge = MPLS_BOOL_TRUE;
			else if(!strcmp(argv[1], "off"))
				g.label_merge = MPLS_BOOL_FALSE;
			else
				continue;
			globalFlags |= LDP_GLOBAL_CFG_LABEL_MERGE;
		} else if(!strcmp(argv[0], "loop-detection-mode")) {
			/* loop-detection-mode hop or path or both */
			if(!strcmp(argv[1], "hop"))
				g.loop_detection_mode = LDP_LOOP_HOPCOUNT;
			else if(!strcmp(argv[1], "path"))
				g.loop_detection_mode = LDP_LOOP_PATHVECTOR;
			else if(!strcmp(argv[1], "both"))
				g.loop_detection_mode = LDP_LOOP_HOPCOUNT_PATHVECTOR;
			else
				continue;
			globalFlags |= LDP_GLOBAL_CFG_LOOP_DETECTION_MODE;
		} else if(!strcmp(argv[0], "ttl-less-domain")) {
			/* ttl-less-domain on or off */
			if(!strcmp(argv[1], "on"))
				g.ttl_less_domain = MPLS_BOOL_TRUE;
			else if(!strcmp(argv[1], "off"))
				g.ttl_less_domain = MPLS_BOOL_FALSE;
			else
				continue;
			globalFlags |= LDP_GLOBAL_CFG_TTLLESS_DOMAIN;
		} else if(!strcmp(argv[0], "local-tcp-port")) {
			/* local-tcp-port */
			g.local_tcp_port = atoi(argv[1]);
			globalFlags |= LDP_GLOBAL_CFG_LOCAL_TCP_PORT;
		} else if(!strcmp(argv[0], "local-udp-port")) {
			/* local-udp-port */
			g.local_udp_port = atoi(argv[1]);
			globalFlags |= LDP_GLOBAL_CFG_LOCAL_UDP_PORT;
		} else if(!strcmp(argv[0], "egress")) {
			/* egress lsr-id or connected or all */
			if(!strcmp(argv[1], "lsr-id"))
				ldp->egress = LDP_EGRESS_LSRID;
			else if(!strcmp(argv[1], "connected"))
				ldp->egress = LDP_EGRESS_CONNECTED;
			else if(!strcmp(argv[1], "all"))
				ldp->egress = LDP_EGRESS_ALL;
			else
				continue;
		} else if(!strcmp(argv[0], "address-mode")) {
			/* address-mode lsr-id or ldp or all */
			if(!strcmp(argv[1], "lsr-id"))
				ldp->address = LDP_ADDRESS_LSRID;
			else if(!strcmp(argv[1], "ldp"))
				ldp->address = LDP_ADDRESS_LDP;
			else if(!strcmp(argv[1], "all"))
				ldp->address = LDP_ADDRESS_ALL;
			else
				continue;
		} else if(!strcmp(argv[0], "transport-address")) {
			/* transport-address lsr-id or interface or ADDR or NAME */
			g.transport_address.type = MPLS_FAMILY_NONE;
			g.transport_address.u.ipv4 = 0;

			if(!strcmp(argv[1], "lsr-id")) {
				/* lsr-id: use lsr-id */
				ldp->transAddr = LDP_TRANS_ADDR_LSRID;
				g.transport_address.type = MPLS_FAMILY_IPV4;
				g.transport_address.u.ipv4 = ntohl(ldp->lsrID.s_addr);
			} else if(!strcmp(argv[1], "interface"))
				/* interface: use interface address */
				ldp->transAddr = LDP_TRANS_ADDR_INTERFACE;
			else {
				if(inet_aton(argv[1], &addr)) {
					/* address: use static address */
					ldp->transAddr = LDP_TRANS_ADDR_STATIC_IP;
					g.transport_address.type = MPLS_FAMILY_IPV4;
					g.transport_address.u.ipv4 = ntohl(addr.s_addr);
				} else {
					/* interface name: use address of specified interface */
					ldp->transAddr = LDP_TRANS_ADDR_STATIC_INTERFACE;
					strlcpy(ldp->transAddrIfName, argv[1], sizeof(ldp->transAddrIfName));
					iface = Interface_FindByName(argv[1]);
					if(iface) {
						g.transport_address.type = MPLS_FAMILY_IPV4;
						g.transport_address.u.ipv4 = ntohl(Interface_GetAddress(iface));
					} else
						continue;
				}
			}

			/* update transport addresses of all interfaces */
			TAILQ_FOREACH(iface, &interfaces, entry) {
				if(ldp->transAddr == LDP_TRANS_ADDR_INTERFACE) {
					iface->entity.transport_address.type = MPLS_FAMILY_IPV4;
					iface->entity.transport_address.u.ipv4 = ntohl(Interface_GetAddress(iface));
				} else {
					iface->entity.transport_address.type = MPLS_FAMILY_NONE;
					iface->entity.transport_address.u.ipv4 = 0;
				}
				if(iface->entity.index) {
					Interface_Disable(iface);
					ldp_cfg_entity_set(ldp->config, &iface->entity, LDP_ENTITY_CFG_TRANS_ADDR);
					Interface_Enable(iface);
				}
			}

			globalFlags |= LDP_GLOBAL_CFG_TRANS_ADDR;
		}
	}

	fclose(file);

	if(globalFlags)
		changed = 1;

	if(changed)
		LDP_Disable();

	LDP_UpdateLSRID();
	if(globalFlags)
		ldp_cfg_global_set(ldp->config, &g, globalFlags);

	if(changed)
		LDP_Enable();
}


void Config_Reload()
{
	Config_Load(config);
}


static void Config_SaveLDP(FILE *file)
{
	ldp_global g;
	struct in_addr addr;
	char addrBuf[64];

	MPLS_ASSERT(file);

	if(!ldp)
		return;

	ldp_cfg_global_get(ldp->config, &g, 0xFFFFFFFF);

	if(ldp->isStaticLSRID && inet_ntop(AF_INET, &ldp->lsrID, addrBuf, sizeof(addrBuf)))
		fprintf(file, "lsr-id %s\n", addrBuf);

	if(!ldp->implicitNull)
		fprintf(file, "implicit-null off\n");

	if(g.edge_inlabel != LDP_GLOBAL_DEF_EDGE_INLABEL) {
		fprintf(file, "edge_inlabel ");
		if(g.edge_inlabel == MPLS_BOOL_TRUE)
			fprintf(file, "on");
		else
			fprintf(file, "off");
		fprintf(file, "\n");

	}

	if(g.lsp_control_mode != LDP_GLOBAL_DEF_CONTROL_MODE) {
		fprintf(file, "lsp-control-mode ");
		if(g.lsp_control_mode == LDP_CONTROL_INDEPENDENT)
			fprintf(file, "independent");
		else
			fprintf(file, "ordered");
		fprintf(file, "\n");
	}

	if(g.label_retention_mode != LDP_GLOBAL_DEF_RETENTION_MODE) {
		fprintf(file, "label-retention-mode ");
		if(g.label_retention_mode == LDP_RETENTION_LIBERAL)
			fprintf(file, "liberal");
		else
			fprintf(file, "conservative");
		fprintf(file, "\n");
	}

	if(g.lsp_repair_mode != LDP_GLOBAL_DEF_REPAIR_MODE) {
		fprintf(file, "lsp-repair-mode ");
		if(g.lsp_repair_mode == LDP_REPAIR_LOCAL)
			fprintf(file, "local");
		else
			fprintf(file, "global");
		fprintf(file, "\n");
	}

	if(g.propagate_release != LDP_GLOBAL_DEF_PROPOGATE_RELEASE) {
		fprintf(file, "propagate-release ");
		if(g.propagate_release == MPLS_BOOL_TRUE)
			fprintf(file, "on");
		else
			fprintf(file, "off");
		fprintf(file, "\n");
	}

	if(g.label_merge != LDP_GLOBAL_DEF_LABEL_MERGE) {
		fprintf(file, "label-merge ");
		if(g.label_merge == MPLS_BOOL_TRUE)
			fprintf(file, "on");
		else
			fprintf(file, "off");
		fprintf(file, "\n");
	}

	if(g.loop_detection_mode != LDP_GLOBAL_DEF_LOOP_DETECTION_MODE) {
		if(g.loop_detection_mode == LDP_LOOP_HOPCOUNT)
			fprintf(file, "loop-detection-mode hop\n");
		else if(g.loop_detection_mode == LDP_LOOP_PATHVECTOR)
			fprintf(file, "loop-detection-mode path\n");
		else if(g.loop_detection_mode == LDP_LOOP_HOPCOUNT_PATHVECTOR)
			fprintf(file, "loop-detection-mode both\n");
	}

	if(g.ttl_less_domain != MPLS_BOOL_FALSE)
		fprintf(file, "ttl-less-domain on\n");

	if(g.local_tcp_port != LDP_GLOBAL_DEF_LOCAL_TCP_PORT)
		fprintf(file, "local-tcp-port %d\n", g.local_tcp_port);

	if(g.local_udp_port != LDP_GLOBAL_DEF_LOCAL_UDP_PORT)
		fprintf(file, "local-udp-port %d\n", g.local_udp_port);

	if(ldp->egress != LDP_DEF_EGRESS_POLICY) {
		switch(ldp->egress) {
		case LDP_EGRESS_LSRID:
			fprintf(file, "egress lsr-id\n");
			break;
		case LDP_EGRESS_CONNECTED:
			fprintf(file, "egress connected\n");
			break;
		case LDP_EGRESS_ALL:
			fprintf(file, "egress all\n");
			break;
		default:
			break;
		}
	}

	if(ldp->address != LDP_DEF_ADDRESS_POLICY) {
		switch (ldp->address) {
		case LDP_ADDRESS_LSRID:
			fprintf(file, "address-mode lsr-id\n");
			break;
		case LDP_ADDRESS_LDP:
			fprintf(file, "address-mode ldp\n");
			break;
		case LDP_ADDRESS_ALL:
			fprintf(file, "address-mode all\n");
			break;
		default:
			break;
		}
	}

	if(ldp->transAddr != LDP_DEF_TRANSPORT_ADDRESS_POLICY) {
		switch (ldp->transAddr) {
		case LDP_TRANS_ADDR_LSRID:
			fprintf(file, "transport-address lsr-id\n");
			break;
		case LDP_TRANS_ADDR_INTERFACE:
			fprintf(file, "transport-address interface\n");
			break;
		case LDP_TRANS_ADDR_STATIC_IP:
			addr.s_addr = htonl(g.transport_address.u.ipv4);
			if(inet_ntop(AF_INET, &addr, addrBuf, sizeof(addrBuf)))
				fprintf(file, "transport-address %s\n", addrBuf);
			break;
		case LDP_TRANS_ADDR_STATIC_INTERFACE:
			fprintf(file, "transport-address %s\n", ldp->transAddrIfName);
			break;
		default:
			break;
		}
	}

	fprintf(file, "\n");
}


static void Config_SaveInterface(FILE *file, interface_t *iface)
{
	char addrBuf[64];
	ldp_entity e;

	MPLS_ASSERT(iface);

	fprintf(file, "interface %s\n", iface->name);

	if(iface->configUp)
		fprintf(file, " mpls ip\n");

	if(iface->vpnLabel > 0) {
		if(inet_ntop(AF_INET, &iface->vpnDest, addrBuf, sizeof(addrBuf))) {
			fprintf(file, " %s %s\n", (iface->vpnType == 2) ? "l2transport" : "l3vpn", addrBuf);
		}
	}

	if(iface->entity.index && ldp) {
		e.index = iface->entity.index;
		ldp_cfg_entity_get(ldp->config, &e, 0xFFFFFFFF);
	} else
		memcpy(&e, &iface->entity, sizeof(struct ldp_entity));

	if(e.label_distribution_mode != LDP_ENTITY_DEF_DISTRIBUTION_MODE) {
		fprintf(file, " distribution-mode ");
		if(e.label_distribution_mode == LDP_DISTRIBUTION_ONDEMAND)
			fprintf(file, "dod");
		else
			fprintf(file, "du");
		fprintf(file, "\n");
	}

	if(e.remote_tcp_port != LDP_ENTITY_DEF_REMOTE_TCP)
		fprintf(file, " remote-tcp-port %d\n", e.remote_tcp_port);

	if(e.remote_udp_port != LDP_ENTITY_DEF_REMOTE_UDP)
		fprintf(file, " remote-udp-port %d\n", e.remote_udp_port);

	if(e.max_pdu != LDP_ENTITY_DEF_MAX_PDU)
		fprintf(file, " max-pdu %d\n", e.max_pdu);

	if(e.hellotime_interval != LDP_ENTITY_DEF_HELLOTIME_INTERVAL)
		fprintf(file, " hello-interval %d\n", e.hellotime_interval);

	if(e.keepalive_interval != LDP_ENTITY_DEF_KEEPALIVE_INTERVAL)
		fprintf(file, " keepalive-interval %d\n", e.keepalive_interval);

	if(e.session_setup_count != LDP_ENTITY_DEF_SESSIONSETUP_COUNT)
		fprintf(file, " max-session-attempt %d\n", e.session_setup_count);

	if(e.path_vector_limit != LDP_ENTITY_DEF_PATHVECTOR_LIMIT)
		fprintf(file, " max-path-vector %d\n", e.path_vector_limit);

	if(e.hop_count_limit != LDP_ENTITY_DEF_HOPCOUNT_LIMIT)
		fprintf(file, " max-hop-count %d\n", e.hop_count_limit);

	if(e.label_request_count != LDP_ENTITY_DEF_REQUEST_COUNT)
		fprintf(file, " max-label-requests %d\n", e.label_request_count);

	fprintf(file, "\n");
}


void Config_Save()
{
	FILE *file;
	interface_t *iface;

	file = fopen(config, "w");
	if(!file)
		return;

	Config_SaveLDP(file);

	TAILQ_FOREACH(iface, &interfaces, entry)
		Config_SaveInterface(file, iface);

	fclose(file);
}
