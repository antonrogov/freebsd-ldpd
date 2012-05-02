#include "ldpd.h"
#include <sys/stat.h>
#include <sys/un.h>
#include "control.h"

typedef struct client_s {
	int				fd;
	struct event	ev;
} client_t;

static int controlFD;
static struct event listenEvent;

static void Control_ShowFEC(int fd);
static void Control_ShowNeighbors(int fd);
static void Control_ShowDatabase(int fd);
static void Control_ShowLDP(int fd);

static void Control_Receive(int fd, short event, void *data)
{
	uint32_t type;

	if(!read(fd, &type, sizeof(type))) {
		printf("Control_Receive: read type\n");
		return;
	}

	switch(type) {
	case COMMAND_SHOW_LDP:
		Control_ShowLDP(fd);
		break;
	case COMMAND_SHOW_LDP_FEC:
		Control_ShowFEC(fd);
		break;
	case COMMAND_SHOW_LDP_NEIGHBORS:
		Control_ShowNeighbors(fd);
		break;
	case COMMAND_SHOW_LDP_DATABASE:
		Control_ShowDatabase(fd);
		break;
	case COMMAND_SHOW_FORWARDING:
		MPLS_ShowLIB(fd);
		break;
	}
}


static void Control_Accept(int fd, short event, void *data)
{
	client_t *client;
	socklen_t len;
	struct sockaddr_un sun;

	client = malloc(sizeof(client));
	if(!client)
		return;

	len = sizeof(sun);
	client->fd = accept(fd, (struct sockaddr *)&sun, &len);
	if(client->fd == -1) {
		if(errno != EWOULDBLOCK && errno != EINTR)
			printf("Control_Accept: accept");
		return;
	}

	fcntl(client->fd, F_SETFL, O_NONBLOCK);

	event_set(&client->ev, client->fd, EV_READ, Control_Receive, NULL);
	event_add(&client->ev, NULL);
}


void Control_Init()
{
	int fd, oldumask;
	struct sockaddr_un sun;

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if(fd == -1) {
		printf("Control_Init: socket\n");
		return;
	}

	bzero(&sun, sizeof(sun));
	sun.sun_family = AF_UNIX;
	strlcpy(sun.sun_path, LDPD_SOCK, sizeof(sun.sun_path));

	if(unlink(LDPD_SOCK) == -1)
		if(errno != ENOENT) {
			printf("Control_Init: unlink %s", LDPD_SOCK);
			close(fd);
			return;
		}

	oldumask = umask(S_IXUSR | S_IXGRP | S_IWOTH | S_IROTH | S_IXOTH);
	if(bind(fd, (struct sockaddr *)&sun, sizeof(sun)) == -1) {
		printf("Control_Init: bind: %s", LDPD_SOCK);
		close(fd);
		umask(oldumask);
		return;
	}
	umask(oldumask);

	if(chmod(LDPD_SOCK, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP) == -1) {
		printf("Control_Init: chmod\n");
		close(fd);
		unlink(LDPD_SOCK);
		return;
	}

	fcntl(fd, F_SETFL, O_NONBLOCK);

	if(listen(fd, 0) == -1) {
		printf("Control_Init: listen");
		return;
	}

	event_set(&listenEvent, fd, EV_READ | EV_PERSIST, Control_Accept, NULL);
	event_add(&listenEvent, NULL);

	controlFD = fd;
}


void Control_Shutdown()
{
	event_del(&listenEvent);
	if(controlFD > 0)
		close(controlFD);
}


static void Control_ShowFEC(int fd)
{
	uint32_t i;
	struct mpls_fec fec;
	struct mpls_nexthop nh;
	struct in_addr addr;
	msgFEC_t msgFEC;
	msgNexthop_t msgNexthop;

	i = 0;
	fec.index = 0;
	while(ldp_cfg_fec_getnext(ldp->config, &fec, 0xFFFFFFFF) == MPLS_SUCCESS)
		i++;
	write(fd, &i, sizeof(i));

	fec.index = 0;
	while(ldp_cfg_fec_getnext(ldp->config, &fec, 0xFFFFFFFF) == MPLS_SUCCESS) {
		i = 0;
		nh.index = 0;
		while(ldp_cfg_fec_nexthop_getnext(ldp->config, &fec, &nh, 0xFFFFFFFF) == MPLS_SUCCESS)
			i++;

		msgFEC.index = fec.index;
		msgFEC.prefix = htonl(fec.u.prefix.network.u.ipv4);
		msgFEC.length = fec.u.prefix.length;
		msgFEC.count = i;
		write(fd, &msgFEC, sizeof(msgFEC));

		nh.index = 0;
		while(ldp_cfg_fec_nexthop_getnext(ldp->config, &fec, &nh, 0xFFFFFFFF) == MPLS_SUCCESS) {
			msgNexthop.index = nh.index;;
			msgNexthop.address = htonl(nh.ip.u.ipv4);
			msgNexthop.attached = nh.attached;
			write(fd, &msgNexthop, sizeof(msgNexthop));
		}
	}
}


static void Control_ShowNeighbors(int fd)
{
	ldp_adj adj;
	ldp_addr addr;
	ldp_entity e;
	ldp_global g;
	ldp_session s;
	ldp_if iff;
	ldp_peer peer;
	uint32_t count, ipaddr, time_now;
	msgNeighbor_t neighbor;
	
	ldp_cfg_global_get(ldp->config, &g, 0xFFFFFFFF);

	count = 0;
	adj.index = 0;
	while(ldp_cfg_adj_getnext(ldp->config, &adj, 0xFFFFFFFF) == MPLS_SUCCESS)
		count++;
	write(fd, &count, sizeof(count));

	adj.index = 0;
	while(ldp_cfg_adj_getnext(ldp->config, &adj, 0xFFFFFFFF) == MPLS_SUCCESS) {
		if (adj.entity_index) {
			e.index = adj.entity_index;
			ldp_cfg_entity_get(ldp->config, &e, 0xFFFFFFFF);
			if(e.entity_type == LDP_DIRECT) {
				iff.index = e.sub_index;
				ldp_cfg_if_get(ldp->config, &iff, 0xFFFFFFFF);
			} else {
				peer.index = e.sub_index;
				ldp_cfg_peer_get(ldp->config, &peer, 0xFFFFFFFF);
			}
		}

		memset(&neighbor, 0, sizeof(neighbor));
		neighbor.id = htonl(adj.remote_lsr_address.u.ipv4);
		neighbor.labelspace = adj.remote_label_space;

		if(adj.session_index) {
			s.index = adj.session_index;
			if(ldp_cfg_session_get(ldp->config, &s, 0xFFFFFFFF) != MPLS_SUCCESS)
				continue;

			neighbor.localAddress = htonl(s.local_name.addr.u.ipv4);
			neighbor.localPort = s.local_name.port;
			neighbor.remoteAddress = htonl(s.remote_name.addr.u.ipv4);
			neighbor.remotePort = s.remote_name.port;
			neighbor.state = s.state;
			neighbor.received = s.mesg_rx;
			neighbor.sent = s.mesg_tx;
			neighbor.mode = s.oper_distribution_mode;

			neighbor.timeUp = s.oper_up;
		}

		if(e.entity_type == LDP_DIRECT)
			strlcpy(neighbor.name, iff.handle->name, sizeof(neighbor.name));
		else
			strlcpy(neighbor.name, peer.peer_name, sizeof(neighbor.name));

		if(adj.session_index) {
			addr.index = 0;
			count = 0;
			while(ldp_cfg_session_raddr_getnext(ldp->config, &s, &addr, 0xFFFFFFFF) == MPLS_SUCCESS)
				count++;
			neighbor.numAddresses = count;
			write(fd, &neighbor, sizeof(neighbor));

			addr.index = 0;
			while(ldp_cfg_session_raddr_getnext(ldp->config, &s, &addr, 0xFFFFFFFF) == MPLS_SUCCESS) {
				ipaddr = htonl(addr.address.u.ipv4);
				write(fd, &ipaddr, sizeof(ipaddr));
			}
		} else {
			neighbor.numAddresses = 0;
			write(fd, &neighbor, sizeof(neighbor));
		}
	}
}


static void Control_ShowDatabase(int fd)
{
	ldp_session session;
	ldp_outlabel out;
	ldp_inlabel in;
	ldp_attr attr;
	ldp_adj adj;
	uint32_t count;
	struct in_addr fec;
	msgLabel_t label;

	if(!ldp)
		return;

	count = 0;
	attr.index = 0;
	while(ldp_cfg_attr_getnext(ldp->config, &attr, 0xFFFFFFFF) == MPLS_SUCCESS)
		count++;
	write(fd, &count, sizeof(count));

	attr.index = 0;
	while(ldp_cfg_attr_getnext(ldp->config, &attr, 0xFFFFFFFF) == MPLS_SUCCESS) {
		label.prefix = htonl(attr.fecTlv.fecElArray[0].addressEl.address);
		label.length = attr.fecTlv.fecElArray[0].addressEl.preLen;

		label.isSession = 1;
		session.index = attr.session_index;
		if(ldp_cfg_session_get(ldp->config, &session, 0xFFFFFFFF) != MPLS_SUCCESS) {
			label.isSession = 0;
			write(fd, &label, sizeof(label));
			continue;
		}

		label.isAdj = 1;
		adj.index = session.adj_index;
		if(ldp_cfg_adj_get(ldp->config, &adj, 0xFFFFFFFF) != MPLS_SUCCESS) {
			label.isAdj = 0;
			write(fd, &label, sizeof(label));
			continue;
		}

		switch(attr.state) {
		case LDP_LSP_STATE_MAP_RECV:
			label.type = LABEL_REMOTE;
			out.index = attr.outlabel_index;
			if(ldp_cfg_outlabel_get(ldp->config, &out, 0xFFFFFFFF) != MPLS_SUCCESS)
				label.label = -1;
			else
				label.label = out.info.label.u.gen;
			label.remoteAddress = htonl(adj.remote_lsr_address.u.ipv4);
			label.labelspace = adj.remote_label_space;
			label.isIngress = attr.ingress == MPLS_BOOL_TRUE;
			break;
		case LDP_LSP_STATE_MAP_SENT:
			label.type = LABEL_LOCAL;
			in.index = attr.inlabel_index;
			if(ldp_cfg_inlabel_get(ldp->config, &in, 0xFFFFFFFF) != MPLS_SUCCESS)
				label.label = -1;
			else
				label.label = in.info.label.u.gen;
			break;
		case LDP_LSP_STATE_WITH_SENT:
		case LDP_LSP_STATE_WITH_RECV:
		case LDP_LSP_STATE_NO_LABEL_RESOURCE_SENT:
		case LDP_LSP_STATE_NO_LABEL_RESOURCE_RECV:
		case LDP_LSP_STATE_ABORT_SENT:
		case LDP_LSP_STATE_ABORT_RECV:
		case LDP_LSP_STATE_NOTIF_SENT:
		case LDP_LSP_STATE_NOTIF_RECV:
		case LDP_LSP_STATE_REQ_RECV:
		case LDP_LSP_STATE_REQ_SENT:
			label.type = LABEL_ATTR;
			label.state = attr.state;
			label.remoteAddress = adj.remote_lsr_address.u.ipv4;
			label.labelspace = adj.remote_label_space;
			break;
		default:
			break;
		}

		write(fd, &label, sizeof(label));
	}
}


static void Control_ShowLDP(int fd)
{
	ldp_global g;
	msgLDP_t msg;

	ldp_cfg_global_get(ldp->config, &g, 0xFFFFFFFF);

    msg.id = htonl(g.lsr_identifier.u.ipv4);
	msg.state = g.admin_state;
    msg.transportAddr = htonl(g.transport_address.u.ipv4);
	msg.controlMode = g.lsp_control_mode;
	msg.repairMode = g.lsp_repair_mode;
	msg.propogateRelease = g.propagate_release;
	msg.labelMerge = g.label_merge;
	msg.retentionMode = g.label_retention_mode;
	msg.loopMode = g.loop_detection_mode;
	msg.ttlLessDomain = g.ttl_less_domain;
	msg.localTCP = g.local_tcp_port;
	msg.localUDP = g.local_udp_port;
	msg.keepaliveTimer = g.keepalive_timer;
	msg.keepaliveInterval = g.keepalive_interval;
	msg.helloTimer = g.hellotime_timer;
	msg.helloInterval = g.hellotime_interval;

	write(fd, &msg, sizeof(msg));
}
