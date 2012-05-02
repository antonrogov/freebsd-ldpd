#include "ldpd.h"


struct mpls_socket {
	int				fd;
	int				type;
	struct event	read;
	struct event	write;
	void			*extra;
};


static void _sockaddr2mpls_dest(struct sockaddr *addr, mpls_dest *dest)
{
	dest->addr.type = MPLS_FAMILY_IPV4;
	dest->port = ntohs(((struct sockaddr_in *)addr)->sin_port);
	dest->addr.u.ipv4 = ntohl(((struct sockaddr_in *)addr)->sin_addr.s_addr);
}


static void _mpls_dest2sockaddr(const mpls_dest *dest, struct sockaddr *addr)
{
	memset(addr, 0, sizeof(struct sockaddr));
	addr->sa_family = AF_INET;
	((struct sockaddr_in *)addr)->sin_port = htons(dest->port);
	((struct sockaddr_in *)addr)->sin_addr.s_addr = htonl(dest->addr.u.ipv4);
}


static void *getsockopt_cmsg_data(struct msghdr *msgh, int level, int type)
{
	struct cmsghdr *cmsg;
	void *ptr;

	ptr = NULL;
	for(cmsg = CMSG_FIRSTHDR(msgh); cmsg; cmsg = CMSG_NXTHDR(msgh, cmsg))
		if(cmsg->cmsg_level == level && cmsg->cmsg_type == type)
			return (ptr = CMSG_DATA(cmsg));

	return NULL;
}


static void socket_read_handler(int fd, short event, void *arg)
{
	struct mpls_socket *socket;

	socket = (struct mpls_socket *)arg;
	if(!socket)
		return;

	switch(socket->type) {
	case MPLS_SOCKET_TCP_DATA:
		ldp_event(ldp->config, socket, socket->extra, LDP_EVENT_TCP_DATA);
		break;
	case MPLS_SOCKET_TCP_LISTEN:
		ldp_event(ldp->config, socket, socket->extra, LDP_EVENT_TCP_LISTEN);
		break;
	case MPLS_SOCKET_UDP_DATA:
		ldp_event(ldp->config, socket, socket->extra, LDP_EVENT_UDP_DATA);
		break;
	default:
		MPLS_ASSERT(0);
	}
}


static void socket_write_handler(int fd, short event, void *arg)
{
	struct mpls_socket *socket;

    socket = (struct mpls_socket *)arg;
	if(!socket)
		return;

	switch(socket->type) {
	case MPLS_SOCKET_TCP_CONNECT:
		ldp_event(ldp->config, socket, socket->extra, LDP_EVENT_TCP_CONNECT);
		break;
	default:
		MPLS_ASSERT(0);
	}
}


mpls_socket_mgr_handle mpls_socket_mgr_open(mpls_instance_handle user_data)
{
	return 0xdeadbeef;
}


void mpls_socket_mgr_close(mpls_socket_mgr_handle handle)
{
}


void mpls_socket_close(mpls_socket_mgr_handle handle, mpls_socket_handle socket)
{
	if(socket) {
		close(socket->fd);
		mpls_free(socket);
	}
}


mpls_socket_handle mpls_socket_create_tcp(mpls_socket_mgr_handle handle)
{
	struct mpls_socket *sock;

	sock = mpls_malloc(sizeof(struct mpls_socket));
	if(!sock)
		return NULL;

	memset(sock, 0, sizeof(struct mpls_socket));
	sock->fd = socket(AF_INET, SOCK_STREAM, 0);
	MPLS_ASSERT(sock->fd > -1);

	return sock;
}


mpls_socket_handle mpls_socket_create_udp(mpls_socket_mgr_handle handle)
{
	struct mpls_socket *sock;
	ssize_t opt;
	size_t optlen;

	sock = mpls_malloc(sizeof(struct mpls_socket));
	if(!sock)
		return NULL;

	memset(sock, 0, sizeof(struct mpls_socket));
	sock->fd = socket(AF_INET, SOCK_DGRAM, 0);
	MPLS_ASSERT(sock->fd > -1);

	opt = 1;
	optlen = sizeof(opt);
	if(setsockopt(sock->fd, IPPROTO_IP, IP_RECVIF, &opt, optlen) < 0) {
		perror("IP_RECVIF");
		mpls_free(sock);
		return NULL;
	}

	return sock;
}


mpls_socket_handle mpls_socket_create_raw(mpls_socket_mgr_handle handle, int proto)
{
	struct mpls_socket *sock;
	u_char opt;
	size_t optlen;

	sock = mpls_malloc(sizeof(struct mpls_socket));
	memset(sock, 0, sizeof(struct mpls_socket));
	sock->fd = socket(AF_INET, SOCK_RAW, proto);
	MPLS_ASSERT(sock->fd > -1);

	opt = 1;
	optlen = sizeof(opt);
	if(setsockopt(sock->fd, IPPROTO_IP, IP_RECVDSTADDR, &opt, optlen) < 0) {
		perror("PKTINFO");
		mpls_free(sock);
		return NULL;
	}

	return sock;
}


mpls_socket_handle mpls_socket_tcp_accept(mpls_socket_mgr_handle handle, mpls_socket_handle socket, mpls_dest *from)
{
	struct mpls_socket *sock;
	struct sockaddr addr;
	unsigned int size;

	sock = mpls_malloc(sizeof(struct mpls_socket));
	size = sizeof(addr);
	if((sock->fd = accept(socket->fd, &addr, &size)) < 0) {
		mpls_free(sock);
		return NULL;
	}

	_sockaddr2mpls_dest(&addr, from);

	return sock;
}


mpls_return_enum mpls_socket_bind(mpls_socket_mgr_handle handle, mpls_socket_handle socket, const mpls_dest *local)
{
	struct sockaddr addr;

	_mpls_dest2sockaddr(local, &addr);

	if(bind(socket->fd, &addr, sizeof(struct sockaddr_in)) < 0) {
		perror("bind");
		return MPLS_FAILURE;
	}

	return MPLS_SUCCESS;
}


mpls_return_enum mpls_socket_tcp_listen(mpls_socket_mgr_handle handle, mpls_socket_handle socket, int depth)
{
	if(listen(socket->fd, depth) < 0)
		return MPLS_FAILURE;

	return MPLS_SUCCESS;
}


mpls_return_enum mpls_socket_tcp_connect(mpls_socket_mgr_handle handle, mpls_socket_handle socket, const mpls_dest *to)
{
	struct sockaddr addr;

	if(!to)
		return MPLS_FAILURE;

	_mpls_dest2sockaddr(to, &addr);

	if(connect(socket->fd, &addr, sizeof(struct sockaddr)) < 0) {
		if(errno == EINPROGRESS)
			return MPLS_NON_BLOCKING;

		if(errno == EALREADY)
			return MPLS_SUCCESS;

		perror("connect");
		return MPLS_FAILURE;
	}

	return MPLS_SUCCESS;
}


mpls_return_enum mpls_socket_connect_status(mpls_socket_mgr_handle handle, mpls_socket_handle socket)
{
	int opt;
	unsigned int optlen;

	opt = 1;
	optlen = sizeof(opt);
	if(getsockopt(socket->fd, SOL_SOCKET, SO_ERROR, &opt, &optlen) < 0) {
		perror("getsockopt");
		return MPLS_FAILURE;
	}
	if(!opt)
		return MPLS_SUCCESS;

	return MPLS_NON_BLOCKING;
}


int mpls_socket_get_errno(const mpls_socket_mgr_handle handle, mpls_socket_handle socket)
{
	return errno;
}


mpls_return_enum mpls_socket_options(mpls_socket_mgr_handle handle, mpls_socket_handle socket, uint32_t flag)
{
	int opt;
	unsigned int optlen;

	opt = 1;
	optlen = sizeof(opt);

	if(flag & MPLS_SOCKOP_REUSE) {
		if(setsockopt(socket->fd, SOL_SOCKET, SO_REUSEADDR, &opt, optlen) < 0)
			return MPLS_FAILURE;
	}
	if(flag & MPLS_SOCKOP_NONBLOCK) {
		if(fcntl(socket->fd, F_SETFL, O_NONBLOCK) < 0)
			return MPLS_FAILURE;
	}
/*FIXME	if(flag & MPLS_SOCKOP_ROUTERALERT) {
		if(setsockopt(socket->fd, sol_ip, IP_ROUTER_ALERT, &opt, optlen) < 0) {
			return MPLS_FAILURE;
	}*/
	if(flag & MPLS_SOCKOP_HDRINCL) {
		if(setsockopt(socket->fd, IPPROTO_IP, IP_HDRINCL, &opt, optlen) < 0)
			return MPLS_FAILURE;
	}

	return MPLS_SUCCESS;
}


mpls_return_enum mpls_socket_multicast_options(mpls_socket_mgr_handle handle, mpls_socket_handle socket, int ttl, int loop)
{
	u_char opt;
	unsigned int optlen;

	opt = ttl;
	optlen = sizeof(opt);
	if (setsockopt(socket->fd, IPPROTO_IP, IP_MULTICAST_TTL, &opt, optlen) < 0)
		return MPLS_FAILURE;

	opt = loop;
	if(setsockopt(socket->fd, IPPROTO_IP, IP_MULTICAST_LOOP, &opt, optlen) < 0)
		return MPLS_FAILURE;

	return MPLS_SUCCESS;
}


mpls_return_enum mpls_socket_multicast_if_tx(mpls_socket_mgr_handle handle, mpls_socket_handle socket, const mpls_if_handle iface)
{
	struct in_addr addr;

	if(!iface)
		addr.s_addr = ntohl(INADDR_ANY);
	else
		addr.s_addr = Interface_GetAddress(iface);

	if(setsockopt(socket->fd, IPPROTO_IP, IP_MULTICAST_IF, &addr, sizeof(addr)) < 0)
		return MPLS_FAILURE;

	return MPLS_SUCCESS;
}


mpls_return_enum mpls_socket_multicast_if_join(mpls_socket_mgr_handle handle, mpls_socket_handle socket, const mpls_if_handle iface,
												const mpls_inet_addr *mult)
{
	struct ip_mreq mreq;

	if(!iface) {
		mreq.imr_multiaddr.s_addr = ntohl(mult->u.ipv4);
		mreq.imr_interface.s_addr = ntohl(INADDR_ANY);
	} else {
		mreq.imr_multiaddr.s_addr = ntohl(mult->u.ipv4);
		mreq.imr_interface.s_addr = Interface_GetAddress(iface);
	}

	if(setsockopt(socket->fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0)
		return MPLS_FAILURE;

	return MPLS_SUCCESS;
}


void mpls_socket_multicast_if_drop(mpls_socket_mgr_handle handle, mpls_socket_handle socket, const mpls_if_handle iface,
									const mpls_inet_addr *mult)
{
	struct ip_mreq mreq;

	if(!iface) {
		mreq.imr_multiaddr.s_addr = ntohl(mult->u.ipv4);
		mreq.imr_interface.s_addr = ntohl(INADDR_ANY);
	} else {
		mreq.imr_multiaddr.s_addr = ntohl(mult->u.ipv4);
		mreq.imr_interface.s_addr = Interface_GetAddress(iface);
	}

	if(setsockopt(socket->fd, IPPROTO_IP, IP_DROP_MEMBERSHIP, &mreq, sizeof(mreq)) < 0)
		perror("multicast drop membership");
}


mpls_return_enum mpls_socket_readlist_add(mpls_socket_mgr_handle handle, mpls_socket_handle socket, void *extra, mpls_socket_enum type)
{
	socket->type = type;
	socket->extra = extra;
	MPLS_ASSERT(socket && (socket->fd > -1));
	event_set(&socket->read, socket->fd, EV_READ | EV_PERSIST, socket_read_handler, socket);
	if(event_add(&socket->read, NULL) == -1)
		return MPLS_FAILURE;

	return MPLS_SUCCESS;
}


void mpls_socket_readlist_del(mpls_socket_mgr_handle handle, mpls_socket_handle socket)
{
	if(socket)
		event_del(&socket->read);
}


mpls_return_enum mpls_socket_writelist_add(mpls_socket_mgr_handle handle, mpls_socket_handle socket, void *extra, mpls_socket_enum type)
{
	socket->type = type;
	socket->extra = extra;
	MPLS_ASSERT(socket && (socket->fd > -1));
	event_set(&socket->write, socket->fd, EV_WRITE | EV_PERSIST, socket_write_handler, socket);
	if(event_add(&socket->write, NULL) == -1)
		return MPLS_FAILURE;

	return MPLS_SUCCESS;
}


void mpls_socket_writelist_del(mpls_socket_mgr_handle handle, mpls_socket_handle socket)
{
	if (socket)
		event_del(&socket->write);
}


int mpls_socket_tcp_read(mpls_socket_mgr_handle handle, mpls_socket_handle socket, uint8_t *buffer, int size)
{
	int ret;

	ret = read(socket->fd, buffer, size);
	if(ret < 0 && errno != EAGAIN) {
		perror("mpls_socket_tcp_read");
		return 0;
	}

	return ret;
}


int mpls_socket_tcp_write(mpls_socket_mgr_handle handle, mpls_socket_handle socket, uint8_t *buffer, int size)
{
	return write(socket->fd, buffer, size);
}


int mpls_socket_udp_sendto(mpls_socket_mgr_handle handle, mpls_socket_handle socket, uint8_t *buffer, int size, const mpls_dest *to)
{
	struct sockaddr addr;

	_mpls_dest2sockaddr(to, &addr);

	return sendto(socket->fd, buffer, size, 0, &addr, sizeof(struct sockaddr));
}


int mpls_socket_udp_recvfrom(mpls_socket_mgr_handle handle, mpls_socket_handle socket, uint8_t *buffer, int size, mpls_dest *from)
{
	int ret;
	struct sockaddr addr;
	struct iovec iov;
	struct cmsghdr *cmsg;
	struct sockaddr_dl *sdl;
	char buf[sizeof(struct cmsghdr) + sizeof(struct sockaddr_dl)];
	struct msghdr msg = {
		.msg_name = &addr, .msg_namelen = sizeof(struct sockaddr),
		.msg_iov = &iov, .msg_iovlen = 1,
		.msg_control = buf, .msg_controllen = sizeof(buf),
		.msg_flags = 0
	};

	iov.iov_base = buffer;
	iov.iov_len = size;

	ret = recvmsg(socket->fd, &msg, 0);
	if(ret < 0 && errno != EAGAIN)
		return 0;

	_sockaddr2mpls_dest(&addr, from);

//	struct in_addr *i = (struct in_addr *)getsockopt_cmsg_data(&msg, IPPROTO_IP, IP_RECVDSTADDR);

//	sdl = (struct sockaddr_dl *)getsockopt_cmsg_data(&msg, IPPROTO_IP, IP_RECVIF);
//	from->if_handle = sdl ? Interface_FindByIndex(sdl->sdl_index) : NULL;

	from->if_handle = NULL;
	cmsg = CMSG_FIRSTHDR(&msg);
	if(cmsg && cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_RECVIF) {
		sdl = (struct sockaddr_dl *)CMSG_DATA(cmsg);
		from->if_handle = (sdl) ? Interface_FindByIndex(sdl->sdl_index) : NULL;
	}

	return ret;
}


mpls_return_enum mpls_socket_get_local_name(mpls_socket_mgr_handle handle, mpls_socket_handle socket, mpls_dest *name)
{
	struct sockaddr addr;
	unsigned int size;

	size = sizeof(addr);
	if(getsockname(socket->fd, &addr, &size) == -1)
		return MPLS_FAILURE;

	_sockaddr2mpls_dest(&addr, name);

	return MPLS_SUCCESS;
}


mpls_return_enum mpls_socket_get_remote_name(mpls_socket_mgr_handle handle, mpls_socket_handle socket, mpls_dest *name)
{
	struct sockaddr addr;
	unsigned int size;

	size = sizeof(addr);
	if(getpeername(socket->fd, &addr, &size) == -1)
		return MPLS_FAILURE;

	_sockaddr2mpls_dest(&addr, name);

	return MPLS_SUCCESS;
}
