#include "ldpd.h"
#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <net/route.h>
#include <sys/sysctl.h>


#define RT_BUF_SIZE 16384
#define MAX_RTSOCK_BUF (128 * 1024)

static struct event ev;
static int fd = -1;


static void prefix2mpls_fec(prefix_t *prefix, mpls_fec *fec)
{
	fec->type = MPLS_FEC_PREFIX;
	fec->u.prefix.network.type = MPLS_FAMILY_IPV4;
	fec->u.prefix.network.u.ipv4 = ntohl(prefix->prefix.s_addr);
	fec->u.prefix.length = prefix->length;
}


static int PrefixLength(struct sockaddr_in *mask, struct sockaddr_in *addr, int isHost)
{
	if (mask != NULL) {
		if(mask->sin_len == 0)
			return 0;
		if(mask->sin_addr.s_addr == 0)
			return 0;
		else
			return (33 - ffs(ntohl(mask->sin_addr.s_addr)));
	} else if(isHost)
		return 32;
	else if(addr->sin_addr.s_addr >= 0xf0000000U)	/* class E */
		return 32;
	else if(addr->sin_addr.s_addr >= 0xe0000000U)	/* class D */
		return 4;
	else if(addr->sin_addr.s_addr >= 0xc0000000U)	/* class C */
		return 24;
	else if(addr->sin_addr.s_addr >= 0x80000000U)	/* class B */
		return 16;
	else											/* class A */
		return 8;
}


static void GetAddresses(int addrs, struct sockaddr *sa, struct sockaddr **rti_info)
{
	int i;
	
#define ROUNDUP(a, size) (((a) & ((size) - 1)) ? (1 + ((a) | ((size) - 1))) : (a))

	for (i = 0; i < RTAX_MAX; i++) {
		if (addrs & (1 << i)) {
			rti_info[i] = sa; 
			sa = (struct sockaddr *)((char *)(sa) + ROUNDUP(sa->sa_len, sizeof(long)));
		} else
			rti_info[i] = NULL;
	}
}  


/*
==============
ParseRouteUpdate
==============
*/
static void ParseRouteUpdate(struct rt_msghdr *rtm)
{
	prefix_t prefix;
	struct in_addr nexthop;
	int ifindex;
	int isConnected;
	struct mpls_fec fec;
	struct mpls_nexthop ldpNexthop;
	struct sockaddr *sa, *rti_info[RTAX_MAX];
	struct sockaddr_in *sa_in;

	if(!rtm)
		return;

	sa = (struct sockaddr *)(rtm + 1);
	GetAddresses(rtm->rtm_addrs, sa, rti_info);

	if((sa = rti_info[RTAX_DST]) == NULL)
		return;

	if(rtm->rtm_errno)		 /* failed attempts... */
		return;

	if(rtm->rtm_flags & RTF_LLINFO)	/* arp cache */
		return;

#ifdef RTF_MPATH
	if(rtm->rtm_flags & RTF_MPATH)	 /* multipath */
		return;
#endif

	switch (sa->sa_family) {
	case AF_INET:
		prefix.prefix.s_addr = ((struct sockaddr_in *)sa)->sin_addr.s_addr;
		prefix.length = PrefixLength((struct sockaddr_in *)rti_info[RTAX_NETMASK], (struct sockaddr_in *)sa, rtm->rtm_flags & RTF_HOST);
		break;
	default:
		break;
	}

	ifindex = rtm->rtm_index;
	if((sa = rti_info[RTAX_GATEWAY]) != NULL)
		switch (sa->sa_family) {
		case AF_INET:
			isConnected = 0;
			nexthop.s_addr = ((struct sockaddr_in *)sa)->sin_addr.s_addr;
			break;
		case AF_LINK:
			nexthop.s_addr = 0;
			isConnected = 1;
		}

	if(prefix.prefix.s_addr == htonl(INADDR_ANY) || prefix.prefix.s_addr == htonl(INADDR_LOOPBACK))
		return;

	memset(&ldpNexthop, 0, sizeof(ldpNexthop));
	ldpNexthop.ip.type = MPLS_FAMILY_IPV4;
	ldpNexthop.ip.u.ipv4 = ntohl(nexthop.s_addr);
	ldpNexthop.type |= MPLS_NH_IP;
	ldpNexthop.distance = 10;
	ldpNexthop.metric = 10;
	ldpNexthop.attached = isConnected ? MPLS_BOOL_TRUE : MPLS_BOOL_FALSE;
	if((ldpNexthop.if_handle = Interface_FindByIndex(ifindex)))
		ldpNexthop.type |= MPLS_NH_IF;

	prefix2mpls_fec(&prefix, &fec);
	if(rtm->rtm_type == RTM_ADD || rtm->rtm_type == RTM_GET) {
		if(ldp_cfg_fec_get(ldp->config, &fec, 0) != MPLS_SUCCESS || fec.is_route == MPLS_BOOL_FALSE) {
			if(ldp_cfg_fec_set(ldp->config, &fec, LDP_CFG_ADD) != MPLS_SUCCESS)
				MPLS_ASSERT(0);
			if(ldp_cfg_fec_nexthop_get(ldp->config, &fec, &ldpNexthop, LDP_FEC_CFG_BY_INDEX) != MPLS_SUCCESS)
				if(ldp_cfg_fec_nexthop_set(ldp->config, &fec, &ldpNexthop, LDP_CFG_ADD | LDP_FEC_CFG_BY_INDEX) != MPLS_SUCCESS)
					MPLS_ASSERT(0);
		}
	} else if(rtm->rtm_type == RTM_DELETE) {
		if(ldp_cfg_fec_get(ldp->config, &fec, 0) == MPLS_SUCCESS && fec.is_route == MPLS_BOOL_TRUE) {
			if(ldp_cfg_fec_nexthop_get(ldp->config, &fec, &ldpNexthop, LDP_FEC_CFG_BY_INDEX) == MPLS_SUCCESS) {
				if(ldp_cfg_fec_nexthop_set(ldp->config, &fec, &ldpNexthop, LDP_FEC_CFG_BY_INDEX | LDP_CFG_DEL |
											LDP_FEC_NEXTHOP_CFG_BY_INDEX) != MPLS_SUCCESS)
					MPLS_ASSERT(0);
			} else
				MPLS_ASSERT(0);
			if(ldp_cfg_fec_set(ldp->config, &fec, LDP_CFG_DEL | LDP_FEC_CFG_BY_INDEX) != MPLS_SUCCESS)
				MPLS_ASSERT(0);
		} else
			MPLS_ASSERT(0);
	}
}


/*
==============
ParseInterfaceInfo
==============
*/
static void ParseInterfaceInfo(struct if_msghdr *ifm, int change)
{
	interface_t *iface;
	struct sockaddr *sa, *rti_info[RTAX_MAX];
	struct sockaddr_dl *sdl;

	sa = (struct sockaddr *)(ifm + 1);
	GetAddresses(ifm->ifm_addrs, sa, rti_info);

	sdl = NULL;
	if((sa = rti_info[RTAX_IFP]) != NULL)
		if(sa->sa_family == AF_LINK)
			sdl = (struct sockaddr_dl *)sa;

	/* Find interface by name, because it could be defined in config file, but wasn't present at ldpd startup */ 
	if(sdl && sdl->sdl_nlen)
		iface = Interface_FindByName((const char *)sdl->sdl_data);
	else
		iface = Interface_FindByIndex(ifm->ifm_index);
	if(!iface) {
		iface = Interface_Create();
		MPLS_ASSERT(iface);
	}

	if(sdl && sdl->sdl_nlen) {
		if(sdl->sdl_nlen >= sizeof(iface->name))
			memcpy(iface->name, sdl->sdl_data, sizeof(iface->name) - 1);
		else if(sdl->sdl_nlen > 0)
			memcpy(iface->name, sdl->sdl_data, sdl->sdl_nlen);
	}

	iface->index = ifm->ifm_index;
	iface->mtu = ifm->ifm_data.ifi_mtu;
	iface->systemUp = (ifm->ifm_flags & IFF_UP) &&
		(ifm->ifm_data.ifi_link_state == LINK_STATE_UP ||
		(ifm->ifm_data.ifi_link_state == LINK_STATE_UNKNOWN &&
		ifm->ifm_data.ifi_type != IFT_CARP));
}


/*
==============
ParseInterfaceAddress
==============
*/
static void ParseInterfaceAddress(struct ifa_msghdr *ifam)
{
	address_t addr;
	interface_t *iface;
	struct sockaddr *sa, *rti_info[RTAX_MAX];

	iface = Interface_FindByIndex(ifam->ifam_index);
	if(!iface)
		return;

	sa = (struct sockaddr *)(ifam + 1);
	GetAddresses(ifam->ifam_addrs, sa, rti_info);

	switch (sa->sa_family) {
	case AF_INET:
		addr.address.prefix = ((struct sockaddr_in *)rti_info[RTAX_IFA])->sin_addr;
		addr.address.length = PrefixLength((struct sockaddr_in *)rti_info[RTAX_NETMASK], (struct sockaddr_in *)rti_info[RTAX_IFA], 0);
		addr.broadcast = ((struct sockaddr_in *)rti_info[RTAX_BRD])->sin_addr;
		break;
	default:
		break;
	}

	if(ifam->ifam_type == RTM_NEWADDR)
		Interface_AddAddress(iface, &addr);
	else if(ifam->ifam_type == RTM_DELADDR)
		Interface_DelAddress(iface, &addr);
}


/*
==============
ParseInterfaceAnnounce
==============
*/
static void ParseInterfaceAnnounce(struct if_announcemsghdr *ifan)
{
	interface_t *iface;

	switch (ifan->ifan_what) {
	case IFAN_ARRIVAL:
		iface = Interface_FindByIndex(ifan->ifan_index);
		if(!iface)
			iface = Interface_Create();
		iface->index = ifan->ifan_index;
		strlcpy(iface->name, ifan->ifan_name, sizeof(iface->name));
		break;
	case IFAN_DEPARTURE:
		iface = Interface_FindByIndex(ifan->ifan_index);
		if(iface)
			Interface_Destroy(iface);
		break;
	}
}


/*
==============
ReadRoutes
==============
*/
static int ReadRoutes()
{
	int i, count;
	size_t len;
	int mib[6];
	char *buf, *next, *end;
	struct rt_msghdr *rtm;

	mib[0] = CTL_NET;
	mib[1] = AF_ROUTE;
	mib[2] = 0;
	mib[3] = AF_INET;
	mib[4] = NET_RT_DUMP;
	mib[5] = 0;

	if(sysctl(mib, 6, NULL, &len, NULL, 0) == -1) {
		fprintf(stderr, "sysctl1\n");
		return 0;
	}
	if((buf = malloc(len)) == NULL) {
		fprintf(stderr, "malloc\n");
		return 0;
	}
	if(sysctl(mib, 6, buf, &len, NULL, 0) == -1) {
		fprintf(stderr, "sysctl2\n");
		free(buf);
		return 0;
	}

	end = buf + len;
	for(next = buf; next < end; next += rtm->rtm_msglen) {
		rtm = (struct rt_msghdr *)next;
		ParseRouteUpdate(rtm);
	}

	free(buf);

	return 1;
}


/*
==============
ReadInterfaces
==============
*/
static int ReadInterfaces()
{
	int i, count;
	size_t len;
	int mib[6];
	char *buf, *next, *end;
	struct if_msghdr *ifm;
	struct sockaddr *sa, *rti_info[RTAX_MAX];
	struct sockaddr_in *sa_in;
	struct sockaddr_dl *sdl;

	mib[0] = CTL_NET;
	mib[1] = AF_ROUTE;
	mib[2] = 0;
	mib[3] = AF_INET;
	mib[4] = NET_RT_IFLIST;
	mib[5] = 0;

	if(sysctl(mib, 6, NULL, &len, NULL, 0) == -1) {
		fprintf(stderr, "sysctl1\n");
		return 0;
	}
	if((buf = malloc(len)) == NULL) {
		fprintf(stderr, "malloc\n");
		return 0;
	}
	if(sysctl(mib, 6, buf, &len, NULL, 0) == -1) {
		fprintf(stderr, "sysctl2\n");
		free(buf);
		return 0;
	}

	end = buf + len;
	for(next = buf; next < end; next += ifm->ifm_msglen) {
		ifm = (struct if_msghdr *)next;
        if(ifm->ifm_type == RTM_IFINFO)
			ParseInterfaceInfo(ifm, 0);
		else if(ifm->ifm_type == RTM_NEWADDR)
			ParseInterfaceAddress((struct ifa_msghdr *)ifm);
	}

	free(buf);

	return 1;
}


/*
==============
ProcessMessage
	dispatch kernel message
==============
*/
static void ProcessMessage(int fd, short event, void *arg)
{
	char buf[RT_BUF_SIZE];
	ssize_t n;
	char *next, *lim;
	struct rt_msghdr *rtm;
	struct if_msghdr ifm;

	if((n = read(fd, &buf, sizeof(buf))) == -1) {
		fprintf(stderr, "dispatch_rtmsg: read error");
		return;
	}

	if(n == 0) {
		fprintf(stderr, "routing socket closed");
		return;
	}

	lim = buf + n;
	for(next = buf; next < lim; next += rtm->rtm_msglen) {
		rtm = (struct rt_msghdr *)next;

		switch (rtm->rtm_type) {
		case RTM_ADD:
		case RTM_CHANGE:
		case RTM_DELETE:
			ParseRouteUpdate(rtm);
			break;
		case RTM_IFINFO:
			ParseInterfaceInfo((struct if_msghdr *)rtm, 1);
			break;
		case RTM_IFANNOUNCE:
			ParseInterfaceAnnounce((struct if_announcemsghdr *)rtm);
			break;
		case RTM_NEWADDR:
		case RTM_DELADDR:
			ParseInterfaceAddress((struct ifa_msghdr *)rtm);
			break;
		case RTM_NEWMADDR:
			break;
		case RTM_DELMADDR:
			break;
		}
	}
}


/*
==============
Kernel_Init
==============
*/
void Kernel_Init()
{
	int opt, receiveBuffer, defaultReceiveBuffer;
	socklen_t len;

	fd = socket(AF_ROUTE, SOCK_RAW, 0);
	if(fd < 0) {
		fprintf(stderr, "cannot open kernel socket\n");
		exit(1);
	}

	opt = 0;
	setsockopt(fd, SOL_SOCKET, SO_USELOOPBACK, &opt, sizeof(opt));

	len = sizeof(defaultReceiveBuffer);
	getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &defaultReceiveBuffer, &len);

	for(receiveBuffer = MAX_RTSOCK_BUF; receiveBuffer > defaultReceiveBuffer &&
		setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &receiveBuffer, sizeof(receiveBuffer)) == -1 && errno == ENOBUFS; receiveBuffer /= 2);

	ReadInterfaces();

	ReadRoutes();

	event_set(&ev, fd, EV_READ | EV_PERSIST, ProcessMessage, NULL);
	event_add(&ev, NULL);
}


/*
==============
Kernel_Shutdown
==============
*/
void Kernel_Shutdown()
{
	event_del(&ev);

	if(fd > 0)
		close(fd);
}
