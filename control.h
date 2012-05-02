#ifndef _CONTROL_H_
#define _CONTROL_H_

#define LDPD_SOCK "/var/run/ldpd.sock"

enum commandType_t {
	COMMAND_SHOW_LDP,
	COMMAND_SHOW_LDP_FEC,
	COMMAND_SHOW_LDP_NEIGHBORS,
	COMMAND_SHOW_LDP_DATABASE,
	COMMAND_SHOW_FORWARDING
};

typedef struct msgNexthop_s {
	uint32_t	index;
	uint32_t	address;
	uint32_t	attached;
} msgNexthop_t;

typedef struct msgFEC_s {
	uint32_t		index;
	uint32_t		prefix;
	uint32_t		length;
	uint32_t		count;
} msgFEC_t;

typedef struct msgNeighbor_s {
	uint32_t	id;
	uint16_t	labelspace;
	uint32_t	localAddress;
	uint16_t	localPort;
	uint32_t	remoteAddress;
	uint16_t	remotePort;
	uint8_t		state;
	uint32_t	received;
	uint32_t	sent;
	uint8_t		mode;
	uint32_t	timeUp;
	char		name[60];
	uint32_t	numAddresses;
} msgNeighbor_t;

typedef enum {
	LABEL_REMOTE,
	LABEL_LOCAL,
	LABEL_ATTR
} labelType_t;

typedef struct msgLabel_s {
	uint32_t	prefix;
	uint8_t		length;
	uint8_t		isSession;
	uint8_t		isAdj;
	uint32_t	remoteAddress;
	uint16_t	labelspace;
	uint8_t		isIngress;
	uint8_t		type;
	int32_t		label;
	uint8_t		state;
} msgLabel_t;

typedef struct msgLDP_s {
	uint32_t	id;
	uint8_t		state;
	uint32_t	transportAddr;
	uint8_t		controlMode;
	uint8_t		repairMode;
	uint8_t		propogateRelease;
	uint8_t		labelMerge;
	uint8_t		retentionMode;
	uint8_t		loopMode;
	uint8_t		ttlLessDomain;
	uint16_t	localTCP;
	uint16_t	localUDP;
	uint32_t	keepaliveTimer;
	uint32_t	keepaliveInterval;
	uint32_t	helloTimer;
	uint32_t	helloInterval;
} msgLDP_t;

typedef struct msgLIBEntry_s {
	uint8_t		type;
	int32_t		local;
	int32_t		outgoing;
	uint32_t	prefix;
	uint8_t		length;
	char		iface[32];
	uint32_t	nexthop;
} msgLIBEntry_t;

#endif
