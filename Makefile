TARGET = ldpd
CC = cc
OBJS = ldpd.o config.o control.o ldp.o kernel.o interface.o peer.o mpls.o \
	freebsd/mpls_fib_impl.o freebsd/mpls_ifmgr_impl.o freebsd/mpls_lock_impl.o freebsd/mpls_mm_impl.o freebsd/mpls_mpls_impl.o \
	freebsd/mpls_policy_impl.o freebsd/mpls_socket_impl.o freebsd/mpls_timer_impl.o freebsd/mpls_tree_impl.o common/mpls_compare.o \
	ldp/ldp_addr.o ldp/ldp_adj.o ldp/ldp_attr.o ldp/ldp_buf.o ldp/ldp_cfg.o ldp/ldp_entity.o ldp/ldp_fec.o \
	ldp/ldp_global.o ldp/ldp_hello.o ldp/ldp_hop.o ldp/ldp_hop_list.o ldp/ldp_if.o ldp/ldp_inet_addr.o \
	ldp/ldp_init.o ldp/ldp_inlabel.o ldp/ldp_keepalive.o ldp/ldp_label_abort.o ldp/ldp_label_mapping.o \
	ldp/ldp_label_rel_with.o ldp/ldp_label_request.o ldp/ldp_mesg.o ldp/ldp_nexthop.o ldp/ldp_nortel.o \
	ldp/ldp_notif.o ldp/ldp_outlabel.o ldp/ldp_pdu_setup.o ldp/ldp_peer.o ldp/ldp_resource.o ldp/ldp_session.o \
	ldp/ldp_state_funcs.o ldp/ldp_state_machine.o ldp/ldp_tunnel.o
CFLAGS = -g -I. -Icommon -Ifreebsd -Ildp -I/usr/local/include
LDFLAGS += -L/usr/local/lib -levent -lnetgraph

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(OBJS)

clean:
	rm -f $(TARGET) $(OBJS)

.c.o:
	$(CC) $(CFLAGS) -c $< -o $@
