#!/usr/bin/python
#
# tc_perf_event.py  Output skb and meta data through perf event
#
# Copyright (c) 2016-present, Facebook, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

from bcc import BPF
import ctypes as ct
import pyroute2
import socket

bpf_program = """
#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <uapi/linux/pkt_cls.h>

struct packet_t {
    u32 src_ip;
    u32 dst_ip;
    u32 src_port;
    u32 dst_port;
    u32 protocol;
    u32 mark;
};

BPF_PERF_OUTPUT(skb_events);

int mark_filter(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    struct packet_t pkt = {};

    if (eth->h_proto == htons(ETH_P_IP)) {
        struct iphdr *ip = data + sizeof(struct ethhdr);
        if ((void *)(ip + 1) > data_end)
            return TC_ACT_OK;

        if (1 || skb->mark == 0xb) {
            pkt.src_ip = ip->saddr;
            pkt.dst_ip = ip->daddr;
            pkt.protocol = ip->protocol;
            pkt.mark = skb->mark;
            if (ip->protocol == IPPROTO_TCP) {
                struct tcphdr *tcp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
                if ((void *)(tcp + 1) > data_end)
                    return TC_ACT_OK;
                pkt.src_port = tcp->source;
                pkt.dst_port = tcp->dest;
            } else if (ip->protocol == IPPROTO_UDP) {
                struct udphdr *udp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
                if ((void *)(udp + 1) > data_end)
                    return TC_ACT_OK;
                pkt.src_port = udp->source;
                pkt.dst_port = udp->dest;
            } else {
            }
            //skb_events.perf_submit_skb(skb, skb->len, &pkt, sizeof(struct packet_t));
            skb_events.perf_submit_skb(skb, skb->len, &pkt.mark, sizeof(pkt.mark));
        }
    }

    return TC_ACT_OK;
}
"""

bpf_txt = """
#include <uapi/linux/if_ether.h>
#include <uapi/linux/in6.h>
#include <uapi/linux/ipv6.h>
#include <uapi/linux/pkt_cls.h>
#include <uapi/linux/bpf.h>

struct packet_t {
    u32 src_ip;
    u32 dst_ip;
    u32 src_port;
    u32 dst_port;
    u32 protocol;
    u32 mark;
};

BPF_PERF_OUTPUT(skb_events);

struct eth_hdr {
	unsigned char   h_dest[ETH_ALEN];
	unsigned char   h_source[ETH_ALEN];
	unsigned short  h_proto;
};

int handle_egress(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct eth_hdr *eth = data;
	struct ipv6hdr *ip6h = data + sizeof(*eth);
	u32 magic = 0xfaceb00c;

	/* single length check */
	if (data + sizeof(*eth) + sizeof(*ip6h) > data_end)
		return TC_ACT_OK;

    struct packet_t pkt = {};
    pkt.mark = 0xb;
    pkt.src_ip = 111;
	if (eth->h_proto == htons(ETH_P_IPV6) &&
	    ip6h->nexthdr == IPPROTO_ICMPV6)
	        skb_events.perf_submit_skb(skb, skb->len, &pkt, sizeof(pkt));

	return TC_ACT_OK;
}"""

def print_skb_event(cpu, data, size):
    class SkbEvent(ct.Structure):
        _fields_ = [("src_ip", ct.c_uint32),
                    ("dst_ip", ct.c_uint32),
                    ("src_port", ct.c_uint32),
                    ("dst_port", ct.c_uint32),
                    ("protocol", ct.c_uint32),
                    ("mark", ct.c_uint32),
                    ("raw", ct.c_ubyte * (size - 6*ct.sizeof(ct.c_uint32)))]
    #  class SkbEvent(ct.Structure):
        #  _fields_ =  [ ("magic", ct.c_uint32),
                      #  ("raw", ct.c_ubyte * (size - ct.sizeof(ct.c_uint32))) ]

    skb_event = ct.cast(data, ct.POINTER(SkbEvent)).contents
    print(f'skb_event.src_ip: {skb_event.src_ip}')
    icmp_type = int(skb_event.raw[54])

    # Only print for echo request
    if icmp_type == 128:
        src_ip = bytes(bytearray(skb_event.raw[22:38]))
        dst_ip = bytes(bytearray(skb_event.raw[38:54]))
        print("%-3s %-32s %-12s 0x%08x" %
              (cpu, socket.inet_ntop(socket.AF_INET6, src_ip),
               socket.inet_ntop(socket.AF_INET6, dst_ip),
               skb_event.mark))

try:
    b = BPF(text=bpf_txt)
    fn = b.load_func("handle_egress", BPF.SCHED_CLS)

    ipr = pyroute2.IPRoute()
    ipr.link("add", ifname="me", kind="veth", peer="you")
    me = ipr.link_lookup(ifname="me")[0]
    you = ipr.link_lookup(ifname="you")[0]
    for idx in (me, you):
        ipr.link('set', index=idx, state='up')

    ipr.tc("add", "clsact", me)
    ipr.tc("add-filter", "bpf", me, ":1", fd=fn.fd, name=fn.name,
           parent="ffff:fff3", classid=1, direct_action=True)

    b["skb_events"].open_perf_buffer(print_skb_event)
    print('Try: "ping6 ff02::1%me"\n')
    print("%-3s %-32s %-12s %-10s" % ("CPU", "SRC IP", "DST IP", "Magic"))
    try:
        while True:
            b.perf_buffer_poll()
    except KeyboardInterrupt:
        pass
finally:
    if "me" in locals(): ipr.link("del", index=me)
