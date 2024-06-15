//go:build ignore

// 部分的にコピーしてる
// https://eunomia.dev/tutorials/20-tc/#writing-ebpf-programs

// 以下あたりの定義も拝借. ethhdr/iphdr など
// https://github.com/cilium/ebpf/blob/b8dc0ee25417ce7cd4a6feb48be42c0615ee9043/examples/headers/common.h#L4

// #include <vmlinux.h>
// #include "common.h"
#include <linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define TC_ACT_OK 0
#define TC_ACT_SHOT 2

#define ETH_P_IPv4 0x0800
#define ETH_P_ARP 0x0806

#define IP_P_ICMP 0x01
#define IP_P_TCP 0x06
#define IP_P_UDP 0x17

// Wireshark観察する限りはそうだが要fix
#define TCP_FLG_RST_ACK 0x29
// bpfのlog観察する限りはそうだが要fix
#define TCP_FLG_RST 0x8

#define MAX_ENTRIES 64
#define AF_INET		2

struct ethhdr {
	unsigned char h_dest[6];
	unsigned char h_source[6];
	__be16 h_proto;
};

struct iphdr {
	__u8 ihl: 4;
	__u8 version: 4;
	__u8 tos;
	__be16 tot_len;
	__be16 id;
	__be16 frag_off;
	__u8 ttl;
	__u8 protocol;
	__sum16 check;
	__be32 saddr;
	__be32 daddr;
};

// https://www.infraexpert.com/study/tcpip8.html
struct tcphdr {
	__be16 sport;
	__be16 dport;
    __be32 sequence;
    __be32 acknowladge;
    __u8 offset: 4;
    __u8 yoyaku: 3;
    __be16 controlflg: 9;
    __be16 window;
    __be16 checksum;
    __be16 urg;
};

char __license[] SEC("license") = "Dual MIT/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY); 
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} pkt_count SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY); 
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} arp_pkt_count SEC(".maps");

// __sk_buff について
// https://medium.com/@c0ngwang/understanding-struct-sk-buff-730cf847a722

SEC("tc")
int control_egress(struct __sk_buff *skb)
{
    void *data_end = (void *)(__u64)skb->data_end;
    void *data = (void *)(__u64)skb->data;
    struct ethhdr *eth;
    struct iphdr *iph;
    struct tcphdr *tcph;

    __u32 key    = 0; 
    __u64 *count = bpf_map_lookup_elem(&pkt_count, &key);
    __u64 *arp_count = bpf_map_lookup_elem(&arp_pkt_count, &key);

    // bpf_printk("proto: %x", skb->protocol);
    // bpf_printk("data: %x", skb->data);
    // bpf_printk("data_end: %x", skb->data_end);

    if (count) { 
        __sync_fetch_and_add(count, 1); 
    }

    eth = data;
    if ((void *)(eth + 1) > data_end) {
        bpf_printk("a");
        return TC_ACT_OK;
    }

    iph = (struct iphdr *)(eth + 1);
    if ((void *)(iph + 1) > data_end) {
        bpf_printk("b");
        return TC_ACT_OK;
    }

    if (bpf_ntohs(eth->h_proto) == ETH_P_ARP) {
        bpf_printk("Ether Type: ARP");
        if (arp_count) { 
            __sync_fetch_and_add(arp_count, 1); 
        }
        // return TC_ACT_SHOT;
        return TC_ACT_OK;
    }

    if (bpf_ntohs(eth->h_proto) == ETH_P_IPv4) {
        bpf_printk("Ether Type  : IP");
        bpf_printk("    tot_len : %d", bpf_ntohs(iph->tot_len));
        bpf_printk("    ttl     : %d", iph->ttl);
        bpf_printk("    protocol: %x", iph->protocol);
        bpf_printk("    dst     : %x", bpf_ntohl(iph->daddr));
        bpf_printk("    src     : %x", bpf_ntohl(iph->saddr));

        if (iph->protocol == IP_P_ICMP) {
            bpf_printk("ICMP");
            return TC_ACT_OK;
        }
        if (iph->protocol == IP_P_UDP) {
            bpf_printk("UDP");
            return TC_ACT_OK;
        }
        if (iph->protocol == IP_P_TCP) {
            bpf_printk("TCP");

            tcph = (struct tcphdr *)(iph + 1);
            if ((void *)(tcph + 1) > data_end) {
                bpf_printk("c");
                return TC_ACT_OK;
            }

            bpf_printk("    sport     : %x", bpf_ntohs(tcph->sport));
            bpf_printk("    dport     : %x", bpf_ntohs(tcph->dport));
            bpf_printk("    controlflg: %x", bpf_ntohs(tcph->controlflg));
            bpf_printk("    controlflg: %x", tcph->controlflg);

            if (tcph->controlflg == TCP_FLG_RST_ACK) {
                bpf_printk("TCP RST-ACK");
                return TC_ACT_SHOT;
                // return TC_ACT_OK;
            }
            if (tcph->controlflg == TCP_FLG_RST) {
                bpf_printk("TCP RST");
                return TC_ACT_SHOT;
                // return TC_ACT_OK;
            }

            return TC_ACT_OK;
        }

        return TC_ACT_OK;
    }

    return TC_ACT_OK;
}