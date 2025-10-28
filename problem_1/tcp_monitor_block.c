#include <uapi/linux/bpf.h>
#include <uapi/linux/ptrace.h>
#include <linux/tcp.h>
#include <net/sock.h>
#include <net/inet_sock.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <linux/tcp.h>
#include <uapi/linux/pkt_cls.h>
#include <linux/fs.h>
#include <linux/uaccess.h>


typedef struct
{
    u32 src_ip;
    u16 src_port;
    u32 dst_ip;
    u16 dst_port;
    u32 pid;
    u8 tcp_flags;
    char comm[TASK_COMM_LEN];
} full_packet;


BPF_HASH(block_list, u16, u8);
BPF_PERF_OUTPUT(blocked_events);


#ifndef tcp_flag_byte
#define tcp_flag_byte(th) (((u_int8_t *)th)[13])
#endif

static __always_inline int tcp_header_bound_check(struct tcphdr* tcp, void* data_end)
{
    if ((void*)tcp + sizeof(*tcp) > data_end)
    {
        return -1;
    }

    return 0;
}

int handle_ingress(struct __sk_buff* ctx)
{
    void* data_end = (void*)(long)ctx->data_end;
    void* data = (void*)(long)ctx->data;
    struct ethhdr* eth = data;
    struct iphdr* ip = data + sizeof(*eth);
    struct tcphdr* tcp;

    // length check 
    if (data + sizeof(*eth) + sizeof(*ip) > data_end)
    {
        return TC_ACT_OK;
    }

    // we are only interested in eth
    if (eth->h_proto != htons(ETH_P_IP))
    {
        return TC_ACT_SHOT;
    }

    // we are only interested in tcp:ipv4
    if (ip->protocol != IPPROTO_TCP)
    {
        return TC_ACT_OK;
    }

    tcp = (void*)ip + sizeof(*ip);
    if (tcp_header_bound_check(tcp, data_end))
    {
        return TC_ACT_OK;
    }

    u8 tcpflags = ((u_int8_t*)tcp)[13];
    u16 src_port = bpf_ntohs(tcp->source);
    u16 dst_port = bpf_ntohs(tcp->dest);


    full_packet pkt = {
        .src_ip = ip->saddr;
        .src_port = src_port;
        .dst_ip = ip->daddr;
        .dst_port = dst_port;
        .tcp_flags = tcpflags;
    };

    u8* blocked = block_list.lookup(&dst_port);
    if (blocked) {
        blocked_events.perf_submit(ctx, &pkt, sizeof(packet_value));
        return TC_ACT_SHOT;
    }

    return TC_ACT_OK;
}
