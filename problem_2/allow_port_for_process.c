#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/in.h>
#include <linux/sched.h>

#define ALLOWED_PORT 4040
#define TARGET_PROCESS "myprocess"

BPF_PERF_OUTPUT(blocked_events);

struct blocked_packet {
    u32 pid;
    u32 src_ip;
    u32 dst_ip;
    u16 src_port;
    u16 dst_port;
    char comm[TASK_COMM_LEN];
};

int handle_egress(struct __sk_buff* skb)
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

    // Get current process name
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));

    // Only filter packets from TARGET_PROCESS
    if (__builtin_memcmp(comm, TARGET_PROCESS, sizeof(TARGET_PROCESS) - 1) == 0) {
        u16 src_port = bpf_ntohs(tcp->src);

        if (src_port != ALLOWED_PORT) {
            blocked_packet pkt = {
                .pid = bpf_get_current_pid_tgid() >> 32;
                .src_ip = ip->saddr;
                .src_port = src_port;
                .dst_ip = ip->daddr;
                .dst_port = dst_port;
            };
            __builtin_memcpy(pkt.comm, comm, sizeof(comm));

            blocked_events.perf_submit(skb, &pkt, sizeof(pkt));

            return TC_ACT_SHOT;
        }
    }

    return TC_ACT_OK;
}
