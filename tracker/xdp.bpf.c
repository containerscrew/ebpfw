//go:build ignore

// Required headers for eBPF and networking
#include <linux/bpf.h>         // Core BPF definitions (e.g., SEC, BPF helpers)
#include <linux/if_ether.h>    // Ethernet header definitions (e.g., ethhdr)
#include <linux/ip.h>          // IP header definitions (e.g., iphdr)
#include <linux/udp.h>         // UDP header definitions (e.g., udphdr)
#include <linux/tcp.h>         // TCP header definitions (e.g., tcphdr)
#include <linux/in.h>          // Protocol definitions (e.g., IPPROTO_UDP, IPPROTO_TCP)
#include <bpf/bpf_helpers.h>   // BPF helper macros (e.g., SEC() for section definitions)
#include <bpf/bpf_endian.h>    // BPF helper functions for endian conversion (e.g., bpf_htons())
#include <linux/version.h>     // Kernel version macros (e.g., LINUX_VERSION_CODE)

// Required license declaration for the eBPF verifier
char __license[] SEC("license") = "Dual MIT/GPL";
__u32 __version SEC("version") = LINUX_VERSION_CODE;

// Define a data structure to send to user space via perf ring buffer
struct event {
    __be32 saddr;    // Source IP address (big-endian)
    __be32 daddr;    // Destination IP address (big-endian)
    __be16 sport;    // Source port (big-endian)
    __be16 dport;    // Destination port (big-endian)
    __u8 protocol;   // Protocol type (e.g., IPPROTO_TCP or IPPROTO_UDP)
};

// Define a perf event array map to send data to user space
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY); // Map type: perf event array
} events SEC(".maps");                           // Map name: events

struct event *unused __attribute__((unused)); // Prevent "variable unused" warning

SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    // Extract pointers to the start and end of the packet data.
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)eth + sizeof(*eth) > data_end)
        return XDP_PASS;  // Pass packet if too short (can't inspect it)

    // Check if the EtherType is IPv4 (0x0800 for IPv4)
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;  // Pass non-IPv4 packets

    // Parse IP header
    struct iphdr *iph = data + sizeof(*eth);
    if ((void *)iph + sizeof(*iph) > data_end)
        return XDP_PASS;  // Pass if IP header is incomplete

    // Process only TCP or UDP packets
    __u8 protocol = iph->protocol;
    if (protocol != IPPROTO_UDP && protocol != IPPROTO_TCP)
        return XDP_PASS;  // Pass non-TCP/UDP packets

    // Initialize event structure
    struct event ev = {
        .saddr = iph->saddr,
        .daddr = iph->daddr,
        .protocol = protocol
    };

    // Parse TCP or UDP header based on protocol type
    if (protocol == IPPROTO_UDP) {
        struct udphdr *udph = (void *)iph + sizeof(*iph);
        if ((void *)udph + sizeof(*udph) > data_end)
            return XDP_PASS;  // Pass if UDP header is incomplete

        ev.sport = udph->source;
        ev.dport = udph->dest;

    } else if (protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = (void *)iph + sizeof(*iph);
        if ((void *)tcph + sizeof(*tcph) > data_end)
            return XDP_PASS;  // Pass if TCP header is incomplete

        ev.sport = tcph->source;
        ev.dport = tcph->dest;
    }

    // Send the event to user space via the perf ring buffer
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &ev, sizeof(ev));

    return XDP_PASS;  // Allow the packet to continue through the network stack
}
