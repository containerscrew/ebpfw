//go:build ignore

// Required headers for eBPF and networking
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/version.h>

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

// Define a map to store allowed ports
struct {
    __uint(type, BPF_MAP_TYPE_HASH);    // Define map type as a hash map
    __type(key, __be16);                // Use port numbers as keys (big-endian)
    __type(value, __u8);                // Use an unsigned 8-bit value as a flag
    __uint(max_entries, 1024);          // Allow up to 1024 entries
} allowed_ports SEC(".maps");           // Name the map 'allowed_ports'

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
        return XDP_DROP;  // Drop packet if too short

    // Check if the EtherType is IPv4 (0x0800 for IPv4)
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_DROP;  // Drop non-IPv4 packets

    // Parse IP header
    struct iphdr *iph = data + sizeof(*eth);
    if ((void *)iph + sizeof(*iph) > data_end)
        return XDP_DROP;  // Drop if IP header is incomplete

    // Process only TCP or UDP packets
    __u8 protocol = iph->protocol;
    if (protocol != IPPROTO_UDP && protocol != IPPROTO_TCP)
        return XDP_DROP;  // Drop non-TCP/UDP packets

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
            return XDP_DROP;  // Drop if UDP header is incomplete

        ev.sport = udph->source;
        ev.dport = udph->dest;

        // Check if the destination port is allowed
        __u8 *allowed_port = bpf_map_lookup_elem(&allowed_ports, &udph->dest);
        if (!allowed_port) {
            return XDP_DROP;  // Drop if the port is not allowed
        }

    } else if (protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = (void *)iph + sizeof(*iph);
        if ((void *)tcph + sizeof(*tcph) > data_end)
            return XDP_DROP;  // Drop if TCP header is incomplete

        ev.sport = tcph->source;
        ev.dport = tcph->dest;

        // Check if the destination port is allowed
        __u8 *allowed_port = bpf_map_lookup_elem(&allowed_ports, &tcph->dest);
        if (!allowed_port) {
            return XDP_DROP;  // Drop if the port is not allowed
        }
    }

    // Send the event to user space via the perf ring buffer
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &ev, sizeof(ev));

    return XDP_PASS;  // Allow the packet to continue through the network stack
}
