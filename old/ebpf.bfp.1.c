// Required headers for eBPF and networking
#include <linux/bpf.h>         // Core BPF definitions (e.g., SEC, BPF helpers)
#include <linux/if_ether.h>    // Ethernet header definitions (e.g., ethhdr)
#include <linux/ip.h>          // IP header definitions (e.g., iphdr)
#include <linux/tcp.h>         // TCP header definitions (e.g., tcphdr)
#include <linux/udp.h>         // UDP header definitions (e.g., udphdr)
#include <linux/in.h>          // Protocols (e.g., IPPROTO_TCP, IPPROTO_UDP)
#include <bpf/bpf_helpers.h>   // BPF helper macros (e.g., SEC() for section definitions)
#include <bpf/bpf_endian.h>    // BPF helper functions for endian conversion (e.g., bpf_htons())

// This function is an eBPF program that will be attached to an XDP hook
// The XDP hook runs at the earliest possible point in the packet processing pipeline
SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    // Extract pointers to the start and end of the packet data.
    // 'ctx' provides metadata about the packet, including where the data starts and ends.
    void *data = (void *)(long)ctx->data;           // Start of the packet
    void *data_end = (void *)(long)ctx->data_end;   // End of the packet

    // Parse Ethernet header (14 bytes in total for standard Ethernet frame)
    // The Ethernet header contains information like source MAC, destination MAC, and the EtherType (protocol)
    struct ethhdr *eth = data;
    if ((void *)eth + sizeof(*eth) > data_end)      // Ensure that the packet has enough data for an Ethernet header
        return XDP_PASS;                            // If the packet is too short, pass it up the stack (don't process it)

    // Check if the EtherType is IPv4 (0x0800 for IPv4)
    if (eth->h_proto != bpf_htons(ETH_P_IP))        // bpf_htons() converts the EtherType to network byte order
        return XDP_PASS;                            // If it's not an IPv4 packet, pass it up the stack

    // Parse IP header (20 bytes for standard IPv4 header)
    struct iphdr *iph = data + sizeof(*eth);        // Move past the Ethernet header to reach the IP header
    if ((void *)iph + sizeof(*iph) > data_end)      // Ensure the packet has enough data for an IP header
        return XDP_PASS;                            // If the packet is too short, pass it up the stack

    // Extract the source and destination IP addresses from the IP header
    __be32 src_ip = iph->saddr;                     // Source IP address (32-bit value in network byte order)
    __be32 dest_ip = iph->daddr;                    // Destination IP address (32-bit value in network byte order)

    // Check the IP protocol field to determine if the packet is UDP or TCP
    if (iph->protocol == IPPROTO_UDP) {             // If the protocol is UDP (17)
        // Parse the UDP header (8 bytes in total)
        struct udphdr *udph = (void *)iph + sizeof(*iph); // UDP header starts after the IP header
        if ((void *)udph + sizeof(*udph) > data_end)      // Ensure the packet has enough data for a UDP header
            return XDP_PASS;                              // If the packet is too short, pass it up the stack

        // Extract source and destination ports from the UDP header (16-bit values in network byte order)
        __u16 src_port = bpf_ntohs(udph->source);   // bpf_ntohs() converts from network byte order to host byte order
        __u16 dest_port = bpf_ntohs(udph->dest);    // Destination port

        // Print IP addresses and ports (converted to dotted decimal format for IPs)
        bpf_printk("UDP src_ip: %d.%d.%d.%d, dest_ip: %d.%d.%d.%d, src_port: %d, dest_port: %d\n",
                   (src_ip & 0xFF),                 // Extract first byte of source IP
                   (src_ip >> 8) & 0xFF,            // Extract second byte of source IP
                   (src_ip >> 16) & 0xFF,           // Extract third byte of source IP
                   (src_ip >> 24) & 0xFF,           // Extract fourth byte of source IP
                   (dest_ip & 0xFF),                // Extract first byte of destination IP
                   (dest_ip >> 8) & 0xFF,           // Extract second byte of destination IP
                   (dest_ip >> 16) & 0xFF,          // Extract third byte of destination IP
                   (dest_ip >> 24) & 0xFF,          // Extract fourth byte of destination IP
                   src_port, dest_port);            // Print source and destination ports
    }

    // Return XDP_PASS to allow the packet to continue through the network stack
    return XDP_PASS;
}

// Licensing information, required by the BPF verifier
// The GPL license allows this eBPF program to be loaded into the kernel
char _license[] SEC("license") = "GPL";

