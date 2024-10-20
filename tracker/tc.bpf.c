//go:build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/pkt_cls.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char __license[] SEC("license") = "Dual MIT/GPL";

/* Define a hash map for tracking established connections */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);  // Use a 64-bit key combining src and dest IP and ports
    __type(value, __u8); // Value is just a flag to indicate an active connection
    __uint(max_entries, 1024); // Limit to 1024 connections
} established_conns SEC(".maps");

/* Define a map to store unauthorized attempts */
struct unauthorized_entry {
    __u32 src_ip;
    __u32 dest_ip;
    __u32 count;  // Counter for number of unauthorized attempts
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, __u32); // Use source IP as the key for simplicity
    __type(value, struct unauthorized_entry);
    __uint(max_entries, 256); // Limit to 256 entries
} unauthorized_attempts SEC(".maps");

/* Helper function to combine IP and port into a 64-bit key */
static __always_inline __u64 get_connection_key(__u32 ip1, __u16 port1, __u32 ip2, __u16 port2) {
    return ((__u64)ip1 << 32) | ((__u64)port1 << 16) | ((__u64)ip2 << 0) | ((__u64)port2);
}

/* eBPF program to track outgoing connections */
SEC("tc")
int egress_prog_func(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return TC_ACT_OK;

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end || iph->protocol != IPPROTO_TCP)
        return TC_ACT_OK;

    struct tcphdr *tcph = (void *)(iph + 1);
    if ((void *)(tcph + 1) > data_end)
        return TC_ACT_OK;

    // Handle new outgoing SYN packets
    if (tcph->syn && !tcph->ack) {
        __u64 conn_key = get_connection_key(iph->saddr, tcph->source, iph->daddr, tcph->dest);
        __u8 value = 1;
        bpf_map_update_elem(&established_conns, &conn_key, &value, BPF_ANY);
    }

    // Handle connection termination
    if (tcph->fin || (tcph->rst && tcph->ack)) {
        __u64 conn_key = get_connection_key(iph->saddr, tcph->source, iph->daddr, tcph->dest);
        bpf_map_delete_elem(&established_conns, &conn_key);
    }

    return TC_ACT_OK;
}

/* eBPF program to filter incoming connections */
SEC("tc")
int ingress_prog_func(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return TC_ACT_OK;

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end || iph->protocol != IPPROTO_TCP)
        return TC_ACT_OK;

    struct tcphdr *tcph = (void *)(iph + 1);
    if ((void *)(tcph + 1) > data_end)
        return TC_ACT_OK;

    __u64 conn_key = get_connection_key(iph->daddr, tcph->dest, iph->saddr, tcph->source);

    // Check if this is part of an established session
    __u8 *value = bpf_map_lookup_elem(&established_conns, &conn_key);
    if (value) {
        return TC_ACT_OK;
    }

    // Update the map with unauthorized attempt information
    __u32 src_ip = iph->saddr;
    struct unauthorized_entry *entry = bpf_map_lookup_elem(&unauthorized_attempts, &src_ip);
    if (entry) {
        // Increment the count for existing entries
        __sync_fetch_and_add(&entry->count, 1);
    } else {
        // Add a new entry
        struct unauthorized_entry new_entry = {};
        new_entry.src_ip = iph->saddr;
        new_entry.dest_ip = iph->daddr;
        new_entry.count = 1;
        bpf_map_update_elem(&unauthorized_attempts, &src_ip, &new_entry, BPF_ANY);
    }

    return TC_ACT_SHOT; // Drop unauthorized packet
}
