// resource_monitor_kern.c
// Replace existing kernel headers with:
#include "vmlinux.h"       // Main kernel types
#include <bpf/bpf_helpers.h>  // BPF helpers
#include <bpf/bpf_tracing.h>  // Tracing definitions
#include <linux/bpf.h>


// Define the data structures for our monitoring data
struct cpu_stat {
    __u64 cpu_time;     // Total CPU time in nanoseconds
    __u64 last_update;  // Last update timestamp
};

struct net_stat {
    __u64 rx_bytes;     // Total received bytes
    __u64 tx_bytes;     // Total transmitted bytes
};

// Maps to store our data
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, struct cpu_stat);
} cpu_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u64);
} memory_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, struct net_stat);
} network_stats SEC(".maps");

// Config map to hold target PID
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} config SEC(".maps");

// Helper function to check if this is our target PID
static inline bool is_target_pid(__u32 pid) {
    __u32 key = 0;
    __u32 *target = bpf_map_lookup_elem(&config, &key);
    
    if (!target)
        return false;
    
    if (*target == 0)  // 0 means monitor all PIDs
        return true;
    
    return pid == *target;
}

// Track CPU usage when a process is scheduled in/out
// Replace struct definitions with kernel-compatible versions
SEC("tp/sched/sched_switch")
int handle_sched_switch(void *ctx)
{
    struct trace_event_raw_sched_switch *args = ctx;
    __u32 prev_pid = args->prev_pid;
    __u32 next_pid = args->next_pid;
    
    // Update the process that's being switched out
    if (is_target_pid(prev_pid)) {
        struct cpu_stat *stat = bpf_map_lookup_elem(&cpu_stats, &prev_pid);
        if (stat && stat->last_update > 0) {
            // Calculate time spent on CPU
            stat->cpu_time += (now - stat->last_update);
            stat->last_update = 0;  // Process is no longer running
        }
    }
    
    // Set up the process that's being switched in
    if (is_target_pid(next_pid)) {
        struct cpu_stat *stat = bpf_map_lookup_elem(&cpu_stats, &next_pid);
        if (!stat) {
            // First time seeing this PID, initialize stats
            struct cpu_stat new_stat = {
                .cpu_time = 0,
                .last_update = now
            };
            bpf_map_update_elem(&cpu_stats, &next_pid, &new_stat, BPF_ANY);
        } else {
            // Update last_update timestamp
            stat->last_update = now;
        }
    }
    
    return 0;
}

// Track network packets being sent
SEC("tp/net/net_dev_xmit")
int handle_net_dev_xmit(struct trace_event_raw_net_dev_xmit *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    if (!is_target_pid(pid))
        return 0;
    
    struct net_stat *stat = bpf_map_lookup_elem(&network_stats, &pid);
    if (!stat) {
        // Initialize network stats for this PID
        struct net_stat new_stat = {
            .rx_bytes = 0,
            .tx_bytes = 0
        };
        bpf_map_update_elem(&network_stats, &pid, &new_stat, BPF_ANY);
        stat = bpf_map_lookup_elem(&network_stats, &pid);
        if (!stat)
            return 0;
    }
    
    // Add transmitted bytes
    stat->tx_bytes += ctx->len;
    
    return 0;
}

// Track network packets being received
SEC("tp/net/netif_receive_skb")
int handle_netif_receive_skb(struct trace_event_raw_netif_receive_skb *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    if (!is_target_pid(pid))
        return 0;
    
    struct net_stat *stat = bpf_map_lookup_elem(&network_stats, &pid);
    if (!stat) {
        // Initialize network stats for this PID
        struct net_stat new_stat = {
            .rx_bytes = 0,
            .tx_bytes = 0
        };
        bpf_map_update_elem(&network_stats, &pid, &new_stat, BPF_ANY);
        stat = bpf_map_lookup_elem(&network_stats, &pid);
        if (!stat)
            return 0;
    }
    
    // Add received bytes
    stat->rx_bytes += ctx->len;
    
    return 0;
}

// Clean up when a process exits
SEC("tp/sched/sched_process_exit")
int handle_process_exit(struct trace_event_raw_sched_process_template *ctx) {
    __u32 pid = ctx->pid;
    
    if (is_target_pid(pid)) {
        // Clean up our maps
        bpf_map_delete_elem(&cpu_stats, &pid);
        bpf_map_delete_elem(&memory_stats, &pid);
        bpf_map_delete_elem(&network_stats, &pid);
    }
    
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
