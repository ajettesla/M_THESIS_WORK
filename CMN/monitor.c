// resource_monitor_user.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <errno.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
// Add to top of ebpf_program.c
#include <stdbool.h>   // Fixes 'bool', 'true', 'false' errors
#include <linux/sched.h>  // For sched_switch/sched_process_exit structs
#include <linux/netdevice.h> // For net_dev_xmit/netif_receive_skb structs


// Define our data structures (same as in kernel program)
struct cpu_stat {
    __u64 cpu_time;     // Total CPU time in nanoseconds
    __u64 last_update;  // Last update timestamp
};

struct net_stat {
    __u64 rx_bytes;     // Total received bytes
    __u64 tx_bytes;     // Total transmitted bytes
};

// Global variables
static int running = 1;
static struct bpf_object *obj = NULL;

// Signal handler for graceful shutdown
static void int_handler(int sig) {
    running = 0;
}

// Helper function to get process memory usage from /proc
static __u64 get_process_memory(__u32 pid) {
    char path[64];
    FILE *f;
    __u64 mem = 0;
    unsigned long vm_size, vm_rss;
    
    snprintf(path, sizeof(path), "/proc/%u/statm", pid);
    f = fopen(path, "r");
    if (!f)
        return 0;
        
    if (fscanf(f, "%lu %lu", &vm_size, &vm_rss) == 2) {
        // Convert to bytes (page size * resident pages)
        mem = (__u64)vm_rss * sysconf(_SC_PAGESIZE);
    }
    
    fclose(f);
    return mem;
}

// Helper function to check if a process exists
static int process_exists(__u32 pid) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%u", pid);
    return access(path, F_OK) == 0;
}

int main(int argc, char **argv) {
    int err = 0;
    int cpu_map_fd, mem_map_fd, net_map_fd, config_map_fd;
    __u32 pid;
    
    // Parse command line arguments
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <pid>\n", argv[0]);
        return 1;
    }
    
    pid = (__u32)atoi(argv[1]);
    if (pid <= 0) {
        fprintf(stderr, "Invalid PID: %s\n", argv[1]);
        return 1;
    }
    
    // Check if the process exists
    if (!process_exists(pid)) {
        fprintf(stderr, "Process %u does not exist\n", pid);
        return 1;
    }
    
    // Set up signal handler
    signal(SIGINT, int_handler);
    signal(SIGTERM, int_handler);
    
    // Load and verify BPF program
    obj = bpf_object__open_file("resource_monitor_kern.o", NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Failed to open BPF object file\n");
        return 1;
    }
    
    // Load the BPF program into the kernel
    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "Failed to load BPF object: %d\n", err);
        goto cleanup;
    }
    
    // Get file descriptors for maps
    cpu_map_fd = bpf_object__find_map_fd_by_name(obj, "cpu_stats");
    mem_map_fd = bpf_object__find_map_fd_by_name(obj, "memory_stats");
    net_map_fd = bpf_object__find_map_fd_by_name(obj, "network_stats");
    config_map_fd = bpf_object__find_map_fd_by_name(obj, "config");
    
    if (cpu_map_fd < 0 || mem_map_fd < 0 || net_map_fd < 0 || config_map_fd < 0) {
        fprintf(stderr, "Failed to find BPF maps\n");
        goto cleanup;
    }
    
    // Set the target PID in the config map
    __u32 key = 0;
    err = bpf_map_update_elem(config_map_fd, &key, &pid, BPF_ANY);
    if (err) {
        fprintf(stderr, "Failed to update config map: %d\n", err);
        goto cleanup;
    }
    
    // Attach BPF programs to tracepoints
    struct bpf_program *prog;
    bpf_object__for_each_program(prog, obj) {
        const char *prog_name = bpf_program__name(prog);
        struct bpf_link *link;
        
        link = bpf_program__attach(prog);
        if (libbpf_get_error(link)) {
            fprintf(stderr, "Failed to attach program '%s'\n", prog_name);
            err = -1;
            goto cleanup;
        }
    }
    
    printf("Monitoring resources for PID %u. Press Ctrl+C to stop.\n", pid);
    
    // Main loop: poll maps and print data
    while (running) {
        // Check if process still exists
        if (!process_exists(pid)) {
            fprintf(stderr, "Process %u has terminated\n", pid);
            break;
        }
        
        // Get current memory usage from /proc and update map
        __u64 mem_bytes = get_process_memory(pid);
        bpf_map_update_elem(mem_map_fd, &pid, &mem_bytes, BPF_ANY);
        
        // Read CPU statistics
        struct cpu_stat cpu_data = {0};
        bpf_map_lookup_elem(cpu_map_fd, &pid, &cpu_data);
        
        // Read network statistics
        struct net_stat net_data = {0};
        bpf_map_lookup_elem(net_map_fd, &pid, &net_data);
        
        // Clear screen and print statistics
        printf("\033[H\033[J");  // Clear terminal
        printf("Resource Monitor for PID %u\n", pid);
        printf("--------------------------------\n");
        printf("CPU Time:   %llu ns (%.2f s)\n", 
               cpu_data.cpu_time, 
               (double)cpu_data.cpu_time / 1000000000.0);
        printf("Memory:     %llu bytes (%.2f MB)\n", 
               mem_bytes, 
               (double)mem_bytes / (1024 * 1024));
        printf("Network RX: %llu bytes (%.2f KB)\n", 
               net_data.rx_bytes, 
               (double)net_data.rx_bytes / 1024);
        printf("Network TX: %llu bytes (%.2f KB)\n", 
               net_data.tx_bytes, 
               (double)net_data.tx_bytes / 1024);
        
        // Sleep for a second before updating again
        sleep(1);
    }
    
cleanup:
    if (obj) {
        bpf_object__close(obj);
    }
    
    return err != 0;
}
