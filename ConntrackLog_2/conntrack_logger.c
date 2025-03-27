#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <unistd.h>
#include <getopt.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#include <openssl/evp.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <signal.h>
#include <errno.h>

#define BUFFER_SIZE 1024

static int counter = 0;

struct callback_data {
    char *log_folder;
    int print_to_stdout;
};

/**
 * Calculate SHA-256 hash of a string.
 * @param input String to hash.
 * @param output Buffer for the hex hash (at least 65 bytes).
 */
void calculate_sha256(const char *input, char *output) {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    const EVP_MD *md = EVP_sha256();
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;

    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, input, strlen(input));
    EVP_DigestFinal_ex(mdctx, hash, &hash_len);
    EVP_MD_CTX_free(mdctx);

    for (int i = 0; i < hash_len; i++) {
        sprintf(output + (i * 2), "%02x", hash[i]);
    }
    output[hash_len * 2] = 0; // Null-terminate
}

/**
 * Ensure the log folder exists, creating it if necessary.
 * @param log_folder Path to the log folder.
 */
void ensure_log_folder_exists(const char *log_folder) {
    struct stat st = {0};
    if (stat(log_folder, &st) == -1) {
        if (mkdir(log_folder, 0700) == -1 && errno != EEXIST) {
            perror("Failed to create log directory");
        }
    }
}

/**
 * Callback to handle conntrack events and log them.
 */
static int event_cb(enum nf_conntrack_msg_type type,
                    struct nf_conntrack *ct,
                    void *data) {
    struct callback_data *cb_data = (struct callback_data *)data;
    char *log_folder = cb_data->log_folder;
    int print_to_stdout = cb_data->print_to_stdout;

    // Get nanosecond timestamp
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    long long timestamp_ns = (long long)ts.tv_sec * 1000000000LL + ts.tv_nsec;

    // Extract IPv4 addresses
    char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
    struct in_addr src_addr = { .s_addr = nfct_get_attr_u32(ct, ATTR_ORIG_IPV4_SRC) };
    struct in_addr dst_addr = { .s_addr = nfct_get_attr_u32(ct, ATTR_ORIG_IPV4_DST) };
    inet_ntop(AF_INET, &src_addr, src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &dst_addr, dst_ip, INET_ADDRSTRLEN);

    // Extract ports (default to 0 if unset)
    uint16_t src_port = nfct_attr_is_set(ct, ATTR_ORIG_PORT_SRC) ? ntohs(nfct_get_attr_u16(ct, ATTR_ORIG_PORT_SRC)) : 0;
    uint16_t dst_port = nfct_attr_is_set(ct, ATTR_ORIG_PORT_DST) ? ntohs(nfct_get_attr_u16(ct, ATTR_ORIG_PORT_DST)) : 0;

    // Calculate parent hash (connection identifier)
    char hash_input[256], parent_hash[65];
    snprintf(hash_input, sizeof(hash_input), "%s%s%u%u", src_ip, dst_ip, src_port, dst_port);
    calculate_sha256(hash_input, parent_hash);

    // Protocol
    uint8_t proto = nfct_get_attr_u8(ct, ATTR_L4PROTO);
    char protocol_str[16];
    if (proto == IPPROTO_TCP) strcpy(protocol_str, "tcp");
    else if (proto == IPPROTO_UDP) strcpy(protocol_str, "udp");
    else snprintf(protocol_str, sizeof(protocol_str), "proto %u", proto);

    // Message type
    const char *msg_type_str;
    switch (type) {
        case NFCT_T_NEW:     msg_type_str = "NEW";     break;
        case NFCT_T_UPDATE:  msg_type_str = "UPDATE";  break;
        case NFCT_T_DESTROY: msg_type_str = "DESTROY"; break;
        default:             msg_type_str = "UNKNOWN"; break;
    }

    // Timeout
    uint32_t timeout = nfct_attr_is_set(ct, ATTR_TIMEOUT) ? nfct_get_attr_u32(ct, ATTR_TIMEOUT) : 0;

    // TCP state
    const char *state_str = "N/A";
    if (proto == IPPROTO_TCP && nfct_attr_is_set(ct, ATTR_TCP_STATE)) {
        uint8_t tcp_state = nfct_get_attr_u8(ct, ATTR_TCP_STATE);
        switch (tcp_state) {
            case 0:  state_str = "NONE";        break;
            case 1:  state_str = "SYN_SENT";    break;
            case 2:  state_str = "SYN_RECV";    break;
            case 3:  state_str = "ESTABLISHED"; break;
            case 4:  state_str = "FIN_WAIT";    break;
            case 5:  state_str = "CLOSE_WAIT";  break;
            case 6:  state_str = "LAST_ACK";    break;
            case 7:  state_str = "TIME_WAIT";   break;
            case 8:  state_str = "CLOSE";       break;
            case 9:  state_str = "LISTEN";      break;
            default: state_str = "UNKNOWN";     break;
        }
    }

    // Assured status
    const char *assured_str = "";
    if (nfct_attr_is_set(ct, ATTR_STATUS)) {
        uint32_t status = nfct_get_attr_u32(ct, ATTR_STATUS);
        if (status & IPS_ASSURED) assured_str = "ASSURED";
    }

    // Calculate child hash (event-specific)
    char child_hash_input[BUFFER_SIZE], child_hash[65];
    snprintf(child_hash_input, sizeof(child_hash_input), "%lld,%s,%s,%u,%s,%s,%u,%s,%u,%s",
             timestamp_ns, msg_type_str, protocol_str, timeout, state_str,
             src_ip, src_port, dst_ip, dst_port, assured_str);
    calculate_sha256(child_hash_input, child_hash);

    // Construct log file path
    char log_file_path[256];
    snprintf(log_file_path, sizeof(log_file_path), "%s/%s.log", log_folder, parent_hash);

    // Ensure log folder exists (recreate if deleted)
    ensure_log_folder_exists(log_folder);

    // Check if log file exists
    struct stat st;
    int is_new_file = (stat(log_file_path, &st) != 0);

    // Open and write to log file
    FILE *log_file = fopen(log_file_path, "a");
    if (log_file != NULL) {
        if (is_new_file) {
            // Write CSV header if file is new or was deleted
            fprintf(log_file, "Timestamp,ParentHash,ChildHash,SrcIP,SrcPort,DstIP,DstPort,Protocol,MsgType,Timeout,State,Assured\n");
        }
        // Write log entry
        fprintf(log_file, "%lld,%s,%s,%s,%u,%s,%u,%s,%s,%u,%s,%s\n",
                timestamp_ns, parent_hash, child_hash,
                src_ip, src_port, dst_ip, dst_port,
                protocol_str, msg_type_str, timeout, state_str, assured_str);
        fclose(log_file);
    } else {
        perror("Failed to open log file");
        // Attempt to recreate folder and retry
        ensure_log_folder_exists(log_folder);
        log_file = fopen(log_file_path, "a");
        if (log_file != NULL) {
            fprintf(log_file, "Timestamp,ParentHash,ChildHash,SrcIP,SrcPort,DstIP,DstPort,Protocol,MsgType,Timeout,State,Assured\n");
            fprintf(log_file, "%lld,%s,%s,%s,%u,%s,%u,%s,%s,%u,%s,%s\n",
                    timestamp_ns, parent_hash, child_hash,
                    src_ip, src_port, dst_ip, dst_port,
                    protocol_str, msg_type_str, timeout, state_str, assured_str);
            fclose(log_file);
        } else {
            perror("Failed to open log file after retry");
        }
    }

    // Print to stdout if not daemonized
    if (print_to_stdout) {
        printf("%lld,%s,%s,%s,%u,%s,%u,%s,%s,%u,%s,%s\n",
               timestamp_ns, parent_hash, child_hash,
               src_ip, src_port, dst_ip, dst_port,
               protocol_str, msg_type_str, timeout, state_str, assured_str);
    }

    counter++;
    return NFCT_CB_CONTINUE;
}

/**
 * Print usage information.
 */
void print_help(const char *progname) {
    printf("Usage: %s [options]\n", progname);
    printf("Options:\n");
    printf("  -h, --help                Show this help message\n");
    printf("  -l, --log-folder <folder> Specify log folder (default: logs)\n");
    printf("  -d                        Daemonize the program\n");
    printf("  -k                        Kill all running daemons\n");
}

/**
 * Kill all running daemons except the current process.
 */
void kill_all_daemons() {
    pid_t current_pid = getpid();
    FILE *fp = popen("pidof conntrack_logger", "r");
    if (fp == NULL) {
        perror("Failed to run pidof");
        return;
    }

    char pid_str[16];
    while (fscanf(fp, "%s", pid_str) == 1) {
        pid_t pid = atoi(pid_str);
        if (pid != current_pid) {
            if (kill(pid, SIGTERM) == -1) {
                perror("Failed to kill process");
            }
        }
    }
    pclose(fp);
}
int main(int argc, char *argv[]) {
    int opt;
    char *log_folder = "logs"; // Default log folder
    char abs_log_folder[PATH_MAX]; // Buffer for absolute path
    int daemonize = 0;
    int kill_daemons = 0;

    static struct option long_options[] = {
        {"help", no_argument, 0, 'h'},
        {"log-folder", required_argument, 0, 'l'},
        {"daemonize", no_argument, 0, 'd'},
        {"kill", no_argument, 0, 'k'},
        {0, 0, 0, 0}
    };

    // Parse command-line options
    while ((opt = getopt_long(argc, argv, "hl:dk", long_options, NULL)) != -1) {
        switch (opt) {
        case 'h':
            print_help(argv[0]);
            return 0;
        case 'l':
            log_folder = optarg;
            break;
        case 'd':
            daemonize = 1;
            break;
        case 'k':
            kill_daemons = 1;
            break;
        default:
            fprintf(stderr, "Invalid option\n");
            print_help(argv[0]);
            return 1;
        }
    }

    if (kill_daemons) {
        kill_all_daemons();
        printf("Killed all running daemons\n");
        return 0;
    }

    // Convert log_folder to absolute path
    if (realpath(log_folder, abs_log_folder) == NULL) {
        // If realpath fails (e.g., folder doesn't exist yet), construct absolute path manually
        if (log_folder[0] != '/') {
            char cwd[PATH_MAX];
            if (getcwd(cwd, sizeof(cwd)) == NULL) {
                perror("Failed to get current working directory");
                return 1;
            }
            snprintf(abs_log_folder, sizeof(abs_log_folder), "%s/%s", cwd, log_folder);
        } else {
            strncpy(abs_log_folder, log_folder, sizeof(abs_log_folder));
            abs_log_folder[sizeof(abs_log_folder) - 1] = '\0';
        }
    }

    // Initial log folder creation with absolute path
    ensure_log_folder_exists(abs_log_folder);

    if (daemonize) {
        printf("Logging to folder: %s\n", abs_log_folder);
        if (daemon(0, 0) == -1) {
            perror("Failed to daemonize");
            return 1;
        }
    }

    struct callback_data cb_data = {abs_log_folder, !daemonize};
    struct nfct_handle *h = nfct_open(CONNTRACK, NF_NETLINK_CONNTRACK_NEW |
                                      NF_NETLINK_CONNTRACK_UPDATE |
                                      NF_NETLINK_CONNTRACK_DESTROY);
    if (!h) {
        perror("Failed to open conntrack handle");
        return 1;
    }

    nfct_callback_register(h, NFCT_T_ALL, event_cb, &cb_data);
    int ret = nfct_catch(h);
    if (ret == -1) {
        perror("Failed to catch conntrack events");
    }

    nfct_close(h);
    return ret;
}