#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#include <openssl/evp.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <sys/types.h>

#define BUFFER_SIZE 1024

static int counter = 0;

// TCP states (for reference)
enum tcp_state {
    TCP_CONNTRACK_NONE = 0,
    TCP_CONNTRACK_SYN_SENT = 1,
    TCP_CONNTRACK_SYN_RECV = 2,
    TCP_CONNTRACK_ESTABLISHED = 3,
    TCP_CONNTRACK_FIN_WAIT = 4,
    TCP_CONNTRACK_CLOSE_WAIT = 5,
    TCP_CONNTRACK_LAST_ACK = 6,
    TCP_CONNTRACK_TIME_WAIT = 7,
    TCP_CONNTRACK_CLOSE = 8,
    TCP_CONNTRACK_LISTEN = 9,
    TCP_CONNTRACK_MAX = 10
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
 * Callback to handle conntrack events and log them.
 */
static int event_cb(enum nf_conntrack_msg_type type,
                    struct nf_conntrack *ct,
                    void *data) {
    char full_timestamp[64];
    char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
    uint16_t src_port, dst_port;
    char parent_hash[65], child_hash[65];
    char hash_input[256], child_hash_input[BUFFER_SIZE];

    // Get timestamp with microseconds
    struct timeval tv;
    gettimeofday(&tv, NULL);
    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&tv.tv_sec));
    snprintf(full_timestamp, sizeof(full_timestamp), "%s.%06ld", timestamp, tv.tv_usec);

    // Extract IPv4 addresses
    struct in_addr src_addr = { .s_addr = nfct_get_attr_u32(ct, ATTR_ORIG_IPV4_SRC) };
    struct in_addr dst_addr = { .s_addr = nfct_get_attr_u32(ct, ATTR_ORIG_IPV4_DST) };
    inet_ntop(AF_INET, &src_addr, src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &dst_addr, dst_ip, INET_ADDRSTRLEN);

    // Extract ports (default to 0 if unset)
    src_port = nfct_attr_is_set(ct, ATTR_ORIG_PORT_SRC) ? ntohs(nfct_get_attr_u16(ct, ATTR_ORIG_PORT_SRC)) : 0;
    dst_port = nfct_attr_is_set(ct, ATTR_ORIG_PORT_DST) ? ntohs(nfct_get_attr_u16(ct, ATTR_ORIG_PORT_DST)) : 0;

    // Calculate parent hash (connection identifier)
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
            case TCP_CONNTRACK_NONE:        state_str = "NONE";        break;
            case TCP_CONNTRACK_SYN_SENT:    state_str = "SYN_SENT";    break;
            case TCP_CONNTRACK_SYN_RECV:    state_str = "SYN_RECV";    break;
            case TCP_CONNTRACK_ESTABLISHED: state_str = "ESTABLISHED"; break;
            case TCP_CONNTRACK_FIN_WAIT:    state_str = "FIN_WAIT";    break;
            case TCP_CONNTRACK_CLOSE_WAIT:  state_str = "CLOSE_WAIT";  break;
            case TCP_CONNTRACK_LAST_ACK:    state_str = "LAST_ACK";    break;
            case TCP_CONNTRACK_TIME_WAIT:   state_str = "TIME_WAIT";   break;
            case TCP_CONNTRACK_CLOSE:       state_str = "CLOSE";       break;
            case TCP_CONNTRACK_LISTEN:      state_str = "LISTEN";      break;
            default:                        state_str = "UNKNOWN";     break;
        }
    }

    // Assured status
    const char *assured_str = "";
    if (nfct_attr_is_set(ct, ATTR_STATUS)) {
        uint32_t status = nfct_get_attr_u32(ct, ATTR_STATUS);
        if (status & IPS_ASSURED) assured_str = "ASSURED";
    }

    // Calculate child hash (event-specific)
    snprintf(child_hash_input, sizeof(child_hash_input), "%s,%s,%s,%u,%s,%s,%u,%s,%u,%s",
             full_timestamp, msg_type_str, protocol_str, timeout, state_str,
             src_ip, src_port, dst_ip, dst_port, assured_str);
    calculate_sha256(child_hash_input, child_hash);

    // Construct log file path
    char log_file_path[256];
    snprintf(log_file_path, sizeof(log_file_path), "logs/%s.log", parent_hash);

    // Check if file exists (for header)
    struct stat st;
    int is_new_file = (stat(log_file_path, &st) != 0);

    // Open and write to log file
    FILE *log_file = fopen(log_file_path, "a");
    if (log_file != NULL) {
        if (is_new_file) {
            // Write CSV header
            fprintf(log_file, "Timestamp,ParentHash,ChildHash,SrcIP,SrcPort,DstIP,DstPort,Protocol,MsgType,Timeout,State,Assured\n");
        }
        // Write log entry
        fprintf(log_file, "%s,%s,%s,%s,%u,%s,%u,%s,%s,%u,%s,%s\n",
                full_timestamp, parent_hash, child_hash,
                src_ip, src_port, dst_ip, dst_port,
                protocol_str, msg_type_str, timeout, state_str, assured_str);
        fclose(log_file);
    } else {
        perror("Failed to open log file");
    }

    counter++;
    return NFCT_CB_CONTINUE;
}

int main(void) {
    // Create "logs" folder if it doesn’t exist
    struct stat st = {0};
    if (stat("logs", &st) == -1) {
        if (mkdir("logs", 0700) == -1) {
            perror("Failed to create logs directory");
            return -1;
        }
    }

    // Initialize conntrack handle
    struct nfct_handle *h = nfct_open(CONNTRACK, NF_NETLINK_CONNTRACK_NEW |
                                                 NF_NETLINK_CONNTRACK_UPDATE |
                                                 NF_NETLINK_CONNTRACK_DESTROY);
    if (!h) {
        perror("nfct_open");
        return -1;
    }

    // Register callback
    nfct_callback_register(h, NFCT_T_ALL, event_cb, NULL);

    // Capture events
    int ret = nfct_catch(h);
    printf("Received %d events\n", counter);

    nfct_close(h);
    return ret;
}