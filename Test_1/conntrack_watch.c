/* conntrack_watch.c */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <ncurses.h>
#include <openssl/evp.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>

#define MAX_BUCKETS 262144
#define REFRESH_INTERVAL 1
#define LOG_FILE "log.txt"
#define HASH_SUFFIX_LEN 8
#define INET_ADDRSTRLEN 16
#define UNIQUE_ID_MAX 32

typedef struct {
    uint32_t ct_id;
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    uint16_t src_port;
    uint16_t dst_port;
    char proto[8];
    char unique_id[UNIQUE_ID_MAX];
    char hash_suffix[HASH_SUFFIX_LEN + 1];
    uint64_t update_count;
    struct timespec last_seen;
} ConnectionGroup;

static ConnectionGroup buckets[MAX_BUCKETS];
static FILE *logfile = NULL;
static int show_local_traffic = 0;

static int is_local_ip(const char *ip_str) {
    struct in_addr ip;
    if (inet_pton(AF_INET, ip_str, &ip) != 1) return 0;
    return (ntohl(ip.s_addr) >> 24) == 0x7F; // 127.0.0.0/8
}

static void sha256_truncated(const char *data, size_t len, char output[HASH_SUFFIX_LEN + 1]) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;
    
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, data, len);
    EVP_DigestFinal_ex(ctx, hash, &hash_len);
    
    for(int i = 0; i < HASH_SUFFIX_LEN; i++)
        sprintf(output + i*2, "%02x", hash[hash_len - (HASH_SUFFIX_LEN/2) + (i/2)] >> (4 * (i % 2)) & 0x0f);
    output[HASH_SUFFIX_LEN] = '\0';
    EVP_MD_CTX_free(ctx);
}

static void get_protocol_identifier(const struct nf_conntrack *ct, char *unique_id) {
    const uint8_t proto = nfct_get_attr_u8(ct, ATTR_ORIG_L4PROTO);
    
    switch(proto) {
        case IPPROTO_TCP: {
            uint32_t state = nfct_get_attr_u32(ct, ATTR_TCP_STATE);
            snprintf(unique_id, UNIQUE_ID_MAX, "STATE:%u", state);
            break;
        }
        case IPPROTO_UDP: {
            uint32_t counter = nfct_get_attr_u32(ct, ATTR_ORIG_COUNTER_PACKETS);
            snprintf(unique_id, UNIQUE_ID_MAX, "PKTS:%u", counter);
            break;
        }
        case IPPROTO_ICMP: {
            snprintf(unique_id, UNIQUE_ID_MAX, "ICMP");
            break;
        }
        default:
            snprintf(unique_id, UNIQUE_ID_MAX, "N/A");
    }
}

static void process_connection(const struct nf_conntrack *ct, 
                              struct timespec *ts,
                              ConnectionGroup *cg) {
    struct in_addr src_addr = { .s_addr = nfct_get_attr_u32(ct, ATTR_ORIG_IPV4_SRC) };
    struct in_addr dst_addr = { .s_addr = nfct_get_attr_u32(ct, ATTR_ORIG_IPV4_DST) };
    
    inet_ntop(AF_INET, &src_addr, cg->src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &dst_addr, cg->dst_ip, INET_ADDRSTRLEN);

    cg->src_port = ntohs(nfct_get_attr_u16(ct, ATTR_ORIG_PORT_SRC));
    cg->dst_port = ntohs(nfct_get_attr_u16(ct, ATTR_ORIG_PORT_DST));

    const uint8_t proto = nfct_get_attr_u8(ct, ATTR_ORIG_L4PROTO);
    const char *proto_str = "OTHER";
    switch(proto) {
        case IPPROTO_TCP: proto_str = "TCP"; break;
        case IPPROTO_UDP: proto_str = "UDP"; break;
        case IPPROTO_ICMP: proto_str = "ICMP"; break;
    }
    strncpy(cg->proto, proto_str, sizeof(cg->proto)-1);

    get_protocol_identifier(ct, cg->unique_id);

    char hash_input[256];
    snprintf(hash_input, sizeof(hash_input), "%s|%s|%d|%d|%s|%s",
            cg->src_ip, cg->dst_ip, cg->src_port, cg->dst_port, 
            cg->proto, cg->unique_id);
    sha256_truncated(hash_input, strlen(hash_input), cg->hash_suffix);

    cg->update_count++;
    cg->last_seen = *ts;
}

static int process_entry(enum nf_conntrack_msg_type type,
                        struct nf_conntrack *ct,
                        void *data) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    
    const uint32_t ct_id = nfct_get_attr_u32(ct, ATTR_ID);
    const uint32_t bucket = ct_id % MAX_BUCKETS;
    
    if(buckets[bucket].ct_id != ct_id) {
        memset(&buckets[bucket], 0, sizeof(ConnectionGroup));
        buckets[bucket].ct_id = ct_id;
    }

    process_connection(ct, &ts, &buckets[bucket]);
    
    char buf[256];
    nfct_snprintf(buf, sizeof(buf), ct, NFCT_T_UNKNOWN, NFCT_O_DEFAULT, 0);
    fprintf(logfile, "[%ld.%09ld] %s\n", ts.tv_sec, ts.tv_nsec, buf);
    fflush(logfile);
    
    return NFCT_CB_CONTINUE;
}

static void update_display() {
    clear();
    printw("%-15s %-15s %-6s %-6s %-5s %-12s %-8s %-10s %s\n",
           "Source", "Destination", "SPort", "DPort", "Proto", "Identifier", 
           "Updates", "HashTail", "Last Activity");
    
    for(int i = 0; i < MAX_BUCKETS; i++) {
        if(buckets[i].ct_id == 0) continue;

        int src_local = is_local_ip(buckets[i].src_ip);
        int dst_local = is_local_ip(buckets[i].dst_ip);
        if (show_local_traffic != (src_local && dst_local)) continue;

        printw("%-15s %-15s %-6d %-6d %-5s %-12s %-8lu %-10s %ld.%09ld\n",
               buckets[i].src_ip,
               buckets[i].dst_ip,
               buckets[i].src_port,
               buckets[i].dst_port,
               buckets[i].proto,
               buckets[i].unique_id,
               buckets[i].update_count,
               buckets[i].hash_suffix,
               buckets[i].last_seen.tv_sec,
               buckets[i].last_seen.tv_nsec);
    }
    refresh();
}

int main(int argc, char *argv[]) {
    if (argc == 3 && !strcmp(argv[1], "-traffic") && !strcmp(argv[2], "local")) {
        show_local_traffic = 1;
    }

    logfile = fopen(LOG_FILE, "a");
    if (!logfile) {
        perror("logfile");
        return EXIT_FAILURE;
    }

    struct nfct_handle *h = nfct_open(CONNTRACK, 0);
    if (!h) {
        fclose(logfile);
        perror("nfct_open");
        return EXIT_FAILURE;
    }

    initscr();
    cbreak();
    noecho();
    curs_set(0);
    timeout(0);
    keypad(stdscr, TRUE);

    nfct_callback_register(h, NFCT_T_ALL, process_entry, NULL);

    while (1) {
        erase();
        nfct_query(h, NFCT_Q_DUMP, &(uint32_t){AF_INET});
        update_display();
        
        if (getch() == 'q') break;
        napms(REFRESH_INTERVAL * 1000);
    }

    endwin();
    nfct_close(h);
    fclose(logfile);
    return EXIT_SUCCESS;
}

