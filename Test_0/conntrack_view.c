/* conntrack_view.c */
#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#include <libmnl/libmnl.h>

static int callback(
    enum nf_conntrack_msg_type type __attribute__((unused)),
    struct nf_conntrack *ct,
    void *data __attribute__((unused))
) {
    char buf[4096];
    nfct_snprintf(buf, sizeof(buf), ct, 
                NFCT_T_UNKNOWN, 
                NFCT_O_DEFAULT, 
                NFCT_OF_SHOW_LAYER3 | NFCT_OF_TIMESTAMP);
    printf("%s\n", buf);
    return NFCT_CB_CONTINUE;
}

int main(void) {
    struct nfct_handle *h;
    int ret;
    uint32_t family = AF_INET;

    h = nfct_open(CONNTRACK, 0);
    if (!h) {
        perror("nfct_open");
        return EXIT_FAILURE;
    }

    nfct_callback_register(h, NFCT_T_ALL, callback, NULL);
    
    ret = nfct_query(h, NFCT_Q_DUMP, &family);
    if (ret == -1) {
        perror("nfct_query");
        nfct_close(h);
        return EXIT_FAILURE;
    }

    nfct_close(h);
    return EXIT_SUCCESS;
}

