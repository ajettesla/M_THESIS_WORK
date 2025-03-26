#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>

static int callback(enum nf_conntrack_msg_type type __attribute__((unused)),
                   struct nfconntrack *ct,
                   void *data __attribute__((unused)))
{
    char buf[1024];
    
    nfct_snprintf(buf, sizeof(buf), ct,
        NFCT_T_UNKNOWN, NFCT_O_DEFAULT, NFCT_OF_SHOW_LAYER3);
    printf("%s\n", buf);

    return NFCT_CB_CONTINUE;
}

int main(void)
{
    struct nfct_handle *h;
    int ret, family = AF_INET;

    h = nfct_open(CONNTRACK, 0);
    if (!h) {
        perror("nfct_open");
        return EXIT_FAILURE;
    }

    nfct_callback_register(h, NFCT_T_ALL, callback, NULL);

    /* Use basic dump with family specification */
    ret = nfct_query(h, NFCT_Q_DUMP, &family);
    if (ret == -1) {
        fprintf(stderr, "Error %d during dump: %s\n", 
            ret, strerror(errno));
        nfct_close(h);
        return EXIT_FAILURE;
    }

    nfct_close(h);
    return EXIT_SUCCESS;
}

