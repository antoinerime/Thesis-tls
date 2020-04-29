//
// Created by antoine on 28.04.20.
//
#include "utils.h"

#define PTLS_STATE_SERVER_POST_HANDSHAKE 15

int select_operation (ptls_t *tls)
{
    uint64_t maxfd = ptls_get_ctx(tls, CTX_PROTO_OP_INPUT, 0);
    fd_set *readfds = (fd_set *) ptls_get_ctx(tls, CTX_PROTO_OP_INPUT, 1);
    fd_set *writefds = (fd_set *) ptls_get_ctx(tls, CTX_PROTO_OP_INPUT, 2);
    fd_set *exceptfds = (fd_set *) ptls_get_ctx(tls, CTX_PROTO_OP_INPUT, 3);
    struct timeval *timeout = (struct timeval *) ptls_get_ctx(tls, CTX_PROTO_OP_INPUT, 4);
    ptls_buffer_t *sendbuf = (ptls_buffer_t *) ptls_get_ctx(tls, CTX_PROTO_OP_INPUT, 5);

    uint64_t off = ptls_get_buff(sendbuf, BUFF_OFF);
    int state = ptls_get(tls, PTLS_STATE);
    if (state < PTLS_STATE_SERVER_POST_HANDSHAKE || off) {
        uint64_t *args[5] = {maxfd, readfds, writefds, exceptfds, timeout};
        return help_plugin_select(args);
    }
    else
    {
        ptls_context_t *ctx = ptls_get(tls, PTLS_CTX);
        struct timeval prev_timeout;
        prev_timeout.tv_sec = 0;
        prev_timeout.tv_usec = 0;
        get_timeval(ctx, &prev_timeout);

        uint64_t *args[5] = {maxfd, readfds, writefds, exceptfds, &prev_timeout};
        int ret = help_plugin_select(args);
        int timer = 0;
        int allocate = 0;
        int output = 0;
        get_timer(ctx, &timer);
        if (prev_timeout.tv_sec == 0 && prev_timeout.tv_usec == 0 && timer < MAX_TIMER)
        {
            int inlen = 0;
            char *input = get_opaque_data(ctx, 10, sizeof(char), &allocate);
            uint64_t  ptls_traffic_protection_enc = ptls_get(tls, PTLS_TRAFFIC_ENC);
            proto_op_arg_t args[5];
            args[0] = sendbuf;
            args[1] = PTLS_CONTENT_TYPE_APPDATA;
            args[2] = input;
            args[3] = inlen;
            args[4] = ptls_traffic_protection_enc;
            param_id_t param = -1;
            proto_op_params_t pp = {.param = &param, .caller_is_intern = false, .inputc = 5, .inputv = args, .outputv = &output};
            helper_plugin_run_proto_op(tls, &pp, "buffer_push_encrypted_records");
            set_padding(ctx, PTLS_MAX_ENCRYPTED_RECORD_SIZE);
            // Reset timeout
            prev_timeout.tv_sec = 0;
            prev_timeout.tv_usec = BUFLO_TIMER;
        }
        set_timeval(ctx, prev_timeout);
    }
}