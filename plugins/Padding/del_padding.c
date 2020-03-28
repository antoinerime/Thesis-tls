//
// Created by antoine on 28.03.20.
//

#include "utils.h"

int del_padding (ptls_t *tls)
{
    ptls_context_t *ctx = (ptls_context_t *) ptls_get(tls, PTLS_CTX);
    ptls_buffer_t *buffer = (ptls_buffer_t *) ptls_get_ctx(tls, CTX_PROTO_OP_INPUT, 0);
    int padding = 0;
    get_padding(ctx, &padding);
    uint64_t base = ptls_get_buff(buffer, BUFF_BASE);
    uint64_t off = ptls_get_buff(buffer, BUFF_OFF);
    my_memcpy(base, base + padding, padding);
    ptls_set_buff(buffer, BUFF_OFF, off - padding, 0);
    set_padding(ctx, 0);

    return 0;
}
