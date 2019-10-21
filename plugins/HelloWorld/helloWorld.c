//
// Created by antoine on 02.10.19.
//
#include <stdio.h>
#include "picotls/picotls_struct.h"
#include "picotls.h"
#include "picotls/getset.h"

int hello_word(ptls_t *tls)
{
    uint32_t is_serv = (uint32_t) ptls_get_field(tls, PTLS_IS_SRV);
    if (is_serv)
    {

        help_printf_str("I am a server");
    }
    else
    {
        help_printf_str("I am not a server");
    }
    int allocate = 0;
    ptls_context_t *ctx = (ptls_context_t *) ptls_get_field(tls, PTLS_CTX);
    int *data = (int *) get_opaque_data(ctx, 0, sizeof(int), &allocate);
    help_printf_int(allocate);
    if (!allocate)
    {
        help_printf_str("data =");
        int res = 0;
        my_memcpy(&res, data, sizeof(int));
        help_printf_int(res);
    }
    else
        help_printf_str("Set data to 1");
        int res = 1;
        my_memcpy(data, &res, sizeof(int));

    return 0;
}
