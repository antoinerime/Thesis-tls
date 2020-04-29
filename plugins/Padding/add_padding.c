//
// Created by antoine on 22.03.20.
//

#include "utils.h"



int add_padding (ptls_t *tls)
{
    // !!!!!!!!!!!!!!!!! HANDSHAKE MUST BE FINISHED !!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    ptls_context_t *ctx = (ptls_context_t *) ptls_get(tls, PTLS_CTX);
    ptls_buffer_t * sendbuf = (ptls_buffer_t *) ptls_get_ctx(tls, CTX_PROTO_OP_INPUT, 3);


    int timer = 0;
    int allocate = 0;
    int inlen = 0;
    get_timer(ctx, &timer);
    uint32_t is_serv = (uint32_t) ptls_get(tls, PTLS_IS_SRV);
    proto_op_arg_t output = 0;
    uint64_t off = ptls_get_buff(sendbuf, BUFF_OFF);

    if (off < PTLS_MAX_ENCRYPTED_RECORD_SIZE && timer < MAX_TIMER)
    {
        char *input = get_opaque_data(ctx, 10, sizeof(char), &allocate);
        uint64_t  ptls_traffic_protection_enc = ptls_get(tls, PTLS_TRAFFIC_ENC);
        // PREPARE_AND_RUN_PROTOOP(tls, &PROTOOP_NO_PARAM_BUFFER_PUSH_ENCRYPTED_RECORDS, &output, sendbuf, PTLS_CONTENT_TYPE_APPDATA, input, inlen, ptls_traffic_protection_enc);
        // prepare_and_run_proto_op_noparam_helper(tls, &PROTOOPID_NO_PARAM_BUFFER_PUSH_ENCRYPTED_RECORDS, -1, (proto_op_arg_t *) &output, sendbuf, PTLS_CONTENT_TYPE_APPDATA, input, inlen, ptls_traffic_protection_enc);
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
    }
    return 0;
}