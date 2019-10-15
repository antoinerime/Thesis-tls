//
// Created by antoine on 15.10.19.
//

#ifndef PICOTLS_GETSET_H
#define PICOTLS_GETSET_H

#include "picotls.h"
#include "picotls/picotls_struct.h"
// TODO What to do with anonymous struct
typedef enum ptls_field {
    PTLS_CTX,
    PTLS_STATE,
    PTLS_SERV_NAME,
    PTLS_NEG_PROTO,
    PTLS_KEY_SHARE,
    PTLS_CIPH_SUITE,
    PTLS_CLI_RAND,
    PTLS_ESNI,
    PTLS_MASTER_SECRET,
    PTLS_IS_SRV,
    PTLS_IS_PSK_HANDSHK,
    PTLS_CHANGE_CIPHER_SPEC,
    PTLS_NEED_KEY_UPDT,
    PTLS_SKIP_TRACING,
    PTLS_CERT_VERIF,
    PTLS_PENDING_HANDSHAKE_SCRT,
    PTLS_DATA_PTR
}ptls_field ;

typedef enum ptls_ctx_field {
    CTX_RAND_BYTES,
    CTX_GET_TIME,
    CTX_KEY_EXCH,
    CTX_CIPHER_SUITES,
    CTX_CERTIFICATES,
    CTX_ESNI,
    CTX_ON_CLIENT_HELLO,
    CTX_EMIT_CERT,
    CTX_SIGN_CERT,
    CTX_VERIF_CERT,
    CTX_TICKET_LIFETIME,
    CTX_MAX_EARLY_DATA_SIZE,
    CTX_REQ_DHE_ON_PSK,
    CTX_USE_EXPORT,
    CTX_SEND_CHANGE_CIPHER_SPEC,
    CTX_REQ_CLIENT_AUTH,
    CTX_OMIT_END_EARLY_DATA,
    CTX_ENCRYPT_TICKET,
    CTX_SAVE_TICKET,
    CTX_LOG_EVENT,
    CTX_UPDT_OPEN_CNT,
    CTX_UPDT_TRAFFIC_KEY,
    CTX_DECOMPRESS_CERT,
    CTX_UPDT_ESNI_KEY,
    CTX_PROTO_OP_INPUT
}ptls_ctx_field ;

extern uint64_t inline ptls_get_field(ptls_t *tls, enum ptls_field field);
extern void inline ptls_set_field(ptls_t *tls, enum ptls_field field, uint64_t value);

uint64_t inline ptls_get_ctx_field(ptls_t *tls, enum ptls_ctx_field field, uint16_t param);
void inline *ptls_set_ctx_field(ptls_t *tls, enum ptls_ctx_field field, uint64_t value, uint16_t param);

#endif //PICOTLS_GETSET_H
