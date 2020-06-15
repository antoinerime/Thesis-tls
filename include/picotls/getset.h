//
// Created by antoine on 15.10.19.
//

#ifndef PICOTLS_GETSET_H
#define PICOTLS_GETSET_H

#include "picotls/picotls_struct.h"
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
    PTLS_DATA_PTR,
    PTLS_TRAFFIC_ENC
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
    CTX_PROTO_OP_INPUT,
    CTX_PROTO_OP_OUTPUT
}ptls_ctx_field ;

typedef enum ptls_buff_field {
    BUFF_BASE,
    BUFF_CAPACITY,
    BUFF_OFF,
    BUFF_IS_ALLOCATED
}ptls_buff_field;

typedef enum ptls_traffic_protection_field {
    PROTECTION_EPOCH,
    PROTECTION_SEQ,
    PROTECTION_AEAD,
    PROTECTION_ALGO_TAG_SIZE,
    PROTECTION_ALGO_KEY_SIZE,
    PROTECTION_ALGO_IV_SIZE,
    PROTECTION_CTX_SIZE
}ptls_traffic_protection_field ;

extern uint64_t ptls_get(ptls_t *tls, enum ptls_field field);
extern void ptls_set(ptls_t *tls, enum ptls_field field, uint64_t value);

uint64_t ptls_get_ctx(ptls_t *tls, enum ptls_ctx_field field, uint16_t param);
void ptls_set_ctx(ptls_t *tls, enum ptls_ctx_field field, uint64_t value, uint16_t param);

uint64_t ptls_get_buff(ptls_buffer_t *buff, enum ptls_buff_field field);
void ptls_set_buff(ptls_buffer_t *buff, enum ptls_buff_field field, uint64_t value, uint16_t param);

extern uint64_t ptls_get_protection(struct st_ptls_traffic_protection_t *enc, enum ptls_traffic_protection_field);
extern void ptls_set_protection(struct st_ptls_traffic_protection_t *enc, enum ptls_traffic_protection_field, uint64_t value);

#endif //PICOTLS_GETSET_H
