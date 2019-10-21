//
// Created by antoine on 15.10.19.
//

#include "picotls/getset.h"


uint64_t ptls_get_ctx_field(ptls_t *tls, enum ptls_ctx_field field, uint16_t param)
{
    ptls_context_t * ctx = (ptls_context_t *) ptls_get_field(tls, PTLS_CTX);
    switch (field)
    {
        case CTX_RAND_BYTES:
            return (uint64_t) ctx->random_bytes;
        case CTX_GET_TIME:
            return (uint64_t) ctx->get_time;
        case CTX_KEY_EXCH:
            return (uint64_t) ctx->key_exchanges;
        case CTX_CIPHER_SUITES:
            return (uint64_t) ctx->cipher_suites;
        case CTX_ESNI:
            return (uint64_t) ctx->esni;
        case CTX_ON_CLIENT_HELLO:
            return (uint64_t) ctx->on_client_hello;
        case CTX_EMIT_CERT:
            return (uint64_t) ctx->emit_certificate;
        case CTX_SIGN_CERT:
            return (uint64_t) ctx->sign_certificate;
        case CTX_VERIF_CERT:
            return (uint64_t) ctx->verify_certificate;
        case CTX_TICKET_LIFETIME:
            return  ctx->ticket_lifetime;
        case CTX_MAX_EARLY_DATA_SIZE:
            return ctx->max_early_data_size;
        case CTX_REQ_DHE_ON_PSK:
            return ctx->require_dhe_on_psk;
        case CTX_USE_EXPORT:
            return ctx->use_exporter;
        case CTX_SEND_CHANGE_CIPHER_SPEC:
            return ctx->send_change_cipher_spec;
        case CTX_REQ_CLIENT_AUTH:
            return ctx->require_client_authentication;
        case CTX_OMIT_END_EARLY_DATA:
            return ctx->omit_end_of_early_data;
        case CTX_ENCRYPT_TICKET:
            return (uint64_t) ctx->encrypt_ticket;
        case CTX_SAVE_TICKET:
            return (uint64_t) ctx->save_ticket;
        case CTX_LOG_EVENT:
            return (uint64_t) ctx->log_event;
        case CTX_UPDT_OPEN_CNT:
            return (uint64_t) ctx->update_open_count;
        case CTX_UPDT_TRAFFIC_KEY:
            return (uint64_t) ctx->update_traffic_key;
        case CTX_DECOMPRESS_CERT:
            return (uint64_t) ctx->decompress_certificate;
        case CTX_UPDT_ESNI_KEY:
            return (uint64_t) ctx->update_esni_key;
        case CTX_PROTO_OP_INPUT:
            return (ctx->proto_op_inputv[param]);
        case CTX_PROTO_OP_OUTPUT:
            return (ctx->protop_op_output);
        default:
            return 0;
    }
}
void ptls_set_ctx_field(ptls_t *tls, enum ptls_ctx_field field, uint64_t value, uint16_t param)
{
    ptls_context_t * ctx = (ptls_context_t *) ptls_get_field(tls, PTLS_CTX);
    switch (field) {
        case CTX_RAND_BYTES:
            ctx->random_bytes = (void (*)(void *, size_t)) value;
            break;
        case CTX_GET_TIME:
            ctx->get_time = (ptls_get_time_t *) value;
            break;
        case CTX_KEY_EXCH:
            ctx->key_exchanges = (ptls_key_exchange_algorithm_t **) value;
            break;
        case CTX_CIPHER_SUITES:
            ctx->cipher_suites = (ptls_cipher_suite_t **) value;
            break;
        case CTX_ESNI:
            ctx->esni = (ptls_esni_context_t **) value;
            break;
        case CTX_ON_CLIENT_HELLO:
            ctx->on_client_hello = (ptls_on_client_hello_t *) value;
            break;
        case CTX_EMIT_CERT:
            ctx->emit_certificate = (ptls_emit_certificate_t *) value;
            break;
        case CTX_SIGN_CERT:
            ctx->sign_certificate = (ptls_sign_certificate_t *) value;
            break;
        case CTX_VERIF_CERT:
            ctx->verify_certificate = (ptls_verify_certificate_t *) value;
            break;
        case CTX_TICKET_LIFETIME:
            ctx->ticket_lifetime = value;
            break;
        case CTX_MAX_EARLY_DATA_SIZE:
            ctx->max_early_data_size = value;
            break;
        case CTX_REQ_DHE_ON_PSK:
            ctx->require_dhe_on_psk = value;
            break;
        case CTX_USE_EXPORT:
            ctx->use_exporter = value;
            break;
        case CTX_SEND_CHANGE_CIPHER_SPEC:
            ctx->send_change_cipher_spec = value;
            break;
        case CTX_REQ_CLIENT_AUTH:
            ctx->require_client_authentication = value;
            break;
        case CTX_OMIT_END_EARLY_DATA:
            ctx->omit_end_of_early_data = value;
            break;
        case CTX_ENCRYPT_TICKET:
            ctx->encrypt_ticket = (ptls_encrypt_ticket_t *) value;
            break;
        case CTX_SAVE_TICKET:
            ctx->save_ticket = (ptls_save_ticket_t *) value;
            break;
        case CTX_LOG_EVENT:
            ctx->log_event = (ptls_log_event_t *) value;
            break;
        case CTX_UPDT_OPEN_CNT:
            ctx->update_open_count = (ptls_update_open_count_t *) value;
            break;
        case CTX_UPDT_TRAFFIC_KEY:
            ctx->update_traffic_key = (ptls_update_traffic_key_t *) value;
            break;
        case CTX_DECOMPRESS_CERT:
            ctx->decompress_certificate = (ptls_decompress_certificate_t *) value;
            break;
        case CTX_UPDT_ESNI_KEY:
            ctx->update_esni_key = (ptls_update_esni_key_t *) value;
            break;
        case CTX_PROTO_OP_INPUT:
            ctx->proto_op_inputv[param] = value;
            break;
        case CTX_PROTO_OP_OUTPUT:
            ctx->protop_op_output = value;
            break;
        default:
            break;
    }
}
