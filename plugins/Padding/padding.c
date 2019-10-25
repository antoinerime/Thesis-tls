//
// Created by antoine on 14.10.19.
//
#include "picotls/picotls_struct.h"
#include "picotls/getset.h"
#include "picotls/picotls_struct.h"
#include "picotls/plugin.h"


#define PTLS_MAX_PLAINTEXT_RECORD_SIZE 16384
#define PADDING_RANGE 3276
#define PTLS_CONTENT_TYPE_APPDATA 23
#define PTLS_RECORD_VERSION_MAJOR 3
#define PTLS_RECORD_VERSION_MINOR 3


#define ptls_buffer_pushv(buf, src, len)                                                                                           \
    do {                                                                                                                           \
        if ((ret = ptls_buffer__do_pushv((buf), (src), (len))) != 0)                                                               \
            goto Exit;                                                                                                             \
    } while (0)

#define ptls_buffer_push(buf, ...)                                                                                                 \
    do {                                                                                                                           \
        if ((ret = ptls_buffer__do_pushv((buf), (uint8_t[]){__VA_ARGS__}, sizeof((uint8_t[]){__VA_ARGS__}))) != 0)                 \
            goto Exit;                                                                                                             \
    } while (0)

#define ptls_buffer_push_block(buf, _capacity, block)                                                                              \
    do {                                                                                                                           \
        size_t capacity = (_capacity);                                                                                             \
        ptls_buffer_pushv((buf), (uint8_t *)"\0\0\0\0\0\0\0", capacity);                                                           \
        size_t body_start = (size_t) ptls_get_buff((buf), BUFF_OFF);                                                               \
        do {                                                                                                                       \
            block                                                                                                                  \
        } while (0);                                                                                                               \
        size_t _off = (size_t) ptls_get_buff((buf), BUFF_OFF);                                                                      \
        size_t body_size = _off - body_start;                                                                                       \
        for (; capacity != 0; --capacity)                                                                                          \
                ptls_set_buff((buf), BUFF_BASE, (uint8_t)(body_size >> (8 * (capacity - 1))), body_start - capacity);              \
    } while (0)

#define buffer_push_record(buf, type, block)                                                                                       \
    do {                                                                                                                           \
        ptls_buffer_push((buf), (type), PTLS_RECORD_VERSION_MAJOR, PTLS_RECORD_VERSION_MINOR);                                     \
        ptls_buffer_push_block((buf), 2, block);                                                                                   \
    } while (0)

int padding(ptls_t *tls)
{
    ptls_context_t *ctx = (ptls_context_t *) ptls_get(tls, PTLS_CTX);
    ptls_buffer_t *buf = (ptls_buffer_t *) ptls_get_ctx(tls, CTX_PROTO_OP_INPUT, 0);
    uint8_t type = (uint8_t) ptls_get_ctx(tls, CTX_PROTO_OP_INPUT, 1);
    uint8_t *src = (uint8_t *) ptls_get_ctx(tls, CTX_PROTO_OP_INPUT, 2);
    size_t len = (size_t) ptls_get_ctx(tls, CTX_PROTO_OP_INPUT, 3);
    struct st_ptls_traffic_protection_t *enc = (struct st_ptls_traffic_protection_t *) ptls_get_ctx(tls, CTX_PROTO_OP_INPUT, 4);

    int allocate = 0;
    int ret = 0;
    size_t off, chunk_size;
    uint8_t *zeros = get_opaque_data(ctx, 0, PTLS_MAX_PLAINTEXT_RECORD_SIZE, &allocate);
    if (allocate)
        my_memset(zeros, 0, PTLS_MAX_PLAINTEXT_RECORD_SIZE);
    while (len != 0) {
         size_t padding;
        if (len < PTLS_MAX_PLAINTEXT_RECORD_SIZE)
        {
            padding = rand() % len;
            padding = padding + len > PTLS_MAX_PLAINTEXT_RECORD_SIZE ? PTLS_MAX_PLAINTEXT_RECORD_SIZE - len: padding;
            chunk_size = len;
        } else {
            padding = rand();
            padding = PTLS_MAX_PLAINTEXT_RECORD_SIZE - (padding % PADDING_RANGE);
            chunk_size = PTLS_MAX_PLAINTEXT_RECORD_SIZE - padding;
        }

        size_t enc_len = chunk_size + ptls_get_protection(enc, PROTECTION_ALGO_TAG_SIZE) + 1 + padding;
        buffer_push_record(buf, PTLS_CONTENT_TYPE_APPDATA, {
            if ((ret = ptls_buffer_reserve(buf, enc_len)) != 0)
                goto Exit;
            uint8_t aad[5];
            aad[0] = PTLS_CONTENT_TYPE_APPDATA;
            aad[1] = PTLS_RECORD_VERSION_MAJOR;
            aad[2] = PTLS_RECORD_VERSION_MINOR;
            aad[3] = (uint8_t ) (enc_len >> 8);
            aad[4] = (uint8_t) enc_len;

            size_t tmp_off = (size_t) ptls_get_buff(buf, BUFF_OFF);
            size_t base = (size_t) ptls_get_buff(buf, BUFF_BASE);

            ptls_aead_context_t * aead = (ptls_aead_context_t *) ptls_get_protection(enc, PROTECTION_AEAD);
            uint64_t seq = (uint64_t) ptls_get_protection(enc, PROTECTION_SEQ);

            ptls_aead_encrypt_init(aead, seq++, aad, sizeof(aad));
            ptls_set_protection(enc, PROTECTION_SEQ, seq);
            tmp_off += ptls_aead_encrypt_update(aead, ((uint8_t *)base) + tmp_off, src, chunk_size);
            tmp_off += ptls_aead_encrypt_update(aead, ((uint8_t *)base) + tmp_off, &type, 1);
            tmp_off += ptls_aead_encrypt_update(aead, ((uint8_t *)base) + tmp_off, zeros, padding);
            tmp_off += ptls_aead_encrypt_final(aead, ((uint8_t *)base) + tmp_off);
            ptls_set_buff(buf, BUFF_OFF, tmp_off, 0);
        });
        src += chunk_size;
        len -= chunk_size;
    }

Exit:
    return ret;
}
