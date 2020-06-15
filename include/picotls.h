/*
 * Copyright (c) 2016 DeNA Co., Ltd., Kazuho Oku
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */
#ifndef picotls_h
#define picotls_h

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _WINDOWS
#include "wincompat.h"
#endif

#include <assert.h>
#include <inttypes.h>
#include <sys/types.h>
#include <stdbool.h>
#include "picotls/protoop.h"
#include "picotls/picotls_struct.h"
#include "picotls/plugin.h"

#if __GNUC__ >= 3
#define PTLS_LIKELY(x) __builtin_expect(!!(x), 1)
#define PTLS_UNLIKELY(x) __builtin_expect(!!(x), 0)
#else
#define PTLS_LIKELY(x) (x)
#define PTLS_UNLIKELY(x) (x)
#endif

#ifdef _WINDOWS
#define PTLS_THREADLOCAL __declspec(thread)
#else
#define PTLS_THREADLOCAL __thread
#endif

#ifndef PTLS_FUZZ_HANDSHAKE
#define PTLS_FUZZ_HANDSHAKE 0
#endif


/**
 * builds a new ptls_iovec_t instance using the supplied parameters
 */
static ptls_iovec_t ptls_iovec_init(const void *p, size_t len);
/**
 * initializes a buffer, setting the default destination to the small buffer provided as the argument.
 */
static void ptls_buffer_init(ptls_buffer_t *buf, void *smallbuf, size_t smallbuf_size);
/**
 * disposes a buffer, freeing resources allocated by the buffer itself (if any)
 */
static void ptls_buffer_dispose(ptls_buffer_t *buf);
/**
 * internal
 */
void ptls_buffer__release_memory(ptls_buffer_t *buf);
/**
 * reserves space for additional amount of memory
 */
int ptls_buffer_reserve(ptls_buffer_t *buf, size_t delta);
/**
 * internal
 */
int ptls_buffer__do_pushv(ptls_buffer_t *buf, const void *src, size_t len);
/**
 * internal
 */
int ptls_buffer__adjust_asn1_blocksize(ptls_buffer_t *buf, size_t body_size);
/**
 * pushes an unsigned bigint
 */
int ptls_buffer_push_asn1_ubigint(ptls_buffer_t *buf, const void *bignum, size_t size);
/**
 *  send a hello world record
 */

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

#define ptls_buffer_push16(buf, v)                                                                                                 \
    do {                                                                                                                           \
        uint16_t _v = (v);                                                                                                         \
        ptls_buffer_push(buf, (uint8_t)(_v >> 8), (uint8_t)_v);                                                                    \
    } while (0)

#define ptls_buffer_push24(buf, v)                                                                                                 \
    do {                                                                                                                           \
        uint32_t _v = (v);                                                                                                         \
        ptls_buffer_push(buf, (uint8_t)(_v >> 16), (uint8_t)(_v >> 8), (uint8_t)_v);                                               \
    } while (0)

#define ptls_buffer_push32(buf, v)                                                                                                 \
    do {                                                                                                                           \
        uint32_t _v = (v);                                                                                                         \
        ptls_buffer_push(buf, (uint8_t)(_v >> 24), (uint8_t)(_v >> 16), (uint8_t)(_v >> 8), (uint8_t)_v);                          \
    } while (0)

#define ptls_buffer_push64(buf, v)                                                                                                 \
    do {                                                                                                                           \
        uint64_t _v = (v);                                                                                                         \
        ptls_buffer_push(buf, (uint8_t)(_v >> 56), (uint8_t)(_v >> 48), (uint8_t)(_v >> 40), (uint8_t)(_v >> 32),                  \
                         (uint8_t)(_v >> 24), (uint8_t)(_v >> 16), (uint8_t)(_v >> 8), (uint8_t)_v);                               \
    } while (0)

#define ptls_buffer_push_block(buf, _capacity, block)                                                                              \
    do {                                                                                                                           \
        size_t capacity = (_capacity);                                                                                             \
        ptls_buffer_pushv((buf), (uint8_t *)"\0\0\0\0\0\0\0", capacity);                                                           \
        size_t body_start = (buf)->off;                                                                                            \
        do {                                                                                                                       \
            block                                                                                                                  \
        } while (0);                                                                                                               \
        size_t body_size = (buf)->off - body_start;                                                                                \
        for (; capacity != 0; --capacity)                                                                                          \
            (buf)->base[body_start - capacity] = (uint8_t)(body_size >> (8 * (capacity - 1)));                                     \
    } while (0)

#define ptls_buffer_push_asn1_block(buf, block)                                                                                    \
    do {                                                                                                                           \
        ptls_buffer_push((buf), 0xff); /* dummy */                                                                                 \
        size_t body_start = (buf)->off;                                                                                            \
        do {                                                                                                                       \
            block                                                                                                                  \
        } while (0);                                                                                                               \
        size_t body_size = (buf)->off - body_start;                                                                                \
        if (body_size < 128) {                                                                                                     \
            (buf)->base[body_start - 1] = (uint8_t)body_size;                                                                      \
        } else {                                                                                                                   \
            if ((ret = ptls_buffer__adjust_asn1_blocksize((buf), body_size)) != 0)                                                 \
                goto Exit;                                                                                                         \
        }                                                                                                                          \
    } while (0)

#define ptls_buffer_push_asn1_sequence(buf, block)                                                                                 \
    do {                                                                                                                           \
        ptls_buffer_push((buf), 0x30);                                                                                             \
        ptls_buffer_push_asn1_block((buf), block);                                                                                 \
    } while (0)

#define ptls_buffer_push_message_body(buf, key_sched, type, block)                                                                 \
    do {                                                                                                                           \
        ptls_buffer_t *_buf = (buf);                                                                                               \
        ptls_key_schedule_t *_key_sched = (key_sched);                                                                             \
        size_t mess_start = _buf->off;                                                                                             \
        ptls_buffer_push(_buf, (type));                                                                                            \
        ptls_buffer_push_block(_buf, 3, block);                                                                                    \
        if (_key_sched != NULL)                                                                                                    \
            ptls__key_schedule_update_hash(_key_sched, _buf->base + mess_start, _buf->off - mess_start);                           \
    } while (0)

#define ptls_push_message(tls, emitter, key_sched, type, block)                                                                         \
    do {                                                                                                                           \
        ptls_message_emitter_t *_emitter = (emitter);                                                                              \
        if ((ret = _emitter->begin_message(_emitter)) != 0)                                                                        \
            goto Exit;                                                                                                             \
        ptls_buffer_push_message_body(_emitter->buf, (key_sched), (type), block);                                                  \
        if ((ret = _emitter->commit_message(tls, _emitter)) != 0)                                                                       \
            goto Exit;                                                                                                             \
    } while (0)

int ptls_decode16(uint16_t *value, const uint8_t **src, const uint8_t *end);
int ptls_decode24(uint32_t *value, const uint8_t **src, const uint8_t *end);
int ptls_decode32(uint32_t *value, const uint8_t **src, const uint8_t *end);
int ptls_decode64(uint64_t *value, const uint8_t **src, const uint8_t *end);

#define ptls_decode_open_block(src, end, capacity, block)                                                                          \
    do {                                                                                                                           \
        size_t _capacity = (capacity);                                                                                             \
        if (_capacity > (size_t)(end - (src))) {                                                                                   \
            ret = PTLS_ALERT_DECODE_ERROR;                                                                                         \
            goto Exit;                                                                                                             \
        }                                                                                                                          \
        size_t _block_size = 0;                                                                                                    \
        do {                                                                                                                       \
            _block_size = _block_size << 8 | *(src)++;                                                                             \
        } while (--_capacity != 0);                                                                                                \
        if (_block_size > (size_t)(end - (src))) {                                                                                 \
            ret = PTLS_ALERT_DECODE_ERROR;                                                                                         \
            goto Exit;                                                                                                             \
        }                                                                                                                          \
        do {                                                                                                                       \
            const uint8_t *const end = (src) + _block_size;                                                                        \
            do {                                                                                                                   \
                block                                                                                                              \
            } while (0);                                                                                                           \
            if ((src) != end) {                                                                                                    \
                ret = PTLS_ALERT_DECODE_ERROR;                                                                                     \
                goto Exit;                                                                                                         \
            }                                                                                                                      \
        } while (0);                                                                                                               \
    } while (0)

#define ptls_decode_assert_block_close(src, end)                                                                                   \
    do {                                                                                                                           \
        if ((src) != end) {                                                                                                        \
            ret = PTLS_ALERT_DECODE_ERROR;                                                                                         \
            goto Exit;                                                                                                             \
        }                                                                                                                          \
    } while (0);

#define ptls_decode_block(src, end, capacity, block)                                                                               \
    do {                                                                                                                           \
        ptls_decode_open_block((src), end, capacity, block);                                                                       \
        ptls_decode_assert_block_close((src), end);                                                                                \
    } while (0)

/**
 * create a object to handle new TLS connection. Client-side of a TLS connection is created if server_name is non-NULL. Otherwise,
 * a server-side connection is created.
 */
ptls_t *ptls_new(ptls_context_t *ctx, int is_server);
/**
 * releases all resources associated to the ctx object
 */
void ptls_ctx_free(ptls_context_t *ctx);
/**
 * releases all resources associated with the connection
 */
void ptls_free(ptls_t *tls);
/**
 * returns address of the crypto callbacks that the connection is using
 */
ptls_context_t *ptls_get_context(ptls_t *tls);
/**
 * updates the context of a connection. Can be called from `on_client_hello` callback.
 */
void ptls_set_context(ptls_t *tls, ptls_context_t *ctx);
/**
 * returns the client-random
 */
ptls_iovec_t ptls_get_client_random(ptls_t *tls);
/**
 * returns the cipher-suite being used
 */
ptls_cipher_suite_t *ptls_get_cipher(ptls_t *tls);
/**
 * returns the server-name (NULL if SNI is not used or failed to negotiate)
 */
const char *ptls_get_server_name(ptls_t *tls);
/**
 * sets the server-name associated to the TLS connection. If server_name_len is zero, then strlen(server_name) is called to
 * determine the length of the name.
 * On the client-side, the value is used for certificate validation. The value will be also sent as an SNI extension, if it looks
 * like a DNS name.
 * On the server-side, it can be called from on_client_hello to indicate the acceptance of the SNI extension to the client.
 */
int ptls_set_server_name(ptls_t *tls, const char *server_name, size_t server_name_len);
/**
 * returns the negotiated protocol (or NULL)
 */
const char *ptls_get_negotiated_protocol(ptls_t *tls);
/**
 * sets the negotiated protocol. If protocol_len is zero, strlen(protocol) is called to determine the length of the protocol name.
 */
int ptls_set_negotiated_protocol(ptls_t *tls, const char *protocol, size_t protocol_len);
/**
 * returns if the handshake has been completed
 */
int ptls_handshake_is_complete(ptls_t *tls);
/**
 * returns if a PSK (or PSK-DHE) handshake was performed
 */
int ptls_is_psk_handshake(ptls_t *tls);
/**
 * returns a pointer to user data pointer (client is reponsible for freeing the associated data prior to calling ptls_free)
 */
void **ptls_get_data_ptr(ptls_t *tls);
/**
 *
 */
int ptls_skip_tracing(ptls_t *tls);
/**
 *
 */
void ptls_set_skip_tracing(ptls_t *tls, int skip_tracing);
/**
 * proceeds with the handshake, optionally taking some input from peer. The function returns zero in case the handshake completed
 * successfully. PTLS_ERROR_IN_PROGRESS is returned in case the handshake is incomplete. Otherwise, an error value is returned. The
 * contents of sendbuf should be sent to the client, regardless of whether if an error is returned. inlen is an argument used for
 * both input and output. As an input, the arguments takes the size of the data available as input. Upon return the value is updated
 * to the number of bytes consumed by the handshake. In case the returned value is PTLS_ERROR_IN_PROGRESS there is a guarantee that
 * all the input are consumed (i.e. the value of inlen does not change).
 */
int ptls_handshake(ptls_t *tls, ptls_buffer_t *sendbuf, const void *input, size_t *inlen, ptls_handshake_properties_t *args);
/**
 * decrypts the first record within given buffer
 */
proto_op_arg_t ptls_receive(ptls_t *tls);
/**
 * encrypts given buffer into multiple TLS records
 */
proto_op_arg_t ptls_send(ptls_t *tls);
/**
 * updates the send traffic key (as well as asks the peer to update)
 */
int ptls_update_key(ptls_t *tls, int request_update);
/**
 * Returns if the context is a server context.
 */
int ptls_is_server(ptls_t *tls);
/**
 * returns per-record overhead
 */
size_t ptls_get_record_overhead(ptls_t *tls);
/**
 * sends an alert
 */
int ptls_send_alert(ptls_t *tls, ptls_buffer_t *sendbuf, uint8_t level, uint8_t description);
/**
 *
 */
int ptls_export_secret(ptls_t *tls, void *output, size_t outlen, const char *label, ptls_iovec_t context_value, int is_early);
/**
 * build the body of a Certificate message. Can be called with tls set to NULL in order to create a precompressed message.
 */
int ptls_build_certificate_message(ptls_buffer_t *buf, ptls_iovec_t request_context, ptls_iovec_t *certificates,
                                   size_t num_certificates, ptls_iovec_t ocsp_status);
/**
 *
 */
int ptls_calc_hash(ptls_hash_algorithm_t *algo, void *output, const void *src, size_t len);
/**
 *
 */
ptls_hash_context_t *ptls_hmac_create(ptls_hash_algorithm_t *algo, const void *key, size_t key_size);
/**
 *
 */
int ptls_hkdf_extract(ptls_hash_algorithm_t *hash, void *output, ptls_iovec_t salt, ptls_iovec_t ikm);
/**
 *
 */
int ptls_hkdf_expand(ptls_hash_algorithm_t *hash, void *output, size_t outlen, ptls_iovec_t prk, ptls_iovec_t info);
/**
 *
 */
int ptls_hkdf_expand_label(ptls_hash_algorithm_t *algo, void *output, size_t outlen, ptls_iovec_t secret, const char *label,
                           ptls_iovec_t hash_value, const char *label_prefix);
/**
 * instantiates a symmetric cipher
 */
ptls_cipher_context_t *ptls_cipher_new(ptls_cipher_algorithm_t *algo, int is_enc, const void *key);
/**
 * destroys a symmetric cipher
 */
void ptls_cipher_free(ptls_cipher_context_t *ctx);
/**
 * initializes the IV; this function must be called prior to calling ptls_cipher_encrypt
 */
static void ptls_cipher_init(ptls_cipher_context_t *ctx, const void *iv);
/**
 * encrypts given text
 */
static void ptls_cipher_encrypt(ptls_cipher_context_t *ctx, void *output, const void *input, size_t len);
/**
 * instantiates an AEAD cipher given a secret, which is expanded using hkdf to a set of key and iv
 * @param aead
 * @param hash
 * @param is_enc 1 if creating a context for encryption, 0 if creating a context for decryption
 * @param secret the secret. The size must be the digest length of the hash algorithm
 * @return pointer to an AEAD context if successful, otherwise NULL
 */
ptls_aead_context_t *ptls_aead_new(ptls_aead_algorithm_t *aead, ptls_hash_algorithm_t *hash, int is_enc, const void *secret,
                                   const char *label_prefix);
/**
 * destroys an AEAD cipher context
 */
void ptls_aead_free(ptls_aead_context_t *ctx);
/**
 *
 */
int aead_decrypt(struct st_ptls_traffic_protection_t *ctx, void *output, size_t *outlen, const void *input, size_t inlen);
/**
 *
 * @param ctx
 * @param output
 * @param input
 * @param inlen
 * @param seq
 * @param aad
 * @param aadlen
 * @return
 */
size_t ptls_aead_encrypt(ptls_aead_context_t *ctx, void *output, const void *input, size_t inlen, uint64_t seq, const void *aad,
                         size_t aadlen);
/**
 * initializes the internal state of the encryptor
 */
static void ptls_aead_encrypt_init(ptls_aead_context_t *ctx, uint64_t seq, const void *aad, size_t aadlen);
/**
 * encrypts the input and updates the GCM state
 * @return number of bytes emitted to output
 */
static size_t ptls_aead_encrypt_update(ptls_aead_context_t *ctx, void *output, const void *input, size_t inlen);
/**
 * emits buffered data (if any) and the GCM tag
 * @return number of bytes emitted to output
 */
static size_t ptls_aead_encrypt_final(ptls_aead_context_t *ctx, void *output);
/**
 * decrypts an AEAD record
 * @return number of bytes emitted to output if successful, or SIZE_MAX if the input is invalid (e.g. broken MAC)
 */
static size_t ptls_aead_decrypt(ptls_aead_context_t *ctx, void *output, const void *input, size_t inlen, uint64_t seq,
                                const void *aad, size_t aadlen);
/**
 * Return the current read epoch.
 */
size_t ptls_get_read_epoch(ptls_t *tls);
/**
 * Runs the handshake by dealing directly with handshake messages. Callers MUST delay supplying input to this function until the
 * epoch of the input becomes equal to the value returned by `ptls_get_read_epoch()`.
 * @param tls            the TLS context
 * @param sendbuf        buffer to which the output will be written
 * @param epoch_offsets  start and end offset of the messages in each epoch. For example, when the server emits ServerHello between
 *                       offset 0 and 38, the following handshake messages between offset 39 and 348, and a post-handshake message
 *                       between 349 and 451, epoch_offsets will be {0,39,39,349,452} and the length of the sendbuf will be 452.
 *                       This argument is an I/O argument. Applications can either reset sendbuf to empty and epoch_offsets and to
 *                       all zero every time they invoke the function, or retain the values until the handshake completes so that
 *                       data will be appended to sendbuf and epoch_offsets will be adjusted.
 * @param in_epoch       epoch of the input
 * @param input          input bytes (must be NULL when starting the handshake on the client side)
 * @param inlen          length of the input
 * @param properties     properties specific to the running handshake
 * @return same as `ptls_handshake`
 */
int ptls_handle_message(ptls_t *tls, ptls_buffer_t *sendbuf, size_t epoch_offsets[5], size_t in_epoch, const void *input,
                        size_t inlen, ptls_handshake_properties_t *properties);
/**
 * internal
 */
void ptls_aead__build_iv(ptls_aead_context_t *ctx, uint8_t *iv, uint64_t seq);
/**
 * internal
 */
void ptls__key_schedule_update_hash(ptls_key_schedule_t *sched, const uint8_t *msg, size_t msglen);
/**
 * clears memory
 */
extern void (*volatile ptls_clear_memory)(void *p, size_t len);
/**
 * constant-time memcmp
 */
extern int (*volatile ptls_mem_equal)(const void *x, const void *y, size_t len);
/**
 *
 */
static ptls_iovec_t ptls_iovec_init(const void *p, size_t len);
/**
 * checks if a server name is an IP address.
 */
int ptls_server_name_is_ipaddr(const char *name);
/**
 * loads a certificate chain to ptls_context_t::certificates. `certificate.list` and each element of the list is allocated by
 * malloc.  It is the responsibility of the user to free them when discarding the TLS context.
 */
int ptls_load_certificates(ptls_context_t *ctx, char const *cert_pem_file);
/**
 *
 */
int ptls_esni_init_context(ptls_context_t *ctx, ptls_esni_context_t *esni, ptls_iovec_t esni_keys,
                           ptls_key_exchange_context_t **key_exchanges);
/**
 *
 */
void ptls_esni_dispose_context(ptls_esni_context_t *esni);
/**
 * Obtain the ESNI secrets negotiated during the handshake.
 */
ptls_esni_secret_t *ptls_get_esni_secret(ptls_t *ctx);
/**
 *
 */
char *ptls_hexdump(char *dst, const void *src, size_t len);
/**
 * the default get_time callback
 */
void picotls_register_noparam_proto_op(ptls_context_t *cnx);
/**
 *
 */
extern ptls_get_time_t ptls_get_time;
/**
 *
 */
extern PTLS_THREADLOCAL unsigned ptls_default_skip_tracing;

/* inline functions */

inline ptls_iovec_t ptls_iovec_init(const void *p, size_t len)
{
    /* avoid the "return (ptls_iovec_t){(uint8_t *)p, len};" construct because it requires C99
     * and triggers a warning "C4204: nonstandard extension used: non-constant aggregate initializer"
     * in Visual Studio */
    ptls_iovec_t r;
    r.base = (uint8_t *)p;
    r.len = len;
    return r;
}

inline void ptls_buffer_init(ptls_buffer_t *buf, void *smallbuf, size_t smallbuf_size)
{
    assert(smallbuf != NULL);
    buf->base = (uint8_t *)smallbuf;
    buf->off = 0;
    buf->capacity = smallbuf_size;
    buf->is_allocated = 0;
}

inline void ptls_buffer_dispose(ptls_buffer_t *buf)
{
    ptls_buffer__release_memory(buf);
    *buf = (ptls_buffer_t){NULL};
}

inline void ptls_cipher_init(ptls_cipher_context_t *ctx, const void *iv)
{
    ctx->do_init(ctx, iv);
}

inline void ptls_cipher_encrypt(ptls_cipher_context_t *ctx, void *output, const void *input, size_t len)
{
    ctx->do_transform(ctx, output, input, len);
}

inline void ptls_aead_encrypt_init(ptls_aead_context_t *ctx, uint64_t seq, const void *aad, size_t aadlen)
{
    uint8_t iv[PTLS_MAX_IV_SIZE];

    ptls_aead__build_iv(ctx, iv, seq);
    ctx->do_encrypt_init(ctx, iv, aad, aadlen);
}

inline size_t ptls_aead_encrypt_update(ptls_aead_context_t *ctx, void *output, const void *input, size_t inlen)
{
    return ctx->do_encrypt_update(ctx, output, input, inlen);
}

inline size_t ptls_aead_encrypt_final(ptls_aead_context_t *ctx, void *output)
{
    return ctx->do_encrypt_final(ctx, output);
}

inline size_t ptls_aead_decrypt(ptls_aead_context_t *ctx, void *output, const void *input, size_t inlen, uint64_t seq,
                                const void *aad, size_t aadlen)
{
    uint8_t iv[PTLS_MAX_IV_SIZE];

    ptls_aead__build_iv(ctx, iv, seq);
    return ctx->do_decrypt(ctx, output, input, inlen, iv, aad, aadlen);
}

#define ptls_define_hash(name, ctx_type, init_func, update_func, final_func)                                                       \
                                                                                                                                   \
    struct name##_context_t {                                                                                                      \
        ptls_hash_context_t super;                                                                                                 \
        ctx_type ctx;                                                                                                              \
    };                                                                                                                             \
                                                                                                                                   \
    static void name##_update(ptls_hash_context_t *_ctx, const void *src, size_t len)                                              \
    {                                                                                                                              \
        struct name##_context_t *ctx = (struct name##_context_t *)_ctx;                                                            \
        update_func(&ctx->ctx, src, len);                                                                                          \
    }                                                                                                                              \
                                                                                                                                   \
    static void name##_final(ptls_hash_context_t *_ctx, void *md, ptls_hash_final_mode_t mode)                                     \
    {                                                                                                                              \
        struct name##_context_t *ctx = (struct name##_context_t *)_ctx;                                                            \
        if (mode == PTLS_HASH_FINAL_MODE_SNAPSHOT) {                                                                               \
            ctx_type copy = ctx->ctx;                                                                                              \
            final_func(&copy, md);                                                                                                 \
            ptls_clear_memory(&copy, sizeof(copy));                                                                                \
            return;                                                                                                                \
        }                                                                                                                          \
        if (md != NULL)                                                                                                            \
            final_func(&ctx->ctx, md);                                                                                             \
        switch (mode) {                                                                                                            \
        case PTLS_HASH_FINAL_MODE_FREE:                                                                                            \
            ptls_clear_memory(&ctx->ctx, sizeof(ctx->ctx));                                                                        \
            free(ctx);                                                                                                             \
            break;                                                                                                                 \
        case PTLS_HASH_FINAL_MODE_RESET:                                                                                           \
            init_func(&ctx->ctx);                                                                                                  \
            break;                                                                                                                 \
        default:                                                                                                                   \
            assert(!"FIXME");                                                                                                      \
            break;                                                                                                                 \
        }                                                                                                                          \
    }                                                                                                                              \
                                                                                                                                   \
    static ptls_hash_context_t *name##_clone(ptls_hash_context_t *_src)                                                            \
    {                                                                                                                              \
        struct name##_context_t *dst, *src = (struct name##_context_t *)_src;                                                      \
        if ((dst = malloc(sizeof(*dst))) == NULL)                                                                                  \
            return NULL;                                                                                                           \
        *dst = *src;                                                                                                               \
        return &dst->super;                                                                                                        \
    }                                                                                                                              \
                                                                                                                                   \
    static ptls_hash_context_t *name##_create(void)                                                                                \
    {                                                                                                                              \
        struct name##_context_t *ctx;                                                                                              \
        if ((ctx = malloc(sizeof(*ctx))) == NULL)                                                                                  \
            return NULL;                                                                                                           \
        ctx->super = (ptls_hash_context_t){name##_update, name##_final, name##_clone};                                             \
        init_func(&ctx->ctx);                                                                                                      \
        return &ctx->super;                                                                                                        \
    }

#ifdef __cplusplus
}
#endif

#endif
