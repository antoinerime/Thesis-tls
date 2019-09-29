//
// Created by antoine on 29/09/2019.
//

#ifndef PICOTLS_PICOTLS_STRUCT_H
#define PICOTLS_PICOTLS_STRUCT_H

#include <stdbool.h>

#define PTLS_HELLO_RANDOM_SIZE 32

#define PTLS_AES128_KEY_SIZE 16
#define PTLS_AES256_KEY_SIZE 32
#define PTLS_AES_BLOCK_SIZE 16
#define PTLS_AES_IV_SIZE 16
#define PTLS_AESGCM_IV_SIZE 12
#define PTLS_AESGCM_TAG_SIZE 16

#define PTLS_CHACHA20_KEY_SIZE 32
#define PTLS_CHACHA20_IV_SIZE 16
#define PTLS_CHACHA20POLY1305_IV_SIZE 12
#define PTLS_CHACHA20POLY1305_TAG_SIZE 16

#define PTLS_BLOWFISH_KEY_SIZE 16
#define PTLS_BLOWFISH_BLOCK_SIZE 8

#define PTLS_SHA256_BLOCK_SIZE 64
#define PTLS_SHA256_DIGEST_SIZE 32

#define PTLS_SHA384_BLOCK_SIZE 128
#define PTLS_SHA384_DIGEST_SIZE 48

#define PTLS_MAX_SECRET_SIZE 32
#define PTLS_MAX_IV_SIZE 16
#define PTLS_MAX_DIGEST_SIZE 64

/* cipher-suites */
#define PTLS_CIPHER_SUITE_AES_128_GCM_SHA256 0x1301
#define PTLS_CIPHER_SUITE_AES_256_GCM_SHA384 0x1302
#define PTLS_CIPHER_SUITE_CHACHA20_POLY1305_SHA256 0x1303

/* negotiated_groups */
#define PTLS_GROUP_SECP256R1 23
#define PTLS_GROUP_SECP384R1 24
#define PTLS_GROUP_SECP521R1 25
#define PTLS_GROUP_X25519 29
#define PTLS_GROUP_X448 30

/* signature algorithms */
#define PTLS_SIGNATURE_RSA_PKCS1_SHA1 0x0201
#define PTLS_SIGNATURE_RSA_PKCS1_SHA256 0x0401
#define PTLS_SIGNATURE_ECDSA_SECP256R1_SHA256 0x0403
#define PTLS_SIGNATURE_ECDSA_SECP384R1_SHA384 0x0503
#define PTLS_SIGNATURE_ECDSA_SECP521R1_SHA512 0x0603
#define PTLS_SIGNATURE_RSA_PSS_RSAE_SHA256 0x0804
#define PTLS_SIGNATURE_RSA_PSS_RSAE_SHA384 0x0805
#define PTLS_SIGNATURE_RSA_PSS_RSAE_SHA512 0x0806

/* ESNI */
#define PTLS_ESNI_VERSION_DRAFT03 0xff02

#define PTLS_ESNI_RESPONSE_TYPE_ACCEPT 0
#define PTLS_ESNI_RESPONSE_TYPE_RETRY_REQUEST 1

/* error classes and macros */
#define PTLS_ERROR_CLASS_SELF_ALERT 0
#define PTLS_ERROR_CLASS_PEER_ALERT 0x100
#define PTLS_ERROR_CLASS_INTERNAL 0x200

#define PTLS_ERROR_GET_CLASS(e) ((e) & ~0xff)
#define PTLS_ALERT_TO_SELF_ERROR(e) ((e) + PTLS_ERROR_CLASS_SELF_ALERT)
#define PTLS_ALERT_TO_PEER_ERROR(e) ((e) + PTLS_ERROR_CLASS_PEER_ALERT)
#define PTLS_ERROR_TO_ALERT(e) ((e)&0xff)

/* the HKDF prefix */
#define PTLS_HKDF_EXPAND_LABEL_PREFIX "tls13 "

/* alerts */
#define PTLS_ALERT_LEVEL_WARNING 1
#define PTLS_ALERT_LEVEL_FATAL 2

#define PTLS_ALERT_CLOSE_NOTIFY 0
#define PTLS_ALERT_UNEXPECTED_MESSAGE 10
#define PTLS_ALERT_BAD_RECORD_MAC 20
#define PTLS_ALERT_HANDSHAKE_FAILURE 40
#define PTLS_ALERT_BAD_CERTIFICATE 42
#define PTLS_ALERT_CERTIFICATE_REVOKED 44
#define PTLS_ALERT_CERTIFICATE_EXPIRED 45
#define PTLS_ALERT_CERTIFICATE_UNKNOWN 46
#define PTLS_ALERT_ILLEGAL_PARAMETER 47
#define PTLS_ALERT_UNKNOWN_CA 48
#define PTLS_ALERT_DECODE_ERROR 50
#define PTLS_ALERT_DECRYPT_ERROR 51
#define PTLS_ALERT_PROTOCOL_VERSION 70
#define PTLS_ALERT_INTERNAL_ERROR 80
#define PTLS_ALERT_USER_CANCELED 90
#define PTLS_ALERT_MISSING_EXTENSION 109
#define PTLS_ALERT_UNRECOGNIZED_NAME 112
#define PTLS_ALERT_CERTIFICATE_REQUIRED 116
#define PTLS_ALERT_NO_APPLICATION_PROTOCOL 120

/* internal errors */
#define PTLS_ERROR_NO_MEMORY (PTLS_ERROR_CLASS_INTERNAL + 1)
#define PTLS_ERROR_IN_PROGRESS (PTLS_ERROR_CLASS_INTERNAL + 2)
#define PTLS_ERROR_LIBRARY (PTLS_ERROR_CLASS_INTERNAL + 3)
#define PTLS_ERROR_INCOMPATIBLE_KEY (PTLS_ERROR_CLASS_INTERNAL + 4)
#define PTLS_ERROR_SESSION_NOT_FOUND (PTLS_ERROR_CLASS_INTERNAL + 5)
#define PTLS_ERROR_STATELESS_RETRY (PTLS_ERROR_CLASS_INTERNAL + 6)
#define PTLS_ERROR_NOT_AVAILABLE (PTLS_ERROR_CLASS_INTERNAL + 7)
#define PTLS_ERROR_COMPRESSION_FAILURE (PTLS_ERROR_CLASS_INTERNAL + 8)
#define PTLS_ERROR_ESNI_RETRY (PTLS_ERROR_CLASS_INTERNAL + 8)

#define PTLS_ERROR_INCORRECT_BASE64 (PTLS_ERROR_CLASS_INTERNAL + 50)
#define PTLS_ERROR_PEM_LABEL_NOT_FOUND (PTLS_ERROR_CLASS_INTERNAL + 51)
#define PTLS_ERROR_BER_INCORRECT_ENCODING (PTLS_ERROR_CLASS_INTERNAL + 52)
#define PTLS_ERROR_BER_MALFORMED_TYPE (PTLS_ERROR_CLASS_INTERNAL + 53)
#define PTLS_ERROR_BER_MALFORMED_LENGTH (PTLS_ERROR_CLASS_INTERNAL + 54)
#define PTLS_ERROR_BER_EXCESSIVE_LENGTH (PTLS_ERROR_CLASS_INTERNAL + 55)
#define PTLS_ERROR_BER_ELEMENT_TOO_SHORT (PTLS_ERROR_CLASS_INTERNAL + 56)
#define PTLS_ERROR_BER_UNEXPECTED_EOC (PTLS_ERROR_CLASS_INTERNAL + 57)
#define PTLS_ERROR_DER_INDEFINITE_LENGTH (PTLS_ERROR_CLASS_INTERNAL + 58)
#define PTLS_ERROR_INCORRECT_ASN1_SYNTAX (PTLS_ERROR_CLASS_INTERNAL + 59)
#define PTLS_ERROR_INCORRECT_PEM_KEY_VERSION (PTLS_ERROR_CLASS_INTERNAL + 60)
#define PTLS_ERROR_INCORRECT_PEM_ECDSA_KEY_VERSION (PTLS_ERROR_CLASS_INTERNAL + 61)
#define PTLS_ERROR_INCORRECT_PEM_ECDSA_CURVE (PTLS_ERROR_CLASS_INTERNAL + 62)
#define PTLS_ERROR_INCORRECT_PEM_ECDSA_KEYSIZE (PTLS_ERROR_CLASS_INTERNAL + 63)
#define PTLS_ERROR_INCORRECT_ASN1_ECDSA_KEY_SYNTAX (PTLS_ERROR_CLASS_INTERNAL + 64)

#define PTLS_HANDSHAKE_TYPE_CLIENT_HELLO 1
#define PTLS_HANDSHAKE_TYPE_SERVER_HELLO 2
#define PTLS_HANDSHAKE_TYPE_NEW_SESSION_TICKET 4
#define PTLS_HANDSHAKE_TYPE_END_OF_EARLY_DATA 5
#define PTLS_HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS 8
#define PTLS_HANDSHAKE_TYPE_CERTIFICATE 11
#define PTLS_HANDSHAKE_TYPE_CERTIFICATE_REQUEST 13
#define PTLS_HANDSHAKE_TYPE_CERTIFICATE_VERIFY 15
#define PTLS_HANDSHAKE_TYPE_FINISHED 20
#define PTLS_HANDSHAKE_TYPE_KEY_UPDATE 24
#define PTLS_HANDSHAKE_TYPE_COMPRESSED_CERTIFICATE 25
#define PTLS_HANDSHAKE_TYPE_MESSAGE_HASH 254

#define PTLS_ZERO_DIGEST_SHA256                                                                                                    \
    {                                                                                                                              \
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4,    \
            0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55                                                 \
    }

#define PTLS_ZERO_DIGEST_SHA384                                                                                                    \
    {                                                                                                                              \
        0x38, 0xb0, 0x60, 0xa7, 0x51, 0xac, 0x96, 0x38, 0x4c, 0xd9, 0x32, 0x7e, 0xb1, 0xb1, 0xe3, 0x6a, 0x21, 0xfd, 0xb7, 0x11,    \
            0x14, 0xbe, 0x07, 0x43, 0x4c, 0x0c, 0xc7, 0xbf, 0x63, 0xf6, 0xe1, 0xda, 0x27, 0x4e, 0xde, 0xbf, 0xe7, 0x6f, 0x65,      \
            0xfb, 0xd5, 0x1a, 0xd2, 0xf1, 0x48, 0x98, 0xb9, 0x5b                                                                   \
    }


#ifdef _WINDOWS
#pragma warning(pop)
#endif

typedef struct st_ptls_t ptls_t;
typedef struct st_ptls_context_t ptls_context_t;
typedef struct st_ptls_key_schedule_t ptls_key_schedule_t;

typedef uint64_t proto_op_arg_t;
typedef uint16_t param_id_t;

/**
 * represents a sequence of octets
 */
typedef struct st_ptls_iovec_t {
    uint8_t *base;
    size_t len;
} ptls_iovec_t;

/**
 * used for storing output
 */
typedef struct st_ptls_buffer_t {
    uint8_t *base;
    size_t capacity;
    size_t off;
    int is_allocated;
} ptls_buffer_t;

/**
 * key exchange context built by ptls_key_exchange_algorithm::create.
 */
typedef struct st_ptls_key_exchange_context_t {
    /**
     * the underlying algorithm
     */
    const struct st_ptls_key_exchange_algorithm_t *algo;
    /**
     * the public key
     */
    ptls_iovec_t pubkey;
    /**
     * If `release` is set, the callee frees resources allocated to the context and set *keyex to NULL
     */
    int (*on_exchange)(struct st_ptls_key_exchange_context_t **keyex, int release, ptls_iovec_t *secret, ptls_iovec_t peerkey);
} ptls_key_exchange_context_t;

/**
 * A key exchange algorithm.
 */
typedef const struct st_ptls_key_exchange_algorithm_t {
    /**
     * ID defined by the TLS specification
     */
    uint16_t id;
    /**
     * creates a context for asynchronous key exchange. The function is called when ClientHello is generated. The on_exchange
     * callback of the created context is called when the client receives ServerHello.
     */
    int (*create)(const struct st_ptls_key_exchange_algorithm_t *algo, ptls_key_exchange_context_t **ctx);
    /**
     * implements synchronous key exchange. Called when receiving a ServerHello.
     */
    int (*exchange)(const struct st_ptls_key_exchange_algorithm_t *algo, ptls_iovec_t *pubkey, ptls_iovec_t *secret,
                    ptls_iovec_t peerkey);
    /**
     * crypto-specific data
     */
    intptr_t data;
} ptls_key_exchange_algorithm_t;

/**
 * context of a symmetric cipher
 */
typedef struct st_ptls_cipher_context_t {
    const struct st_ptls_cipher_algorithm_t *algo;
    /* field above this line must not be altered by the crypto binding */
    void (*do_dispose)(struct st_ptls_cipher_context_t *ctx);
    void (*do_init)(struct st_ptls_cipher_context_t *ctx, const void *iv);
    void (*do_transform)(struct st_ptls_cipher_context_t *ctx, void *output, const void *input, size_t len);
} ptls_cipher_context_t;

/**
 * a symmetric cipher
 */
typedef const struct st_ptls_cipher_algorithm_t {
    const char *name;
    size_t key_size;
    size_t block_size;
    size_t iv_size;
    size_t context_size;
    int (*setup_crypto)(ptls_cipher_context_t *ctx, int is_enc, const void *key);
} ptls_cipher_algorithm_t;

/**
 * AEAD context. AEAD implementations are allowed to stuff data at the end of the struct. The size of the memory allocated for the
 * struct is governed by ptls_aead_algorithm_t::context_size.
 */
typedef struct st_ptls_aead_context_t {
    const struct st_ptls_aead_algorithm_t *algo;
    uint8_t static_iv[PTLS_MAX_IV_SIZE];
    /* field above this line must not be altered by the crypto binding */
    void (*dispose_crypto)(struct st_ptls_aead_context_t *ctx);
    void (*do_encrypt_init)(struct st_ptls_aead_context_t *ctx, const void *iv, const void *aad, size_t aadlen);
    size_t (*do_encrypt_update)(struct st_ptls_aead_context_t *ctx, void *output, const void *input, size_t inlen);
    size_t (*do_encrypt_final)(struct st_ptls_aead_context_t *ctx, void *output);
    size_t (*do_decrypt)(struct st_ptls_aead_context_t *ctx, void *output, const void *input, size_t inlen, const void *iv,
                         const void *aad, size_t aadlen);
} ptls_aead_context_t;

/**
 * An AEAD cipher.
 */
typedef const struct st_ptls_aead_algorithm_t {
    /**
     * name (following the convention of `openssl ciphers -v ALL`)
     */
    const char *name;
    /**
     * the underlying key stream
     */
    ptls_cipher_algorithm_t *ctr_cipher;
    /**
     * the underlying ecb cipher (might not be available)
     */
    ptls_cipher_algorithm_t *ecb_cipher;
    /**
     * key size
     */
    size_t key_size;
    /**
     * size of the IV
     */
    size_t iv_size;
    /**
     * size of the tag
     */
    size_t tag_size;
    /**
     * size of memory allocated for ptls_aead_context_t. AEAD implementations can set this value to something greater than
     * sizeof(ptls_aead_context_t) and stuff additional data at the bottom of the struct.
     */
    size_t context_size;
    /**
     * callback that sets up the crypto
     */
    int (*setup_crypto)(ptls_aead_context_t *ctx, int is_enc, const void *key);
} ptls_aead_algorithm_t;

/**
 *
 */
typedef enum en_ptls_hash_final_mode_t {
    /**
     * obtains the digest and frees the context
     */
            PTLS_HASH_FINAL_MODE_FREE = 0,
    /**
     * obtains the digest and reset the context to initial state
     */
            PTLS_HASH_FINAL_MODE_RESET = 1,
    /**
     * obtains the digest while leaving the context as-is
     */
            PTLS_HASH_FINAL_MODE_SNAPSHOT = 2
} ptls_hash_final_mode_t;

/**
 * A hash context.
 */
typedef struct st_ptls_hash_context_t {
    /**
     * feeds additional data into the hash context
     */
    void (*update)(struct st_ptls_hash_context_t *ctx, const void *src, size_t len);
    /**
     * returns the digest and performs necessary operation specified by mode
     */
    void (*final)(struct st_ptls_hash_context_t *ctx, void *md, ptls_hash_final_mode_t mode);
    /**
     * creates a copy of the hash context
     */
    struct st_ptls_hash_context_t *(*clone_)(struct st_ptls_hash_context_t *src);
} ptls_hash_context_t;

/**
 * A hash algorithm and its properties.
 */
typedef const struct st_ptls_hash_algorithm_t {
    /**
     * block size
     */
    size_t block_size;
    /**
     * digest size
     */
    size_t digest_size;
    /**
     * constructor that creates the hash context
     */
    ptls_hash_context_t *(*create)(void);
    /**
     * digest of zero-length octets
     */
    uint8_t empty_digest[PTLS_MAX_DIGEST_SIZE];
} ptls_hash_algorithm_t;

typedef const struct st_ptls_cipher_suite_t {
    uint16_t id;
    ptls_aead_algorithm_t *aead;
    ptls_hash_algorithm_t *hash;
} ptls_cipher_suite_t;

struct st_ptls_traffic_protection_t;

typedef struct st_ptls_message_emitter_t {
    ptls_buffer_t *buf;
    struct st_ptls_traffic_protection_t *enc;
    size_t record_header_length;
    int (*begin_message)(struct st_ptls_message_emitter_t *self);
    int (*commit_message)(struct st_ptls_message_emitter_t *self);
} ptls_message_emitter_t;

/**
 * holds ESNIKeys and the private key (instantiated by ptls_esni_parse, freed using ptls_esni_dispose)
 */
typedef struct st_ptls_esni_context_t {
    ptls_key_exchange_context_t **key_exchanges;
    struct {
        ptls_cipher_suite_t *cipher_suite;
        uint8_t record_digest[PTLS_MAX_DIGEST_SIZE];
    } * cipher_suites;
    uint16_t padded_length;
    uint64_t not_before;
    uint64_t not_after;
    uint16_t version;
} ptls_esni_context_t;

/**
 * holds the ESNI secret, as exchanged during the handshake
 */

#define PTLS_ESNI_NONCE_SIZE 16

typedef struct st_ptls_esni_secret_t {
    ptls_iovec_t secret;
    uint8_t nonce[PTLS_ESNI_NONCE_SIZE];
    uint8_t esni_contents_hash[PTLS_MAX_DIGEST_SIZE];
    union {
        struct {
            ptls_key_exchange_algorithm_t *key_share;
            ptls_cipher_suite_t *cipher;
            ptls_iovec_t pubkey;
            uint8_t record_digest[PTLS_MAX_DIGEST_SIZE];
            uint16_t padded_length;
        } client;
    };
    uint16_t version;
} ptls_esni_secret_t;

#define PTLS_CALLBACK_TYPE0(ret, name)                                                                                             \
    typedef struct st_ptls_##name##_t {                                                                                            \
        ret (*cb)(struct st_ptls_##name##_t * self);                                                                               \
    } ptls_##name##_t

#define PTLS_CALLBACK_TYPE(ret, name, ...)                                                                                         \
    typedef struct st_ptls_##name##_t {                                                                                            \
        ret (*cb)(struct st_ptls_##name##_t * self, __VA_ARGS__);                                                                  \
    } ptls_##name##_t

/**
 * arguments passsed to the on_client_hello callback
 */
typedef struct st_ptls_on_client_hello_parameters_t {
    /**
     * SNI value received from the client. The value is {NULL, 0} if the extension was absent.
     */
    ptls_iovec_t server_name;
    /**
     * Raw value of the client_hello message.
     */
    ptls_iovec_t raw_message;
    /**
     *
     */
    struct {
        ptls_iovec_t *list;
        size_t count;
    } negotiated_protocols;
    struct {
        const uint16_t *list;
        size_t count;
    } signature_algorithms;
    struct {
        const uint16_t *list;
        size_t count;
    } certificate_compression_algorithms;
    struct {
        const uint16_t *list;
        size_t count;
    } cipher_suites;
    /**
     * if ESNI was used
     */
    uint8_t esni : 1;
} ptls_on_client_hello_parameters_t;

/**
 * returns current time in milliseconds (ptls_get_time can be used to return the physical time)
 */
PTLS_CALLBACK_TYPE0(uint64_t, get_time);
/**
 * after receiving ClientHello, the core calls the optional callback to give a chance to the swap the context depending on the input
 * values. The callback is required to call `ptls_set_server_name` if an SNI extension needs to be sent to the client.
 */
PTLS_CALLBACK_TYPE(int, on_client_hello, ptls_t *tls, ptls_on_client_hello_parameters_t *params);
/**
 * callback to generate the certificate message. `ptls_context::certificates` are set when the callback is set to NULL.
 */
PTLS_CALLBACK_TYPE(int, emit_certificate, ptls_t *tls, ptls_message_emitter_t *emitter, ptls_key_schedule_t *key_sched,
                   ptls_iovec_t context, int push_status_request);
/**
 * when gerenating CertificateVerify, the core calls the callback to sign the handshake context using the certificate.
 */
PTLS_CALLBACK_TYPE(int, sign_certificate, ptls_t *tls, uint16_t *selected_algorithm, ptls_buffer_t *output, ptls_iovec_t input,
                   const uint16_t *algorithms, size_t num_algorithms);
/**
 * after receiving Certificate, the core calls the callback to verify the certificate chain and to obtain a pointer to a
 * callback that should be used for verifying CertificateVerify. If an error occurs between a successful return from this
 * callback to the invocation of the verify_sign callback, verify_sign is called with both data and sign set to an empty buffer.
 * The implementor of the callback should use that as the opportunity to free any temporary data allocated for the verify_sign
 * callback.
 */
PTLS_CALLBACK_TYPE(int, verify_certificate, ptls_t *tls,
                   int (**verify_sign)(void *verify_ctx, ptls_iovec_t data, ptls_iovec_t sign), void **verify_data,
                   ptls_iovec_t *certs, size_t num_certs);
/**
 * encrypt-and-signs (or verify-and-decrypts) a ticket (server-only)
 */
PTLS_CALLBACK_TYPE(int, encrypt_ticket, ptls_t *tls, int is_encrypt, ptls_buffer_t *dst, ptls_iovec_t src);
/**
 * saves a ticket (client-only)
 */
PTLS_CALLBACK_TYPE(int, save_ticket, ptls_t *tls, ptls_iovec_t input);
/**
 * event logging (incl. secret logging)
 */
typedef struct st_ptls_log_event_t {
    void (*cb)(struct st_ptls_log_event_t *self, ptls_t *tls, const char *type, const char *fmt, ...)
    __attribute__((format(printf, 4, 5)));
} ptls_log_event_t;
/**
 * reference counting
 */
PTLS_CALLBACK_TYPE(void, update_open_count, ssize_t delta);
/**
 * applications that have their own record layer can set this function to derive their own traffic keys from the traffic secret.
 * The cipher-suite that is being associated to the connection can be obtained by calling the ptls_get_cipher function.
 */
PTLS_CALLBACK_TYPE(int, update_traffic_key, ptls_t *tls, int is_enc, size_t epoch, const void *secret);
/**
 * callback for every extension detected during decoding
 */
PTLS_CALLBACK_TYPE(int, on_extension, ptls_t *tls, uint8_t hstype, uint16_t exttype, ptls_iovec_t extdata);
/**
 *
 */
typedef struct st_ptls_decompress_certificate_t {
    /**
     * list of supported algorithms terminated by UINT16_MAX
     */
    const uint16_t *supported_algorithms;
    /**
     * callback that decompresses the message
     */
    int (*cb)(struct st_ptls_decompress_certificate_t *self, ptls_t *tls, uint16_t algorithm, ptls_iovec_t output,
              ptls_iovec_t input);
} ptls_decompress_certificate_t;
/**
 * provides access to the ESNI shared secret (Zx).  API is subject to change.
 */
PTLS_CALLBACK_TYPE(int, update_esni_key, ptls_t *tls, ptls_iovec_t secret, ptls_hash_algorithm_t *hash,
                   const void *hashed_esni_contents);
/**
 *
 */
typedef struct {
    proto_op_id_t *id;
    param_id_t *param;
    bool caller_is_intern;
    int inputc;
    proto_op_arg_t *inputv;
    proto_op_arg_t *outputv;
}proto_op_params_t;

typedef proto_op_arg_t (*protocol_operation)(ptls_t *);
typedef struct proto_oop_param_struct {
    param_id_t param;
    protocol_operation core;
    // TODO pluget_t *replace
    bool intern;
    bool running;
    //TODO observer_node_t pre;
    //TODO observer_node_t post;
    UT_hash_handle hh;
} proto_op_param_struct_t;

typedef struct proto_op_struct {
    proto_op_id_t *id;
    proto_op_param_struct_t *param;
    bool is_parametrable;
    UT_hash_handle hh;

}proto_op_struct_t;

/**
 * the configuration
 */
struct st_ptls_context_t {
    /**
     * PRNG to be used
     */
    void (*random_bytes)(void *buf, size_t len);
    /**
     *
     */
    ptls_get_time_t *get_time;
    /**
     * list of supported key-exchange algorithms terminated by NULL
     */
    ptls_key_exchange_algorithm_t **key_exchanges;
    /**
     * list of supported cipher-suites terminated by NULL
     */
    ptls_cipher_suite_t **cipher_suites;
    /**
     * list of certificates
     */
    struct {
        ptls_iovec_t *list;
        size_t count;
    } certificates;
    /**
     * list of ESNI data terminated by NULL
     */
    ptls_esni_context_t **esni;
    /**
     *
     */
    ptls_on_client_hello_t *on_client_hello;
    /**
     *
     */
    ptls_emit_certificate_t *emit_certificate;
    /**
     *
     */
    ptls_sign_certificate_t *sign_certificate;
    /**
     *
     */
    ptls_verify_certificate_t *verify_certificate;
    /**
     * lifetime of a session ticket (server-only)
     */
    uint32_t ticket_lifetime;
    /**
     * maximum permitted size of early data (server-only)
     */
    uint32_t max_early_data_size;
    /**
     * the field is obsolete; should be set to NULL for QUIC draft-17.  Note also that even though everybody did, it was incorrect
     * to set the value to "quic " in the earlier versions of the draft.
     */
    const char *hkdf_label_prefix__obsolete;
    /**
     * if set, psk handshakes use (ec)dhe
     */
    unsigned require_dhe_on_psk : 1;
    /**
     * if exporter master secrets should be recorded
     */
    unsigned use_exporter : 1;
    /**
     * if ChangeCipherSpec message should be sent during handshake
     */
    unsigned send_change_cipher_spec : 1;
    /**
     * if set, the server requests client certificates
     * to authenticate the client.
     */
    unsigned require_client_authentication : 1;
    /**
     * if set, EOED will not be emitted or accepted
     */
    unsigned omit_end_of_early_data : 1;
    /**
     *
     */
    ptls_encrypt_ticket_t *encrypt_ticket;
    /**
     *
     */
    ptls_save_ticket_t *save_ticket;
    /**
     *
     */
    ptls_log_event_t *log_event;
    /**
     *
     */
    ptls_update_open_count_t *update_open_count;
    /**
     *
     */
    ptls_update_traffic_key_t *update_traffic_key;
    /**
     *
     */
    ptls_decompress_certificate_t *decompress_certificate;
    /**
     *
     */
    ptls_update_esni_key_t *update_esni_key;
    /**
     *
     */
    ptls_on_extension_t *on_extension;
    /**
     *
     */

    proto_op_struct_t *ops;
    /**
     *
     */
     proto_op_arg_t *proto_op_inputv;
};

typedef struct st_ptls_raw_extension_t {
    uint16_t type;
    ptls_iovec_t data;
} ptls_raw_extension_t;

typedef enum en_ptls_early_data_acceptance_t {
    PTLS_EARLY_DATA_ACCEPTANCE_UNKNOWN = 0,
    PTLS_EARLY_DATA_REJECTED,
    PTLS_EARLY_DATA_ACCEPTED
} ptls_early_data_acceptance_t;

/**
 * optional arguments to client-driven handshake
 */
#ifdef _WINDOWS
/* suppress warning C4201: nonstandard extension used: nameless struct/union */
#pragma warning(push)
#pragma warning(disable : 4201)
#endif
typedef struct st_ptls_handshake_properties_t {
    union {
        struct {
            /**
             * list of protocols offered through ALPN
             */
            struct {
                const ptls_iovec_t *list;
                size_t count;
            } negotiated_protocols;
            /**
             * session ticket sent to the application via save_ticket callback
             */
            ptls_iovec_t session_ticket;
            /**
             * pointer to store the maximum size of early-data that can be sent immediately. If set to non-NULL, the first call to
             * ptls_handshake (or ptls_handle_message) will set `*max_early_data` to the value obtained from the session ticket, or
             * to zero if early-data cannot be sent. If NULL, early data will not be used.
             */
            size_t *max_early_data_size;
            /**
             * If early-data has been accepted by peer, or if the state is still unknown. The state changes anytime after handshake
             * keys become available. Applications can peek the tri-state variable every time it calls `ptls_hanshake` or
             * `ptls_handle_message` to determine the result at the earliest moment. This is an output parameter.
             */
            ptls_early_data_acceptance_t early_data_acceptance;
            /**
             * negotiate the key exchange method before sending key_share
             */
            unsigned negotiate_before_key_exchange : 1;
            /**
             * ESNIKeys (the value of the TXT record, after being base64-"decoded")
             */
            ptls_iovec_t esni_keys;
        } client;
        struct {
            /**
             * psk binder being selected (len is set to zero if none)
             */
            struct {
                uint8_t base[PTLS_MAX_DIGEST_SIZE];
                size_t len;
            } selected_psk_binder;
            /**
             * parameters related to use of the Cookie extension
             */
            struct {
                /**
                 * HMAC key to protect the integrity of the cookie. The key should be as long as the digest size of the first
                 * ciphersuite specified in ptls_context_t (i.e. the hash algorithm of the best ciphersuite that can be chosen).
                 */
                const void *key;
                /**
                 * additional data to be used for verifying the cookie
                 */
                ptls_iovec_t additional_data;
            } cookie;
            /**
             * if HRR should always be sent
             */
            unsigned enforce_retry : 1;
            /**
             * if retry should be stateless (cookie.key MUST be set when this option is used)
             */
            unsigned retry_uses_cookie : 1;
        } server;
    };
    /**
     * an optional list of additional extensions to send either in CH or EE, terminated by type == UINT16_MAX
     */
    ptls_raw_extension_t *additional_extensions;
    /**
     * an optional callback that returns a boolean value indicating if a particular extension should be collected
     */
    int (*collect_extension)(ptls_t *tls, struct st_ptls_handshake_properties_t *properties, uint16_t type);
    /**
     * an optional callback that reports the extensions being collected
     */
    int (*collected_extensions)(ptls_t *tls, struct st_ptls_handshake_properties_t *properties, ptls_raw_extension_t *extensions);
} ptls_handshake_properties_t;

#endif //PICOTLS_PICOTLS_STRUCT_H
