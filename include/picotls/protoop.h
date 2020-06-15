//
// Created by antoine on 26/09/2019.
//

#ifndef PICOTLS_PROTOOP_H
#define PICOTLS_PROTOOP_H

#include <stdint.h>
#include "uthash.h"

typedef char* protoop_str_id_t;
typedef struct protoop_id {
    uint64_t hash;
    char* id;
} proto_op_id_t;

static inline uint64_t hash_value_str(char *str_pid)
{
    uint64_t ret;
    HASH_VALUE_STR(str_pid, ret);
    return ret;
}

/**
 * Operation used to perform the decryption of a record
 */
#define PROTOOPID_NOPARAM_AEAD_DECRYPT "aead_decrypt"
extern proto_op_id_t PROTOOP_NOPARAM_AEAD_DECRYPT;
#define PROTOOPID_NO_PARAM_HANDLE_INPUT "handle_input"
extern proto_op_id_t PROTOOP_NO_PARAM_HANDLE_INPUT;
/**
 * This operation creates a new TLS records and encrypts it from the input data
 */
#define PROTOOPID_NO_PARAM_BUFFER_PUSH_ENCRYPTED_RECORDS "buffer_push_encrypted_records"
extern proto_op_id_t PROTOOP_NO_PARAM_BUFFER_PUSH_ENCRYPTED_RECORDS;
/**
 * This operation is called right after the TCP connection has been established.
 * It is responsible for managing the TLS connection from the beginning ot the end
 */
# define PROTOOPID_NO_PARAM_HANDLE_CONNECTION "handle_connection"
extern proto_op_id_t PROTOOP_NO_PARAM_HANDLE_CONNECTION;
/**
 * This operation is called each time new data need to be sent
 */
# define PROTOOPID_NO_PARAM_PTLS_RECEIVE "ptls_receive"
extern proto_op_id_t PROTOOP_NO_PARAM_PTLS_RECEIVE;
/**
 * This operation is called when new data is receivced on the socket
 */
#define PROTOOPID_NO_PARAM_PTLS_SEND "ptls_send"
extern proto_op_id_t PROTOOP_NO_PARAM_PTLS_SEND;
/**
 * This operation selects if a new message is available on the receive socket or the input file
 */
#define PROTOOPID_NO_PARAM_SELECT_OPERATION "select_operation"
extern proto_op_id_t PROTOOP_NO_PARAM_SELECT_OPERATION;
#endif //PICOTLS_PROTOOP_H
