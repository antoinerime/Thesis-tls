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
 *
 */
#define PROTOOPID_NOPARAM_AEAD_DECRYPT "aead_decrypt"
extern proto_op_id_t PROTOOP_NOPARAM_AEAD_DECRYPT;
/**
 *
 */
#define PROTOOPID_NO_PARAM_HANDLE_INPUT "handle_input"
extern proto_op_id_t PROTOOP_NO_PARAM_HANDLE_INPUT;
/**
 *
 */
#define PROTOOPID_NO_PARAM_BUFFER_PUSH_ENCRYPTED_RECORDS "buffer_push_encrypted_records"
extern proto_op_id_t PROTOOP_NO_PARAM_BUFFER_PUSH_ENCRYPTED_RECORDS;
/**
 *
 */
# define PROTOOPID_NO_PARAM_HANDLE_CONNECTION "handle_connection"
extern proto_op_id_t PROTOOP_NO_PARAM_HANDLE_CONNECTION;
/**
 *
 */
# define PROTOOPID_NO_PARAM_PTLS_RECEIVE "ptls_receive"
extern proto_op_id_t PROTOOP_NO_PARAM_PTLS_RECEIVE;
/*
 *
 */
#define PROTOOPID_NO_PARAM_PTLS_SEND "ptls_send"
extern proto_op_id_t PROTOOP_NO_PARAM_PTLS_SEND;
/*
 *
 */
#define PROTOOPID_NO_PARAM_SELECT_OPERATION "select_operation"
extern proto_op_id_t PROTOOP_NO_PARAM_SELECT_OPERATION;
#endif //PICOTLS_PROTOOP_H
