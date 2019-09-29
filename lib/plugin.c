//
// Created by antoine on 26/09/2019.
//

#include <stdio.h>
#include "picotls/plugin.h"

proto_op_arg_t *new_inputv(ptls_context_t *cnx, const proto_op_params_t *pp);

void register_noparam_proto_op(ptls_context_t *cnx, proto_op_id_t *proto_id, protocol_operation op)
{
    proto_op_struct_t *proto_op;

    if(proto_id->hash == 0)
        proto_id->hash = hash_value_str(proto_id->id);
    HASH_FIND_PID(cnx->ops, &(proto_id->hash), proto_op);
    if (proto_op)
    {
        fprintf(stderr, "Protocol operation already in hashmap");
        return;
    }

    proto_op = (proto_op_struct_t*) malloc(sizeof(proto_op_struct_t));
    if (!proto_op)
    {
        fprintf(stderr, "Failed to allocate memory in %s, line %d", __FILE__, __LINE__);
        return;
    }
    proto_op_id_t *id = (proto_op_id_t *) malloc(sizeof(proto_op_id_t));
    if (!id)
    {
        fprintf(stderr, "Failed to allocate memory in %s, line %d", __FILE__, __LINE__);
        return;
    }
    size_t str_id_len = sizeof(proto_id->id) + 1;
    strncpy(id->id, proto_id->id, str_id_len);
    id->hash = proto_id->hash;

    proto_op->id = id;
    proto_op->is_parametrable = false;
    proto_op->param = create_protocol_operation_param(NO_PARAM, op);

    HASH_ADD_PID(cnx->ops, id->hash, proto_op);
}

proto_op_param_struct_t *create_protocol_operation_param(param_id_t param, protocol_operation op)
{
    proto_op_param_struct_t *proto_op_param = (proto_op_param_struct_t *) malloc(sizeof(proto_op_param_struct_t));
    if (!proto_op_param)
    {
        fprintf(stderr, "Failed to allocate memory in %s:%d", __FILE__, __LINE__);
        return NULL;
    }
    proto_op_param->param = param;
    proto_op_param->core = op;
    proto_op_param->intern = true;
    proto_op_param->running = false;

    return proto_op_param;
}

proto_op_arg_t run_plugin_proto_op_internal(ptls_context_t *cnx, const proto_op_params_t *pp, ptls_t *tls)
{
    // TODO CHeck number of arguments

    proto_op_struct_t *post;
    if (pp->id->hash == 0)
        pp->id->hash = hash_value_str(pp->id->id);

    HASH_FIND_PID(cnx->ops, &(pp->id->hash), post);
    if (!post)
    {
        fprintf(stderr, "Proto opertation doesn't exist at %s:%d\n", __FILE__, __LINE__);
        exit(-1);
    }
    proto_op_param_struct_t *popst;
    if (post->is_parametrable) {
        // TODO
    }else {
        popst = post->param;
    }

    proto_op_arg_t status;

    // TODO check if correct number of arg
    cnx->proto_op_inputv = pp->inputv;
    status = popst->core(tls);

    return status;
}

