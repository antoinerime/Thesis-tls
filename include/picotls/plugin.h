//
// Created by antoine on 26/09/2019.
//

#ifndef PICOTLS_PLUGIN_H
#define PICOTLS_PLUGIN_H

#include <stdlib.h>
#include <stdarg.h>
#include "protoop.h"
#include "picotls_struct.h"

#define NO_PARAM (param_id_t) -1

#define PREPARE_AND_RUN_PROTOOP(tls, pid, outputv, ...) prepare_and_run_proto_op_no_param_helper(tls, pid, NO_PARAM, outputv, N_ARGS(args), args)


void prepare_and_run_proto_op_noparam_helper(ptls_t *tls, proto_op_id_t pid, proto_op_arg_t *outputv, const uint nargs, ...)
{
    va_list ap;
    va_start(ap, nargs);

}

/**
 *
 * @return
 */
proto_op_param_struct_t *create_protocol_operation_param(param_id_t, protocol_operation);
/**
 *
 */
proto_op_arg_t run_plugin_proto_op_internal(ptls_context_t *cnx, const proto_op_params_t *pp, ptls_t *tls);
/**
 *
 */
void register_noparam_proto_op(ptls_context_t *cnx, proto_op_id_t *proto_id, protocol_operation op);
#endif //PICOTLS_PLUGIN_H
