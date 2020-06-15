//
// Created by antoine on 26/09/2019.
//

#ifndef PICOTLS_PLUGIN_H
#define PICOTLS_PLUGIN_H

#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include "protoop.h"
#include "picotls_struct.h"
#include "ubpf/vm/inc/ubpf.h"
#include "picotls/getset.h"

#define NO_PARAM (param_id_t) -1

# define N_ARGS(...) N_ARGS_HELPER1(__VA_ARGS__, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0)
# define N_ARGS_HELPER1(...) N_ARGS_HELPER2(__VA_ARGS__)
# define N_ARGS_HELPER2(x1, x2, x3, x4, x5, x6, x7, x8, x9, n, ...) n

#define PLUGIN_FNAME_MAX_SIZE 250
#define EBPF_MEMORY_SIZE 100

#define PREPARE_AND_RUN_PROTOOP(tls, pid, outputv, ...) prepare_and_run_proto_op_noparam_helper(tls, pid, NO_PARAM, (proto_op_arg_t *) outputv, N_ARGS(__VA_ARGS__), __VA_ARGS__)


/**
 *
 * Register a list of helper functions in the vm
 */
int ubpf_register_basic_functions(struct ubpf_vm *vm);
/**
 *
 * Read the manifest files indicated by plugin_name and register each pluglet
 */
int ubpf_read_and_register_plugins(ptls_context_t *ctx, char *plugin_name);
/**
 *
 * Create a new protocol operation object
 */
proto_op_param_struct_t *create_protocol_operation_param(param_id_t, protocol_operation);
/**
 *
 * Function called to execute a protocol operation
 * This function execute pre pluglet if there is any
 * This function execute the core function or the replace pluglet if there is any
 * This function execute post pluglet if there is any
 */
proto_op_arg_t run_plugin_proto_op_internal(const proto_op_params_t *pp, ptls_t *tls);
/**
 * Register a protocol operation into the hashmap
 */
void register_noparam_proto_op(ptls_context_t *cnx, proto_op_id_t *proto_id, protocol_operation op);
/**
 *
 * Helper functions to call protocol operations from the main code
 * This function takes a variable number of arguments that are the arguments for the function executed by the protocol operation
 */
void prepare_and_run_proto_op_noparam_helper(ptls_t *tls, proto_op_id_t *pid, param_id_t param, proto_op_arg_t *outputv, const uint nargs, ...);
/**
 * Helper function to call protocol operations from pluglets
 */
void helper_plugin_run_proto_op(ptls_t *tls, proto_op_params_t *pp, const char *proto_op_name);
/**
 * Helper function used by pluglets to retrieve the pointer of data that has been allocated in the plugin's heap previously
 */
void *get_opaque_data(ptls_context_t *cnx, opaque_id_t op_id, size_t size, int *allocate);
#endif //PICOTLS_PLUGIN_H

