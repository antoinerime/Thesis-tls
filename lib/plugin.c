//
// Created by antoine on 26/09/2019.
//

#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <elf.h>
#include "picotls/plugin.h"
#include "picotls/memory.h"
#include "picotls.h"

proto_op_arg_t *new_inputv(ptls_context_t *cnx, const proto_op_params_t *pp);


plugin_t *initialize_plugin(ptls_context_t *cnx, char *line, size_t len);

bool parse_line(char *line, char *dir_name, char **code_file_name, proto_op_id_t **pid, proto_op_type *type);

bool register_plugin(ptls_context_t *cnx, char *fname, proto_op_id_t *pid, proto_op_type type, param_id_t param, plugin_t *plugin, pluglet_t *pluglet);

int register_pluglet(proto_op_param_struct_t *param, proto_op_type type, char *fname, pluglet_t *pluglet);

int load_pluglet_code(char *fname, pluglet_t *pluglet);

static void *readfile(const char *path, size_t maxlen, size_t *len);

void exec_observer_plugin(ptls_context_t *cnx, observer_node_t *obs, proto_op_arg_t *outputv);

void exec_pluglet(ptls_context_t *cnx, pluglet_t *pluglet, proto_op_arg_t *outputv);

void abort_plugin(ptls_context_t *cnx, pluglet_stack_t *top);

void destroy_pluglet(pluglet_t *pluglet);

// TODO Move the helper fun
void help_printf_str(char *s) {
    printf("%s\n", s);
}
int ubpf_register_basic_functions(struct ubpf_vm *vm)
{
int ret = 0;
ret += ubpf_register(vm, 0x01, "fprintf", &fprintf);
ret += ubpf_register(vm, 0x02, "help_printf_str", &help_printf_str);
return ret;
}


int ubpf_read_and_register_plugins(ptls_context_t *ctx, char * plugin_name)
{
    if (strlen(plugin_name) > PLUGIN_FNAME_MAX_SIZE) {
        fprintf(stderr, "Plugin name too long \n");
        return -1;
    }
    char fplugin_name[strlen(plugin_name)+1];
    memcpy(fplugin_name, plugin_name, strlen((plugin_name) +1));
    FILE *fp;
    char *line = NULL;
    size_t len = 0;
    ssize_t read;

    fp = fopen(plugin_name, "r");
    if (fp == NULL)
    {
        fprintf(stderr, "Failed to open %s: %s\n", plugin_name, strerror(errno));
        return -1;
    }
    read = getline(&line, &len, fp);
    if (read == -1)
    {
        fprintf(stderr, "Failed to read first line %s: %s\n", plugin_name, strerror(errno));
        fclose(fp);
        if (line)
            free(line);
        return -1;
    }
    plugin_t *plugin = initialize_plugin(ctx, line, read);
    if (!plugin){
        fprintf(stderr, "Failed to allocate memory %s:%d\n", __FILE__, __LINE__);
        fclose(fp);
        if (line)
            free(line);
        return -1;
    }
    bool ok = true;
    char *dir_name = dirname(fplugin_name);

    // TODO Check return value
    pluglet_stack_t *top = calloc(1, sizeof(pluglet_stack_t));
    while((read = getline(&line, &len, fp)) != -1 && ok) {
        char *code_file_name = NULL;
        proto_op_id_t *pid = NULL;
        proto_op_type type = REPLACE;
        if ((ok = parse_line(line, dir_name, &code_file_name, &pid, &type)) == false)
        {
            // TODO Free macro or sth
            return -1;
        }

        param_id_t param = NO_PARAM;
        pluglet_t *pluglet = calloc(1, sizeof(pluglet));
        ok = register_plugin(ctx, code_file_name, pid, type, param, plugin, pluglet);

        pluglet_stack_t *stack = calloc(1, sizeof(pluglet_stack_t));
        stack->pluglet = pluglet;
        stack->pid = pid;
        stack->type = type;
        stack->next = top->next;
        top->next = stack;
    }
    fclose(fp);
    if (line)
        free(line);
    if (!ok)
    {
        free(plugin->name);
        free(plugin);
        abort_plugin(ctx, top);
        free(top);
    } else
    {
        HASH_ADD_STR(ctx->plugin, name, plugin);
    }
    return ok;
}

void abort_plugin(ptls_context_t *cnx, pluglet_stack_t *top) {
    pluglet_stack_t *stack;
    proto_op_struct_t *proto_struct;
    proto_op_param_struct_t *param;
    observer_node_t *obs;
    stack = top->next;
    while (stack){
        if (stack->pid->hash == 0)
        {
            stack->pid->hash = hash_value_str(stack->pid->id);
        }
        HASH_FIND_PID(cnx->ops, &(stack->pid->hash), proto_struct);
        if (proto_struct)
        {
            param = proto_struct->param;
            switch (stack->type)
            {
                case PRE:
                    obs = param->pre;
                    param->pre = obs->next;
                    free(obs);
                    break;
                case REPLACE:
                    param->replace = NULL;
                    break;
                case POST:
                    obs = param->post;
                    param->post = obs->next;
                    free(obs);
                    break;
            }
            destroy_pluglet(stack->pluglet);
            free(stack->pid->id);
            free(stack->pid);
            top = stack;
            stack = top->next;
            free(top);
        }
    }
}

void destroy_pluglet(pluglet_t *pluglet) {
    ubpf_destroy(pluglet->vm);
    free(pluglet);
}

int register_pluglet(proto_op_param_struct_t *param, proto_op_type type, char *fname, pluglet_t *pluglet) {

    int ret;
    ret = load_pluglet_code(fname, pluglet);
    if (ret != 0)
        return ret;
    switch (type)
    {
        case REPLACE:
            if (param->replace)
            {
                // TODO Error if there is already a replace ?
                return -1;
            } else {
                param->replace = pluglet;
            }
            break;
        case PRE:
            if (param->pre != NULL)
            {
                observer_node_t *pre = calloc(1, sizeof(observer_node_t));
                pre->pluglet = pluglet;
                pre->next = param->pre->next;
                param->pre = pre;
            } else {
                observer_node_t *pre = calloc(1, sizeof(observer_node_t));
                pre->pluglet = pluglet;
                pre->next = NULL;
                param->pre = pre;
            }
            break;
        case POST:
            if (param->pre != NULL)
            {
                observer_node_t *post = calloc(1, sizeof(observer_node_t));
                post->pluglet = pluglet;
                post->next = param->post->next;
                param->post = post;
            } else {
                observer_node_t *post = calloc(1, sizeof(observer_node_t));
                post->pluglet = pluglet;
                post->next = NULL;
                param->post = post;
            }
            break;
        default:
            break;
    }
    return ret;
}

int load_pluglet_code(char *fname, pluglet_t *pluglet) {
    size_t code_len;
    void *code = readfile(fname, 1024*1024, &code_len);
    if (code == NULL)
        return 1;

    bool elf = code_len >= SELFMAG && !memcmp(code, ELFMAG, SELFMAG);

    char *errmsg;
    int rv;
    if (elf) {
        // TODO memory_ptr ?
        rv = ubpf_load_elf(pluglet->vm, code, code_len, &errmsg, 10, EBPF_MEMORY_SIZE);
    } else {
        rv = ubpf_load(pluglet->vm, code, code_len, &errmsg, 10, EBPF_MEMORY_SIZE);
    }
    free(code);

    if (rv < 0) {
        fprintf(stderr, "Failed to load code: %s\n", errmsg);
        free(errmsg);
        return 1;
    }

    return 0;
}

bool register_plugin(ptls_context_t *cnx, char *fname, proto_op_id_t *pid, proto_op_type type, param_id_t param, plugin_t *plugin, pluglet_t *pluglet) {
    if (!pluglet)
    {
        fprintf(stderr, "Failed to allocate pluglet memory %s: %d\n", __FILE__, __LINE__);
        return false;
    }
    pluglet->vm = ubpf_create();
    ubpf_register_basic_functions(pluglet->vm);
    pluglet->plugin = plugin;

    if (pid->hash == 0)
    {
        pid->hash = hash_value_str(pid->id);
    }
    proto_op_struct_t *proto_op;
    HASH_FIND_PID(cnx->ops, &(pid->hash), proto_op);
    if (!proto_op)
    {
        // TODO SHould we create a new one or raise an error ? Is this the exetern type ?
    }

    int ret;
    if (proto_op->is_parametrable)
    {
        // TODO ...
        ret = 0;
    }else if (proto_op->is_parametrable == false && param == NO_PARAM){
        ret = register_pluglet(proto_op->param, type, fname, pluglet);
    }else {
        // TODO raise error
        ret = -1;
    }
    return ret == 0;
}

bool parse_line(char *line, char *dir_name, char **code_file_name, proto_op_id_t **pid, proto_op_type *type) {
    char pid_name[20];
    char type_name[10];
    char tmp_code_filename[20];
    // TODO !!!!!!!!!!!!!!!!! Check maximum size !!!!!!!!!!!
    strcpy(pid_name, strsep(&line, " "));
    strcpy(type_name, strsep(&line, " "));
    strcpy(tmp_code_filename, strsep(&line, " "));
    if (strsep(&line, " ") != NULL)
    {
        fprintf(stderr, "Wrong syntax for plugin file, should be: [proto_op_name] [proto_op_type] [code_filename]\n");
        return false;
    }

    if ((strcmp(type_name, "replace")) == 0)
        *(type) = REPLACE;
    else if ((strcmp(type_name, "pre")) == 0)
        *(type) = PRE;
    else if ((strcmp(type_name, "post")) == 0)
        *(type) = POST;
    else
    {
        fprintf(stderr, "Wrong syntax for proto_op_type, can be either: pre, post or replace\n");
        return -1;
    }
    // Create new proto op id
    proto_op_id_t *tmp_pid = calloc(1, sizeof(proto_op_id_t));
    tmp_pid->id = calloc(strlen(pid_name)+1, sizeof(char));
    strncpy(tmp_pid->id, pid_name, strlen(pid_name));
    *(pid) = tmp_pid;

    // Create code file name
    char * tmp_code_file_name = malloc(sizeof(char) * (strlen(dir_name)+1+strlen(tmp_code_filename)));
    strncpy(tmp_code_file_name, dir_name, strlen(dir_name) +1);
    strncat(tmp_code_file_name, "/", 1);
    strncat(tmp_code_file_name, tmp_code_filename, strlen(tmp_code_filename));
    *(code_file_name) = tmp_code_file_name;

    return true;
}

plugin_t *initialize_plugin(ptls_context_t *cnx, char *line, size_t len) {
    plugin_t *p = calloc(1, sizeof(plugin_t));
    if (!p)
    {
        fprintf(stderr, "Failed to allocate memory %s:%d\n", __FILE__, __LINE__);
        return NULL;
    }
    p->name = calloc((len+1), sizeof(char));
    if (!p->name)
    {
        fprintf(stderr, "Failed to allocate memory %s:%d\n", __FILE__, __LINE__);
        free(p);
        return NULL;
    }
    strncpy(p->name, line, len);
    strncat(p->name, "\0", 1);
    return p;
}


static void *readfile(const char *path, size_t maxlen, size_t *len)
{
    FILE *file;
    if (!strcmp(path, "-")) {
        file = fdopen(STDIN_FILENO, "r");
    } else {
        file = fopen(path, "r");
    }

    if (file == NULL) {
        fprintf(stderr, "Failed to open %s: %s\n", path, strerror(errno));
        return NULL;
    }

    void *data = calloc(maxlen, 1);
    size_t offset = 0;
    size_t rv;
    while ((rv = fread(data+offset, 1, maxlen-offset, file)) > 0) {
        offset += rv;
    }

    if (ferror(file)) {
        fprintf(stderr, "Failed to read %s: %s\n", path, strerror(errno));
        fclose(file);
        free(data);
        return NULL;
    }

    if (!feof(file)) {
        fprintf(stderr, "Failed to read %s because it is too large (max %u bytes)\n",
                path, (unsigned)maxlen);
        fclose(file);
        free(data);
        return NULL;
    }

    fclose(file);
    if (len) {
        *len = offset;
    }
    return data;
}
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

    proto_op = (proto_op_struct_t*) calloc(1, sizeof(proto_op_struct_t));
    if (!proto_op)
    {
        fprintf(stderr, "Failed to allocate memory in %s, line %d", __FILE__, __LINE__);
        return;
    }
    proto_op_id_t *id = (proto_op_id_t *) calloc(1, sizeof(proto_op_id_t));
    if (!id)
    {
        fprintf(stderr, "Failed to allocate memory in %s, line %d", __FILE__, __LINE__);
        return;
    }
    size_t str_id_len = sizeof(proto_id->id) + 1;
    id->id = (char *) malloc(sizeof(char) * str_id_len);
    if (!id->id)
    {
        fprintf(stderr, "Failed to allocate memory in %s, line %d", __FILE__, __LINE__);
        return;
    }
    strncpy(id->id, proto_id->id, str_id_len);
    id->hash = proto_id->hash;

    proto_op->id = id;
    proto_op->is_parametrable = false;
    proto_op->param = create_protocol_operation_param(NO_PARAM, op);

    HASH_ADD_PID(cnx->ops, id->hash, proto_op);
}

proto_op_param_struct_t *create_protocol_operation_param(param_id_t param, protocol_operation op)
{
    proto_op_param_struct_t *proto_op_param = (proto_op_param_struct_t *) calloc(1, sizeof(proto_op_param_struct_t));
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

proto_op_arg_t run_plugin_proto_op_internal(const proto_op_params_t *pp, ptls_t *tls)
{
    // TODO CHeck number of arguments
    ptls_context_t *cnx = ptls_get_context(tls);
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
    // Store the current plugin to put it back at the end of the function
    plugin_t *previous_plugin = cnx->current_plugin;
    proto_op_arg_t status;

    // TODO check if correct number of arg
    cnx->proto_op_inputv = pp->inputv;
    observer_node_t *obs = popst->pre;
    exec_observer_plugin(cnx, obs, pp->outputv);
    if (popst->replace)
        exec_pluglet(cnx, obs->pluglet, pp->outputv);
    else
    {
        // We are not in the context of a plugin if the we execute the core code
        cnx->current_plugin = NULL;
        status = popst->core(tls);
        memcpy(pp->outputv, &status, sizeof(proto_op_arg_t));
    }
    obs = popst->post;
    exec_observer_plugin(cnx, obs, pp->outputv);
    cnx->current_plugin = previous_plugin;
    return status;
}

void exec_observer_plugin(ptls_context_t *cnx, observer_node_t *obs, proto_op_arg_t *outputv) {
    while (obs)
    {
        exec_pluglet(cnx, obs->pluglet, outputv);
        obs = obs->next;
    }
}

void exec_pluglet(ptls_context_t *cnx, pluglet_t *pluglet, proto_op_arg_t *outputv) {
    plugin_t *p = pluglet->plugin;
    // TODO IF jit
    // How to not override the ouptput of core
    cnx->current_plugin = pluglet->plugin;
    *(outputv) = ubpf_exec(pluglet->vm, p->memory, PLUGIN_MEMORY);
}

/**
 *
 * @param tls
 * @param pid
 * @param param
 * @param outputv
 * @param nargs
 * @param ...
 */
void prepare_and_run_proto_op_noparam_helper(ptls_t *tls, proto_op_id_t *pid, param_id_t param, proto_op_arg_t *outputv, const uint nargs, ...)
{
    int i;

    va_list ap;
    va_start(ap, nargs);
    proto_op_arg_t args[nargs];
    for (i=0; i < nargs; i++)
    {
        args[i] = va_arg(ap, proto_op_arg_t);
    }
    va_end(ap);
    proto_op_params_t pp = {.id = pid, .param = &param, .caller_is_intern = true, .inputc = nargs, .inputv = args, .outputv =outputv};
    run_plugin_proto_op_internal(&pp, tls);

}
/**
 *
 */
void *get_opaque_data(ptls_context_t *cnx, opaque_id_t op_id, size_t size, bool *allocate)
{
    plugin_t *plugin = cnx->current_plugin;
    if (!plugin)
    {
        fprintf(stderr, "Only plugin can get opaque data %s: %d\n", __FILE__, __LINE__);
        return NULL;
    }
    if (op_id > OPAQUE_ID_MAX)
    {
        fprintf(stderr, "Error opaque id should be lower than %d\n", OPAQUE_ID_MAX);
        return NULL;
    }
    ptls_opaque_meta_t data = plugin->opaque_metas[op_id];
    if (data.start_ptr)
    {
        if (data.size != size)
        {
            fprintf(stderr, "Opaque data size does not correspond %s:%d\n", __FILE__, __LINE__);
            return NULL;
        }
        *(allocate) = false;
        return data.start_ptr;
    }
    data.start_ptr = my_malloc(cnx, size);
    if (!data.start_ptr)
    {
        fprintf(stderr, "Failed to allocate memory with my malloc %s: %d\n", __FILE__, __LINE__);
        return NULL;
    }
    *(allocate) = true;
    return data.start_ptr;

}
