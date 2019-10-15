#ifndef MEMORY_H
#define MEMORY_H

#include "picotls_struct.h"

void *my_malloc(ptls_context_t *cnx, unsigned int size);
void *my_malloc_dbg(ptls_context_t *cnx, unsigned int size, char *file, int line);
void my_free(ptls_context_t *cnx, void *ptr);
void my_free_dbg(ptls_context_t *cnx, void *ptr, char *file, int line);
void *my_realloc(ptls_context_t *cnx, void *ptr, unsigned int size);

void my_free_in_core(plugin_t *p, void *ptr);

void init_memory_management(plugin_t *p);

#ifndef MAX
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#endif

#ifdef DEBUG_MEMORY_PRINTF

#define DBG_MEMORY_PRINTF_FILENAME_MAX 24
#define DBG_MEMORY_PRINTF(fmt, ...)                                                                 \
    debug_printf("%s:%u [%s]: " fmt "\n",                                                    \
        __FILE__ + MAX(DBG_MEMORY_PRINTF_FILENAME_MAX, sizeof(__FILE__)) - DBG_MEMORY_PRINTF_FILENAME_MAX, \
        __LINE__, __FUNCTION__, __VA_ARGS__)

#else

#define DBG_MEMORY_PRINTF(fmt, ...)

#endif // #ifdef DEBUG_PLUGIN_PRINTF

#endif // MEMORY_H
