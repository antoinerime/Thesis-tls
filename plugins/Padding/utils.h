#include "picotls/picotls_struct.h"
#include "picotls/getset.h"
#include "picotls/plugin.h"
#include "picotls/protoop.h"

#include <netlink/utils.h>
#include <netlink/route/tc.h>
#include <netlink/route/qdisc.h>
#include <netlink/route/qdisc/htb.h>
#include <netlink/route/cls/u32.h>
#include <netlink/socket.h>
#include <time.h>


#define PTLS_MAX_ENCRYPTED_RECORD_SIZE 16406
#define PTLS_MAX_PLAINTEXT_RECORD_SIZE 16384

typedef struct
{
    struct rtnl_qdisc *qdisc;
    struct rtnl_class *class;
    struct rtnl_cls *cls;
    struct nl_sock *sock;
    struct rtnl_link *link;
    struct nl_cache *cache;
} tc_ctrl_t;

static __attribute__((always_inline)) void get_traffic_ctrl (ptls_context_t *ctx, tc_ctrl_t *tc_ctrl)
{

    int allocate = 0;
    tc_ctrl_t *ptr = (tc_ctrl_t*) get_opaque_data(ctx, 0, sizeof(tc_ctrl_t), &allocate);
    my_memcpy(tc_ctrl, ptr, sizeof(tc_ctrl_t));
}

static __attribute__((always_inline)) void set_traffic_ctrl(ptls_context_t *ctx, tc_ctrl_t tc_ctrl)
{
    int allocate = 0;
    tc_ctrl_t *ptr = (tc_ctrl_t *) get_opaque_data(ctx, 0, sizeof(tc_ctrl_t), &allocate);
    my_memcpy(ptr, &tc_ctrl, sizeof(tc_ctrl_t));
}

static __attribute__((always_inline)) void get_timer(ptls_context_t *ctx, int *timer)
{
    time_t seconds = 0;
    time(&seconds);
    time_t prev_time = 0;
    int allocate = 0;
    time_t *ptr= (time_t *) get_opaque_data(ctx, 1, sizeof(time_t), &allocate);
    my_memcpy(&prev_time, ptr, sizeof(int));
    if (!allocate)
        *timer = seconds - prev_time;
    else
        *timer = 0;
        my_memcpy(time, &seconds, sizeof(time_t));
}

static __attribute__((always_inline)) void set_time(ptls_context_t *ctx)
{
    time_t seconds = 0;
    time(&seconds);
    int allocate = 0;
    time_t *time = (time_t *) get_opaque_data(ctx, 1, sizeof(time_t), &allocate);
    my_memcpy(time, &seconds, sizeof(time_t));
}


static __attribute__((always_inline)) void set_padding(ptls_context_t *ctx, int padding)
{
    int allocate = 0;
    int *data = (int *) get_opaque_data(ctx, 2, sizeof(int), &allocate);
    my_memcpy(data, &padding, sizeof(int));
}


static __attribute__((always_inline)) void get_padding(ptls_context_t *ctx, int *padding)
{
    int allocate = 0;
    int *ptr = (int *) get_opaque_data(ctx, 2, sizeof(int), &allocate);
    my_memcpy(padding, ptr, sizeof(int));
}