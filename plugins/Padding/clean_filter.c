//
// Created by antoine on 28.03.20.
//

#include "utils.h"

#include <netlink/utils.h>
#include <netlink/route/tc.h>
#include <netlink/route/qdisc.h>
#include <netlink/route/qdisc/htb.h>
#include <netlink/route/cls/u32.h>
#include <netlink/socket.h>

int clean_filter (ptls_t *tls)
{
    ptls_context_t *ctx = ptls_get(tls, PTLS_CTX);

    tc_ctrl_t tc_ctrl;
    get_traffic_ctrl(ctx, &tc_ctrl);

    rtnl_qdisc_delete(tc_ctrl.sock, tc_ctrl.qdisc);
    rtnl_qdisc_put(tc_ctrl.qdisc);
    rtnl_cls_put(tc_ctrl.cls);
    rtnl_link_put(tc_ctrl.link);
    nl_cache_put(tc_ctrl.cache);
    nl_socket_free(tc_ctrl.sock);
    rtnl_class_put(tc_ctrl.class);

}
