#include <netlink/utils.h>
#include <netlink/route/tc.h>
#include <netlink/route/qdisc.h>
#include <netlink/route/qdisc/htb.h>
#include <netlink/route/cls/u32.h>
#include <netlink/socket.h>
#include <ifaddrs.h>
#include <linux/if_ether.h>

#include "picotls/picotls_struct.h"
#include "picotls/getset.h"
#include "picotls/picotls_struct.h"
#include "picotls/plugin.h"
#include "utils.h"

int set_filter(ptls_t *tls)
{
    ptls_context_t *ctx = (ptls_context_t *) ptls_get(tls, PTLS_CTX);
    int sockfd = (int) ptls_get_ctx(tls, CTX_PROTO_OP_INPUT, 0);
    const char *server_name = (const char *) ptls_get_ctx(tls, CTX_PROTO_OP_INPUT, 1);
    const char *input_file = (const char *) ptls_get_ctx(tls, CTX_PROTO_OP_INPUT, 2);
    ptls_handshake_properties_t *hsprop = (ptls_handshake_properties_t *) ptls_get_ctx(tls, CTX_PROTO_OP_INPUT, 3);
    int request_key_update = (int) ptls_get_ctx(tls, CTX_PROTO_OP_INPUT, 4);
    int keep_sender_open = (int) ptls_get_ctx(tls, CTX_PROTO_OP_INPUT, 5);
    char* plugins = (char *) ptls_get_ctx(tls, CTX_PROTO_OP_INPUT, 6);
    int number_of_plugins = (int) ptls_get_ctx(tls, CTX_PROTO_OP_INPUT, 7);

    // Get connection information
    struct sockaddr_in s_sa, d_sa;
    // struct sockaddr_in d_sa;
    socklen_t s_sa_len = sizeof(s_sa);
    socklen_t d_sa_len = sizeof(d_sa);
    struct ifaddrs* ifaddr;
    struct ifaddrs* ifa;
    char iface[20];
    int err;
    err = getsockname(sockfd, &s_sa, &s_sa_len);
    getifaddrs(&ifaddr);
    // look which interface contains the wanted IP.
    // When found, ifa->ifa_name contains the name of the interface (eth0, eth1, ppp0...)
    help_printf_str("60\n");
    // for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
    // {
    //     if (ifa->ifa_addr)
    //     {
    //         if (AF_INET == ifa->ifa_addr->sa_family)
    //         {
    //             struct sockaddr_in* inaddr = (struct sockaddr_in*)ifa->ifa_addr;

    //             if (inaddr->sin_addr.s_addr == s_sa.sin_addr.s_addr)
    //             {
    //                 if (ifa->ifa_name)
    //                 {
    //                     help_printf_str("60\n");
    //                     strncpy(iface, ifa->ifa_name, 20);
    //                     help_printf_str("60\n");
    //                 }
    //             }
    //         }
    //     }
    // }
    help_printf_str("end loop\n");
    freeifaddrs(ifaddr);

    err = getpeername(sockfd, &d_sa, &d_sa_len);



    // Setup qdisc for conection
    struct nl_cache_mngr *mngr;



    // Allocate a new cache manager for RTNETLINK and automatically

    // provide the caches added to the manager.

    help_printf_str("start sock\n");
    struct nl_sock *sock = nl_socket_alloc();
    nl_connect(sock, NETLINK_ROUTE);

    help_printf_str("alloc sock\n");
    struct nl_cache *cache;

    struct rtnl_link *link;

    if (rtnl_link_alloc_cache(sock, AF_UNSPEC, &cache) < 0)
        perror("alloc_cache() failed");

    if (!(link = rtnl_link_get_by_name(cache, "enp3s0")))
        perror("link get by name() failed");
    // err = rtnl_link_get_kernel(sock, 2, "enp3so", &link);
    // if (err)
    //     fprintf(stderr, "Unable to get link kernel: %s\n", nl_geterror(err));

    struct rtnl_qdisc *qdisc;

    qdisc = rtnl_qdisc_alloc();
    // rtnl_qdisc_tbf_set_rate(qdisc, 1000, 1000, 0);

    rtnl_tc_set_link(TC_CAST(qdisc), link);
    rtnl_tc_set_parent(TC_CAST(qdisc), TC_H_ROOT);
    rtnl_tc_set_handle(TC_CAST(qdisc), TC_HANDLE(1, 0));
    rtnl_tc_set_kind(TC_CAST(qdisc), "htb");

    // rtnl_htb_set_defcls(qdisc, TC_HANDLE(1, 5));


    err = rtnl_qdisc_add(sock, qdisc, NLM_F_CREATE);
    if (err < 0) {
        // fprintf(stderr, "rtnl_qdisc_add failed: %s\n", nl_geterror(err));
    }
    // Create new class
    struct rtnl_class *class = rtnl_class_alloc();
    rtnl_tc_set_link(TC_CAST(class), link);
    rtnl_tc_set_parent(TC_CAST(class), TC_HANDLE(1, 0));
    rtnl_tc_set_handle(TC_CAST(class), TC_HANDLE(1, 1));

    err = rtnl_tc_set_kind(TC_CAST(class), "htb");
    if (err < 0) {
        // fprintf(stderr, "rtnl_tc_set_kind failed: %s\n", nl_geterror(err));
    }

    rtnl_htb_set_prio(class, 0);
    rtnl_htb_set_rate(class, 10000);

    err = rtnl_class_add(sock, class, NLM_F_CREATE);
    if (err < 0) {
        // fprintf(stderr, "rtnl_class_add failed: %s\n", nl_geterror(err));
    }
   // Create new classifier
    struct rtnl_cls *cls = rtnl_cls_alloc();
    rtnl_tc_set_link(TC_CAST(cls), link);
    rtnl_tc_set_kind(TC_CAST(cls), "u32");
    rtnl_cls_set_prio(cls, 1);
    rtnl_cls_set_protocol(cls, ETH_P_IP);
    rtnl_tc_set_parent(TC_CAST(cls), TC_HANDLE(1, 0));

    //uint32_t direction = 12 // Src IP
    uint32_t direction = 16; //dst IP

    // uint32_t dist_addr = ntohl(d_sa.sin_addr.s_addr);
    rtnl_u32_add_key_uint32(cls, d_sa.sin_addr.s_addr, 0xffffffff, direction, 0);
    rtnl_u32_set_classid(cls, TC_HANDLE(1, 1));
    rtnl_u32_set_cls_terminal(cls);

    err = rtnl_cls_add(sock, cls, NLM_F_CREATE);
    if (err < 0) {
        // fprintf(stderr, "rtnl_cls_add child failed: %s\n", nl_geterror(err));
    }

    tc_ctrl_t tc_ctrl = {qdisc, class, cls, sock, link, cache};
    set_traffic_ctrl(ctx, tc_ctrl);
    set_time(ctx);

}