#include <csignal>
#include <atomic>
#include <cstring>
#include <algorithm>

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_flow.h>
#include <rte_malloc.h>
#include <rte_random.h>

#include "core/context.hpp"
#include "edge/router.hpp"
#include "edge/api.hpp"
#include "edge/edge_loop.hpp"
#include "tenant/tenant_loop.hpp"

// Global Instantiations (externs declared in core/context.hpp)
WorkerContext* g_contexts[RTE_MAX_LCORE] = {nullptr};
std::atomic<bool> force_quit{false};

static void configure_flow_steering(uint16_t port_id, uint16_t* tcp_qs, uint16_t num_tcp_qs, uint16_t* udp_qs, uint16_t num_udp_qs) {    
    struct rte_flow_error error;    
    struct rte_flow_attr attr = {.ingress = 1};    
    
    if (num_tcp_qs > 0) {        
        struct rte_flow_item_tcp tcp_spec = {};        
        struct rte_flow_item_tcp tcp_mask = {};        
        tcp_spec.hdr.dst_port = rte_cpu_to_be_16(80);        
        tcp_mask.hdr.dst_port = 0xFFFF;        
        
        struct rte_flow_item tcp_items[] = {            
            { .type = RTE_FLOW_ITEM_TYPE_ETH, .spec = nullptr, .last = nullptr, .mask = nullptr },            
            { .type = RTE_FLOW_ITEM_TYPE_IPV4, .spec = nullptr, .last = nullptr, .mask = nullptr },            
            { .type = RTE_FLOW_ITEM_TYPE_TCP, .spec = &tcp_spec, .last = nullptr, .mask = &tcp_mask },            
            { .type = RTE_FLOW_ITEM_TYPE_END }        
        };        
        
        struct rte_flow_action_rss tcp_rss = {            
            .types = RTE_ETH_RSS_IP | RTE_ETH_RSS_TCP,            
            .key_len = 0,            
            .queue_num = (uint32_t)num_tcp_qs,            
            .queue = tcp_qs        
        };        
        struct rte_flow_action tcp_actions[] = {            
            { .type = RTE_FLOW_ACTION_TYPE_RSS, .conf = &tcp_rss },            
            { .type = RTE_FLOW_ACTION_TYPE_END }        
        };        
        if (!rte_flow_create(port_id, &attr, tcp_items, tcp_actions, &error)) {            
            rte_exit(EXIT_FAILURE, "TCP flow rule failed: %s\n", error.message ? error.message : "unknown");        
        }    
    }    
    
    if (num_udp_qs > 0) {        
        struct rte_flow_item udp_items[] = {            
            { .type = RTE_FLOW_ITEM_TYPE_ETH, .spec = nullptr, .last = nullptr, .mask = nullptr },            
            { .type = RTE_FLOW_ITEM_TYPE_IPV4, .spec = nullptr, .last = nullptr, .mask = nullptr },            
            { .type = RTE_FLOW_ITEM_TYPE_UDP, .spec = nullptr, .last = nullptr, .mask = nullptr },            
            { .type = RTE_FLOW_ITEM_TYPE_END }        
        };        
        struct rte_flow_action_rss udp_rss = {            
            .types = RTE_ETH_RSS_IP | RTE_ETH_RSS_UDP,            
            .key_len = 0,            
            .queue_num = (uint32_t)num_udp_qs,            
            .queue = udp_qs        
        };        
        struct rte_flow_action udp_actions[] = {            
            { .type = RTE_FLOW_ACTION_TYPE_RSS, .conf = &udp_rss },            
            { .type = RTE_FLOW_ACTION_TYPE_END }        }
            ;        
            if (!rte_flow_create(port_id, &attr, udp_items, udp_actions, &error)) {            
                rte_exit(EXIT_FAILURE, "UDP flow rule failed: %s\n", error.message ? error.message : "unknown");        
            }    
        }    
        
        uint16_t all_qs[RTE_MAX_LCORE];    
        std::memcpy(all_qs, tcp_qs, num_tcp_qs * sizeof(uint16_t));    
        std::memcpy(all_qs + num_tcp_qs, udp_qs, num_udp_qs * sizeof(uint16_t));    
        uint16_t num_all_qs = num_tcp_qs + num_udp_qs;    
        
        if (num_all_qs > 0) {        
            struct rte_flow_item_eth arp_spec = { .type = rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP) };        
            struct rte_flow_item_eth arp_mask = { .type = 0xFFFF };        
            struct rte_flow_item arp_items[] = {            
                { .type = RTE_FLOW_ITEM_TYPE_ETH, .spec = &arp_spec, .last = nullptr, .mask = &arp_mask },            
                { .type = RTE_FLOW_ITEM_TYPE_END }        
            };        
            struct rte_flow_action_rss arp_rss = {            
                .types = 0,             .key_len = 0,            
                .queue_num = (uint32_t)num_all_qs,            
                .queue = all_qs        
            };        
            struct rte_flow_action arp_actions[] = {            
                { .type = RTE_FLOW_ACTION_TYPE_RSS, .conf = &arp_rss },            
                { .type = RTE_FLOW_ACTION_TYPE_END }        
            };        
            if (!rte_flow_create(port_id, &attr, arp_items, arp_actions, &error)) {            
                rte_exit(EXIT_FAILURE, "ARP flow rule failed: %s\n", error.message ? error.message : "unknown");        
            }    
        }
    }
    
    static void signal_handler(int signum){
        if(signum == SIGINT || signum == SIGTERM){
            force_quit.store(true, std::memory_order_relaxed);
        }
    }
    int main(int argc, char *argv[]) {    
        if (rte_eal_init(argc, argv) < 0) rte_exit(EXIT_FAILURE, "EAL init failed.\n");    
        signal(SIGINT, signal_handler);    
        signal(SIGTERM, signal_handler);    
        
        rte_srand(rte_rdtsc());     
        
        uint16_t port_id = RTE_MAX_ETHPORTS;    
        RTE_ETH_FOREACH_DEV(port_id) { break; }    
        if (port_id == RTE_MAX_ETHPORTS) rte_exit(EXIT_FAILURE, "No valid port.\n");    
        
        struct rte_flow_error flow_error;    
        if (rte_flow_isolate(port_id, 1, &flow_error) < 0) {        
            rte_exit(EXIT_FAILURE, "Flow isolation failed: %s\n", flow_error.message ? flow_error.message : "unknown");    
        }    
        
        struct rte_ether_addr port_mac;    
        rte_eth_macaddr_get(port_id, &port_mac);    
        uint32_t gateway_vip = rte_cpu_to_be_32(RTE_IPV4(192, 168, 1, 50));    
        
        int socket_id = rte_eth_dev_socket_id(port_id);    
        if (socket_id == SOCKET_ID_ANY) socket_id = rte_socket_id();     
        
        uint16_t num_cores = rte_lcore_count() - 1;     
        if (num_cores == 0) num_cores = 1;     
        
        struct rte_mempool *tcp_mbuf_pool = rte_pktmbuf_pool_create("TCP_MBUF_POOL", (NUM_MBUFS * num_cores) / 2, MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, socket_id);    
        struct rte_mempool *udp_mbuf_pool = rte_pktmbuf_pool_create("UDP_MBUF_POOL", (NUM_MBUFS * num_cores) / 2, MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, socket_id);    
        
        struct rte_eth_dev_info dev_info;    
        rte_eth_dev_info_get(port_id, &dev_info);    
        struct rte_eth_conf port_conf = {};        
        
        port_conf.rxmode.mq_mode = RTE_ETH_MQ_RX_RSS;    
        port_conf.rx_adv_conf.rss_conf.rss_hf = RTE_ETH_RSS_IP | RTE_ETH_RSS_TCP | RTE_ETH_RSS_UDP;        
        
        if (dev_info.rx_offload_capa & RTE_ETH_RX_OFFLOAD_CHECKSUM) port_conf.rxmode.offloads |= RTE_ETH_RX_OFFLOAD_CHECKSUM;    
        if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_IPV4_CKSUM) port_conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_IPV4_CKSUM;    
        if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_TCP_CKSUM) port_conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_TCP_CKSUM;    
        
        rte_eth_dev_configure(port_id, num_cores, num_cores, &port_conf);    
        ZeroCopyRouter router;    
        router.add_route("/api/users/:id", handle_get_user);    
        
        uint16_t tcp_qs[RTE_MAX_LCORE];    
        uint16_t udp_qs[RTE_MAX_LCORE];    
        uint16_t num_tcp_qs = 0;    
        uint16_t num_udp_qs = 0;    
        
        uint16_t target_tcp_cores = std::max((uint16_t)1, (uint16_t)(num_cores / 4));    
        
        struct rte_hash_parameters tenant_hash_params = {0};    
        tenant_hash_params.name = "TENANT_HASH";    
        tenant_hash_params.entries = MAX_TENANTS;    
        tenant_hash_params.key_len = sizeof(uint32_t);    
        tenant_hash_params.hash_func = rte_jhash;    
        tenant_hash_params.socket_id = socket_id;    
        tenant_hash_params.extra_flag = RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY | RTE_HASH_EXTRA_FLAGS_MULTI_WRITER_ADD;    
        struct rte_hash* global_tenant_hash = rte_hash_create(&tenant_hash_params);    
        GlobalTenantQoS* global_qos_table = (GlobalTenantQoS*)rte_zmalloc_socket("GlobalQoS", sizeof(GlobalTenantQoS) * MAX_TENANTS, RTE_CACHE_LINE_SIZE, socket_id);    
        
        uint16_t q = 0;    
        unsigned int lcore_id;    
        
        RTE_LCORE_FOREACH_WORKER(lcore_id) {        
            uint16_t lcore_socket = rte_lcore_to_socket_id(lcore_id);        
            if (lcore_socket == SOCKET_ID_ANY) lcore_socket = socket_id;        
            
            WorkerContext* ctx = (WorkerContext*)rte_zmalloc_socket("WorkerCtx", sizeof(WorkerContext), RTE_CACHE_LINE_SIZE, lcore_socket);        
            if (!ctx) rte_exit(EXIT_FAILURE, "NUMA context allocation failed.\n");                
            
            g_contexts[lcore_id] = ctx;        
            ctx->port_id = port_id;        
            ctx->queue_id = q;        
            ctx->vip = gateway_vip;        
            ctx->port_mac = port_mac;        
            
            if (num_tcp_qs < target_tcp_cores) {            
                rte_eth_rx_queue_setup(port_id, q, RX_RING_SIZE, lcore_socket, nullptr, tcp_mbuf_pool);            
                rte_eth_tx_queue_setup(port_id, q, TX_RING_SIZE, lcore_socket, nullptr);            
                
                tcp_qs[num_tcp_qs++] = q;            
                char pool_name[32]; std::snprintf(pool_name, sizeof(pool_name), "TCB_POOL_%d", q);            
                char hash_name[32]; std::snprintf(hash_name, sizeof(hash_name), "TCP_HASH_%d", q);            
                ctx->local_tcb_pool = rte_mempool_create(pool_name, MAX_CONNECTIONS_PER_CORE, sizeof(TCB), 256, 0, nullptr, nullptr, tcb_obj_init, nullptr, lcore_socket, 0);            
                
                struct rte_hash_parameters hash_params = {0};            
                hash_params.name = hash_name;            
                hash_params.entries = MAX_CONNECTIONS_PER_CORE * 2.0;            
                hash_params.key_len = sizeof(TcpConnectionKey);            
                hash_params.hash_func = rte_jhash;             
                hash_params.socket_id = lcore_socket;            
                hash_params.extra_flag = 0;                         
                
                ctx->local_hash_map = rte_hash_create(&hash_params);            
                ctx->router = &router;            
                ctx->mbuf_pool = tcp_mbuf_pool;            
                ctx->cookie_secret = (uint32_t)rte_rand();             
                ctx->lru_head = nullptr;            
                ctx->lru_tail = nullptr;            
                
                rte_eal_remote_launch(rx_tcp_edge_loop, ctx, lcore_id);        
            } else {            
                rte_eth_rx_queue_setup(port_id, q, RX_RING_SIZE, lcore_socket, nullptr, udp_mbuf_pool);            
                rte_eth_tx_queue_setup(port_id, q, TX_RING_SIZE, lcore_socket, nullptr);            
                
                udp_qs[num_udp_qs++] = q;                        
                
                ctx->local_tcb_pool = nullptr;            
                ctx->local_hash_map = nullptr;            
                ctx->router = nullptr;            
                ctx->mbuf_pool = udp_mbuf_pool;            
                ctx->tenant_hash = global_tenant_hash;            
                ctx->tenant_qos_table = global_qos_table;                        
                
                rte_eal_remote_launch(rx_internal_tenant_loop, ctx, lcore_id);        
            }        
            q++;    
        }    
        
        rte_eth_dev_start(port_id);    
        rte_eth_promiscuous_enable(port_id);

        configure_flow_steering(port_id, tcp_qs, num_tcp_qs, udp_qs, num_udp_qs);    
        
        uint64_t timer_hz = rte_get_tsc_hz();        
        
        // Master Core Control Plane: GC and Signal Polling    
        while (!force_quit.load(std::memory_order_relaxed)) {        
            rte_delay_ms(1000);         
            uint64_t now_sec = rte_rdtsc() / timer_hz;                
            
            for (uint32_t k = 0; k < MAX_TENANTS; ++k) {            
                uint64_t curr_state = global_qos_table[k].state.load(std::memory_order_relaxed);            
                uint32_t last_sec = curr_state >> 32;                        
                
                if (last_sec > 0 && (now_sec - last_sec) > TENANT_IDLE_TIMEOUT_SEC) {                
                    uint32_t expired_tid = global_qos_table[k].tenant_id.load(std::memory_order_relaxed);                                
                    
                    global_qos_table[k].state.store(0, std::memory_order_relaxed);                                 
                    
                    if (rte_hash_del_key(global_tenant_hash, &expired_tid) < 0) {                    // Eviction race mitigation: benign failure if already purged                
                    
                    }            
                }        
            }    
        }    
        
        rte_eal_mp_wait_lcore();     
        
        rte_eth_dev_stop(port_id);    
        rte_eth_dev_close(port_id);    
        rte_mempool_free(tcp_mbuf_pool);     
        rte_mempool_free(udp_mbuf_pool);         
        
        RTE_LCORE_FOREACH_WORKER(lcore_id) {        
            WorkerContext* ctx = g_contexts[lcore_id];        
            if (ctx) {            
                if (ctx->local_tcb_pool) rte_mempool_free(ctx->local_tcb_pool);            
                if (ctx->local_hash_map) rte_hash_free(ctx->local_hash_map);            
                rte_free(ctx);        
            }    
        }        
        
        rte_hash_free(global_tenant_hash);    
        rte_free(global_qos_table);    
        
        rte_eal_cleanup();    
        return 0;
    }