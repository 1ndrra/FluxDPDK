#pragma once
#include <atomic>
#include <string_view>
#include <new>
#include <rte_hash.h>
#include "core/types.hpp"

class ZeroCopyRouter;
struct WorkerContext; 

typedef void (*RouteHandler)(struct TCB* tcb, WorkerContext* ctx, struct rte_mbuf* rx_mbuf);

struct alignas(64) GlobalTenantQoS {    
    std::atomic<uint32_t> tenant_id{0};     
    std::atomic<uint64_t> state{0}; 
};

struct alignas(64) TCB {    
    TCB* prev{nullptr};    
    TCB* next{nullptr};    
    struct rte_mbuf* ooo_head{nullptr};     
    struct rte_mbuf* rx_ready_tail{nullptr};     
    struct rte_mbuf* rx_ready_head{nullptr};     
    uint64_t last_activity_tsc{0};     
    TcpState state{STATE_CLOSED};    
    rte_be32_t rcv_nxt{0};     
    rte_be32_t snd_nxt{0};     
    uint32_t precomputed_hash{0};        
    
    struct rte_mbuf* last_parsed_mbuf{nullptr};     
    RouteHandler matched_handler{nullptr};    
    
    HttpParserState http_state{HttpParserState::EXPECT_METHOD};    
    uint32_t client_ip{0};    
    uint32_t local_ip{0};    
    uint32_t content_length{0};    
    uint32_t bytes_received{0};    
    
    TcpConnectionKey hash_key;     
    uint16_t client_port{0};    
    uint16_t client_mss{536};    
    uint16_t slab_len{0};     
    uint16_t header_len{0};     

    uint8_t frag_count{0};    
    uint8_t param_count{0};    
    bool is_straddling{false};     
    
    struct rte_ether_addr client_mac;    
    struct rte_ether_addr local_mac;    
    
    TokenFragment url_fragments[MAX_FRAGMENTS];    
    std::string_view route_params[MAX_ROUTE_PARAMS];    
    char token_slab[TOKEN_SLAB_SIZE];     
    char header_buf[MAX_HEADER_SIZE];
};

static inline void tcb_obj_init(struct rte_mempool *mp, void *arg, void *obj, unsigned obj_idx) {    
    (void)mp; (void)arg; (void)obj_idx;    
    new (obj) TCB();
 }
 
 struct alignas(RTE_CACHE_LINE_SIZE) WorkerContext {    
    uint16_t port_id;    
    uint16_t queue_id;    
    uint32_t cookie_secret;    
    uint32_t vip;    
    struct rte_ether_addr port_mac;        
    
    struct rte_hash *local_hash_map;     
    struct rte_mempool *local_tcb_pool;    
    struct rte_mempool *mbuf_pool;     
    ZeroCopyRouter* router;                  
    
    TCB* lru_head{nullptr};    
    TCB* lru_tail{nullptr};        
    
    struct rte_mbuf **bufs_to_tx;     
    int *tx_count;        
    
    uint64_t tx_alloc_drops{0};    
    uint64_t qos_alloc_drops{0};    
    
    struct rte_hash *tenant_hash{nullptr};    
    GlobalTenantQoS *tenant_qos_table{nullptr};    
    
    alignas(RTE_CACHE_LINE_SIZE) std::atomic<bool> force_quit{false};
 };
 
 extern WorkerContext* g_contexts[RTE_MAX_LCORE];
 extern std::atomic<bool> force_quit;