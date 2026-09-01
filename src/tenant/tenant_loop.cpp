#include <algorithm>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_udp.h>
#include "tenant/tenant_loop.hpp"
#include "tenant/hypervisor.hpp"

int rx_internal_tenant_loop(void *arg) {    
    WorkerContext* ctx = static_cast<WorkerContext*>(arg);    
    struct rte_mbuf *bufs[BURST_SIZE];    
    struct rte_mbuf *bufs_to_free[BURST_SIZE];        
    
    uint64_t timer_hz = rte_get_tsc_hz();        
    
    while (true) {        
        const uint16_t num_received = rte_eth_rx_burst(ctx->port_id, ctx->queue_id, bufs, BURST_SIZE);                
        
        if (unlikely(num_received == 0)) {            
            if (unlikely(force_quit.load(std::memory_order_relaxed))) break;            
            continue;         
        }        
        
        int free_count = 0;        
        uint64_t current_tsc = rte_rdtsc();        
        uint32_t current_sec = current_tsc / timer_hz;        
        
        for (int i = 0; i < num_received; i++) {            
            if (likely(i + PREFETCH_OFFSET < num_received)) {                
                rte_prefetch0(bufs[i + PREFETCH_OFFSET]);                
                rte_prefetch0(rte_pktmbuf_mtod(bufs[i + PREFETCH_OFFSET], void *));            
            }                        
            
            if (unlikely(bufs[i]->ol_flags & (RTE_MBUF_F_RX_IP_CKSUM_BAD | RTE_MBUF_F_RX_L4_CKSUM_BAD))) {                
                bufs_to_free[free_count++] = bufs[i]; continue;            
            }                       
            
            if (unlikely(bufs[i]->data_len < sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_udp_hdr) + sizeof(InternalComputeHeader))) {                
                bufs_to_free[free_count++] = bufs[i]; continue;            
            }            
            
            struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(bufs[i], struct rte_ether_hdr *);            
            if (unlikely(rte_be_to_cpu_16(eth_hdr->ether_type) != RTE_ETHER_TYPE_IPV4)) {                
                bufs_to_free[free_count++] = bufs[i]; continue;            
            }            
            
            struct rte_ipv4_hdr *ipv4_hdr = rte_pktmbuf_mtod_offset(bufs[i], struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));            
            if (unlikely(ipv4_hdr->next_proto_id != IPPROTO_UDP)) {                
                bufs_to_free[free_count++] = bufs[i]; continue;            
            }                        
            
            uint8_t ip_hdr_len = (ipv4_hdr->version_ihl & RTE_IPV4_HDR_IHL_MASK) * RTE_IPV4_IHL_MULTIPLIER;            
            InternalComputeHeader* internal_hdr = rte_pktmbuf_mtod_offset(bufs[i], InternalComputeHeader*, sizeof(struct rte_ether_hdr) + ip_hdr_len + sizeof(struct rte_udp_hdr));            
            
            uint32_t required_len = sizeof(struct rte_ether_hdr) + ip_hdr_len + sizeof(struct rte_udp_hdr) + sizeof(InternalComputeHeader) + internal_hdr->payload_length;            
            if (unlikely(bufs[i]->data_len < required_len)) {                
                bufs_to_free[free_count++] = bufs[i]; continue;            
            }            
            
            uint32_t tid = internal_hdr->tenant_id;            
            int idx = rte_hash_lookup(ctx->tenant_hash, &tid);                        
            
            if (unlikely(idx < 0)) {                
                idx = rte_hash_add_key(ctx->tenant_hash, &tid);                
                if (unlikely(idx < 0)) {                    
                    ctx->qos_alloc_drops++;                    
                    bufs_to_free[free_count++] = bufs[i]; continue;                
                }                
                ctx->tenant_qos_table[idx].tenant_id.store(tid, std::memory_order_relaxed);                                
                
                uint64_t initial_state = ((uint64_t)current_sec << 32) | (uint32_t)TENANT_TOKENS_PER_SEC;                
                uint64_t expected_state = 0;                
                ctx->tenant_qos_table[idx].state.compare_exchange_strong(expected_state, initial_state, std::memory_order_acq_rel);            
            }            
            
            GlobalTenantQoS& qos = ctx->tenant_qos_table[idx];            
            uint64_t curr_state = qos.state.load(std::memory_order_relaxed);           
            bool consumed = false;                        
            
            do {                
                uint32_t last_sec = (curr_state >> 32) & 0xFFFFFFFF;                
                int32_t curr_tokens = curr_state & 0xFFFFFFFF;                               
                
                uint32_t elapsed = current_sec - last_sec;                
                if (elapsed > 0) {                   
                    int64_t increment = (int64_t)elapsed * TENANT_TOKENS_PER_SEC;                    
                    curr_tokens = std::min((int64_t)TENANT_TOKENS_PER_SEC, curr_tokens + increment);                    
                    last_sec = current_sec;                 
                }                                
                
                if (curr_tokens <= 0) break;                 
                curr_tokens--;                                
                
                uint64_t next_state = ((uint64_t)last_sec << 32) | (uint32_t)curr_tokens;                
                consumed = qos.state.compare_exchange_weak(curr_state, next_state, std::memory_order_relaxed);            
            } while (!consumed);           
            
            if (unlikely(!consumed)) {                
                bufs_to_free[free_count++] = bufs[i]; continue;            
            }            
            
            bool dispatch_consumed = hypervisor_dispatch_compute(internal_hdr->tenant_id, internal_hdr->command_opcode, internal_hdr, bufs[i]);                        
            
            if (!dispatch_consumed) {                
                bufs_to_free[free_count++] = bufs[i];             
            }        
        }                
        
        if (likely(free_count > 0)) rte_pktmbuf_free_bulk(bufs_to_free, free_count);    
    }    
    return 0;
}