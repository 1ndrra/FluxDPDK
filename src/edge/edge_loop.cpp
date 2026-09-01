#include <rte_ethdev.h>
#include <rte_cycles.h>
#include "edge/edge_loop.hpp"
#include "edge/tcp.hpp"
#include "core/net.hpp"

int rx_tcp_edge_loop(void *arg) {    
    WorkerContext* ctx = static_cast<WorkerContext*>(arg);    
    struct rte_mbuf *bufs[BURST_SIZE];    
    struct rte_mbuf *bufs_to_free[BURST_SIZE];    
    struct rte_mbuf *bufs_to_tx[BURST_SIZE];        
    
    ctx->bufs_to_tx = bufs_to_tx;        
    
    uint64_t timer_hz = rte_get_tsc_hz();    
    uint64_t timeout_cycles = timer_hz * 30;     
    uint64_t current_tsc = rte_rdtsc();    
    uint64_t loop_count = 0;    
    
    const void *keys_ptr[BURST_SIZE];    
    TcpConnectionKey tcp_keys[BURST_SIZE];    
    void *tcb_ptrs[BURST_SIZE];    
    PacketMeta meta[BURST_SIZE];    
    
    while (true) {        
        const uint16_t num_received = rte_eth_rx_burst(ctx->port_id, ctx->queue_id, bufs, BURST_SIZE);                
        
        if (unlikely(num_received == 0)) {            
            if (unlikely(force_quit.load(std::memory_order_relaxed))) break;            
            continue;         
        }        
        
        rte_compiler_barrier();        
        int free_count = 0;        
        int tx_count = 0;        
        ctx->tx_count = &tx_count;       
        uint32_t num_valid = 0;        
        
        for (int i = 0; i < num_received; i++) {            
            if (likely(i + PREFETCH_OFFSET < num_received)) {                
                rte_prefetch0(bufs[i + PREFETCH_OFFSET]);                
                rte_prefetch0(rte_pktmbuf_mtod(bufs[i + PREFETCH_OFFSET], void *));            
            }                        
            
            if (unlikely(bufs[i]->ol_flags & (RTE_MBUF_F_RX_IP_CKSUM_BAD | RTE_MBUF_F_RX_L4_CKSUM_BAD))) {                
                bufs_to_free[free_count++] = bufs[i]; continue;            
            }            
            
            if (unlikely(bufs[i]->data_len < sizeof(struct rte_ether_hdr))) {                
                bufs_to_free[free_count++] = bufs[i]; continue;            
            }            
            
            struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(bufs[i], struct rte_ether_hdr *);            
            uint16_t ether_type = rte_be_to_cpu_16(eth_hdr->ether_type);            
            
            if (unlikely(ether_type != RTE_ETHER_TYPE_IPV4)) {                
                if (ether_type == RTE_ETHER_TYPE_ARP) {                    
                    if (unlikely(bufs[i]->data_len < sizeof(struct rte_ether_hdr) + sizeof(struct rte_arp_hdr))) {                        
                        bufs_to_free[free_count++] = bufs[i]; continue;                    
                    }                    
                    if (handle_arp_request(bufs[i], eth_hdr, ctx) == ACTION_TX) bufs_to_tx[tx_count++] = bufs[i];                    
                    else bufs_to_free[free_count++] = bufs[i];                
                } else bufs_to_free[free_count++] = bufs[i];               
                 continue;            
                }            
                
                if (unlikely(bufs[i]->data_len < sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr))) {                
                    bufs_to_free[free_count++] = bufs[i]; continue;            
                }            
                
                struct rte_ipv4_hdr *ipv4_hdr = rte_pktmbuf_mtod_offset(bufs[i], struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));            
                if (unlikely(ipv4_hdr->next_proto_id != IPPROTO_TCP || (rte_be_to_cpu_16(ipv4_hdr->fragment_offset) & RTE_IPV4_HDR_OFFSET_MASK) != 0)) {                
                    bufs_to_free[free_count++] = bufs[i]; continue;            
                }                        
                
                uint8_t ip_hdr_len = (ipv4_hdr->version_ihl & RTE_IPV4_HDR_IHL_MASK) * RTE_IPV4_IHL_MULTIPLIER;                        
                
                if (unlikely(bufs[i]->data_len < sizeof(struct rte_ether_hdr) + ip_hdr_len + sizeof(struct rte_tcp_hdr))) {                
                    bufs_to_free[free_count++] = bufs[i]; continue;            
                }                        
                
                struct rte_tcp_hdr *tcp_hdr = rte_pktmbuf_mtod_offset(bufs[i], struct rte_tcp_hdr *, sizeof(struct rte_ether_hdr) + ip_hdr_len);            
                uint8_t tcp_hdr_len = (tcp_hdr->data_off >> 4) * 4;            
                
                if (unlikely(tcp_hdr_len < sizeof(struct rte_tcp_hdr) || bufs[i]->data_len < sizeof(struct rte_ether_hdr) + ip_hdr_len + tcp_hdr_len)) {                
                    bufs_to_free[free_count++] = bufs[i]; continue;            
                }            
                
                if (rte_be_to_cpu_16(tcp_hdr->dst_port) != 80) {                
                    bufs_to_free[free_count++] = bufs[i]; continue;            
                }            
                
                tcp_keys[num_valid] = {ipv4_hdr->src_addr, ipv4_hdr->dst_addr, tcp_hdr->src_port, tcp_hdr->dst_port, 0};            
                keys_ptr[num_valid] = &tcp_keys[num_valid];                        
                
                meta[num_valid].mbuf = bufs[i];            
                meta[num_valid].eth_hdr = eth_hdr;            
                meta[num_valid].ip_hdr = ipv4_hdr;            
                meta[num_valid].tcp_hdr = tcp_hdr;            
                meta[num_valid].precomputed_hash = rte_jhash(&tcp_keys[num_valid], sizeof(TcpConnectionKey), 0);                        
                
                num_valid++;        
            }        
            
            uint64_t hit_mask = 0;        
            if (likely(num_valid > 0)) {            
                rte_hash_lookup_bulk_data(ctx->local_hash_map, keys_ptr, num_valid, &hit_mask, tcb_ptrs);        
            }        
            
            for (uint32_t i = 0; i < num_valid; i++) {            
                void* tcb_ptr = (hit_mask & (1ULL << i)) ? tcb_ptrs[i] : nullptr;            
                PacketAction action = process_tcp(                
                    meta[i].mbuf, meta[i].eth_hdr, meta[i].ip_hdr, meta[i].tcp_hdr,                 
                    ctx, &tcp_keys[i], tcb_ptr, meta[i].precomputed_hash            
                );                        
                
                if (action == ACTION_DROP) bufs_to_free[free_count++] = meta[i].mbuf;            
                else if (action == ACTION_TX) bufs_to_tx[tx_count++] = meta[i].mbuf;        
            }                
            
            if (likely(tx_count > 0)) {            
                uint16_t sent = rte_eth_tx_burst(ctx->port_id, ctx->queue_id, bufs_to_tx, tx_count);            
                if (unlikely(sent < tx_count)) rte_pktmbuf_free_bulk(&bufs_to_tx[sent], tx_count - sent);        
            }        
            
            if (likely(free_count > 0)) rte_pktmbuf_free_bulk(bufs_to_free, free_count);        
            
            if (unlikely((loop_count++ & 0x3FFF) == 0)) {            
                current_tsc = rte_rdtsc();            
                while (ctx->lru_head != nullptr) {                
                    if (current_tsc - ctx->lru_head->last_activity_tsc > timeout_cycles) cleanup_tcb(ctx->lru_head, ctx);                
                    else break;            
                }        
            }    
        }    
        return 0;
    }