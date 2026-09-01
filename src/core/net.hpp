#pragma once
#include <rte_jhash.h>
#include <rte_cycles.h>
#include <rte_byteorder.h>
#include "core/context.hpp"

static inline const PacketTemplate& get_tcp_template() {    
    static const PacketTemplate tmpl = []() {        
        PacketTemplate t{};        
        t.eth.ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);        
        t.ip.version_ihl = (4 << 4) | 5;        
        t.ip.time_to_live = 64;        
        t.ip.next_proto_id = IPPROTO_TCP;        
        t.ip.fragment_offset = rte_cpu_to_be_16(RTE_IPV4_HDR_DF_FLAG);        
        t.tcp.data_off = (sizeof(struct rte_tcp_hdr) / 4) << 4;        
        return t;    
    }();    
    return tmpl;
}

static inline uint32_t generate_cookie_hash(const TcpConnectionKey& key, uint32_t secret, uint32_t time_slot) {    
    uint32_t data[5] = {key.src_ip, key.dst_ip, (uint32_t)key.src_port << 16 | key.dst_port, secret, time_slot};    
    return rte_jhash(data, sizeof(data), 0) & 0x00FFFFFF; 
}

static inline uint32_t generate_syn_cookie(const TcpConnectionKey& key, uint32_t secret, uint16_t client_mss) {    
    uint32_t time_slot = rte_rdtsc() / (rte_get_tsc_hz() * 64);    
    uint8_t mss_idx = (client_mss >= 1460) ? 3 : ((client_mss >= 1440) ? 2 : ((client_mss >= 1300) ? 1 : 0));  
   uint32_t hash = generate_cookie_hash(key, secret, time_slot);    
   return hash | (mss_idx << 24) | ((time_slot & 0x1F) << 27);
}
   
static inline bool validate_syn_cookie(uint32_t cookie, const TcpConnectionKey& key, uint32_t secret, uint16_t& out_mss) {    
    uint32_t current_time = rte_rdtsc() / (rte_get_tsc_hz() * 64);    
    uint32_t cookie_time = (cookie >> 27) & 0x1F;    
    uint8_t mss_idx = (cookie >> 24) & 0x07;        
    
    for (int i = 0; i <= 1; ++i) {        
        uint32_t check_time = current_time - i;        
        if ((check_time & 0x1F) == cookie_time) {            
            if (generate_cookie_hash(key, secret, check_time) == (cookie & 0x00FFFFFF)) {                
                uint16_t mss_table[4] = {536, 1300, 1440, 1460};                
                out_mss = mss_table[mss_idx];                
                return true;            
            }        
        }    
    }    
    return false;
}

static inline uint16_t parse_mss_option(struct rte_tcp_hdr* tcp) {    
    uint8_t hdr_len = (tcp->data_off >> 4) * 4;    
    if (unlikely(hdr_len < sizeof(struct rte_tcp_hdr))) return 536;   
    
    uint8_t end = hdr_len - sizeof(struct rte_tcp_hdr);    
    uint8_t* opt = (uint8_t*)(tcp + 1);        
    
    for (uint8_t i = 0; i < end; ) {        
        if (opt[i] == 0) break;         
        if (opt[i] == 1) { i++; continue; }         
        if (opt[i] == 2 && i + 3 < end && opt[i+1] == 4) {             
            return rte_be_to_cpu_16(*(uint16_t*)(opt + i + 2));        
        }        
        if (opt[i+1] == 0) break;        
        i += opt[i+1];    
    }    
    return 536; 
}

struct rte_mbuf* craft_stateless_syn_ack(struct rte_mbuf* rx_mbuf, struct rte_ether_hdr* eth, struct rte_ipv4_hdr* ip, struct rte_tcp_hdr* tcp, uint32_t isn);
PacketAction handle_arp_request(struct rte_mbuf *mbuf, struct rte_ether_hdr *eth_hdr, WorkerContext* ctx);