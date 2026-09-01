#include "core/net.hpp"
#include <rte_arp.h>
#include <cstring>

struct rte_mbuf* craft_stateless_syn_ack(struct rte_mbuf* rx_mbuf, struct rte_ether_hdr* eth, struct rte_ipv4_hdr* ip, struct rte_tcp_hdr* tcp, uint32_t isn) {    
    uint16_t l4_len = sizeof(struct rte_tcp_hdr) + 4;     
    uint16_t header_len = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) + l4_len;    
    uint32_t capacity = rx_mbuf->buf_len - RTE_PKTMBUF_HEADROOM;        
    
    if (unlikely(header_len > capacity)) return nullptr;    
    
    rte_pktmbuf_reset(rx_mbuf);    
    rx_mbuf->data_len = header_len;    
    rx_mbuf->pkt_len = header_len;    
    char* pkt_data = rte_pktmbuf_mtod(rx_mbuf, char*);    
    
    const PacketTemplate& tmpl = get_tcp_template();    
    std::memcpy(pkt_data, &tmpl, sizeof(PacketTemplate));    
    
    struct rte_ether_hdr* tx_eth = reinterpret_cast<struct rte_ether_hdr*>(pkt_data);    
    rte_ether_addr_copy(&eth->src_addr, &tx_eth->dst_addr);    
    rte_ether_addr_copy(&eth->dst_addr, &tx_eth->src_addr);        
    
    struct rte_ipv4_hdr* tx_ip = reinterpret_cast<struct rte_ipv4_hdr*>(pkt_data + sizeof(struct rte_ether_hdr));    
    tx_ip->total_length = rte_cpu_to_be_16(sizeof(struct rte_ipv4_hdr) + l4_len);    
    tx_ip->src_addr = ip->dst_addr;    
    tx_ip->dst_addr = ip->src_addr;    
    
    struct rte_tcp_hdr* tx_tcp = reinterpret_cast<struct rte_tcp_hdr*>(pkt_data + sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));    
    tx_tcp->src_port = tcp->dst_port;    
    tx_tcp->dst_port = tcp->src_port;    
    tx_tcp->sent_seq = rte_cpu_to_be_32(isn);     
    tx_tcp->recv_ack = rte_cpu_to_be_32(rte_be_to_cpu_32(tcp->sent_seq) + 1);     
    tx_tcp->data_off = (l4_len / 4) << 4;    
    tx_tcp->tcp_flags = RTE_TCP_SYN_FLAG | RTE_TCP_ACK_FLAG;     
    tx_tcp->rx_win = rte_cpu_to_be_16(WINDOW_SLOTS);    
    
    uint8_t* tcp_opts = reinterpret_cast<uint8_t*>(tx_tcp + 1);    
    tcp_opts[0] = 2; // Kind: MSS    
    tcp_opts[1] = 4; // Length    
    *reinterpret_cast<uint16_t*>(tcp_opts + 2) = rte_cpu_to_be_16(1460); // Server MSS    
    
    rx_mbuf->l2_len = sizeof(struct rte_ether_hdr);    
    rx_mbuf->l3_len = sizeof(struct rte_ipv4_hdr);    
    rx_mbuf->l4_len = l4_len;    
    rx_mbuf->ol_flags |= TX_OFFLOAD_FLAGS;    
    tx_ip->hdr_checksum = 0;    
    tx_tcp->cksum = rte_ipv4_phdr_cksum(tx_ip, rx_mbuf->ol_flags);    
    
    return rx_mbuf;
}

PacketAction handle_arp_request(struct rte_mbuf *mbuf, struct rte_ether_hdr *eth_hdr, WorkerContext* ctx) {    
    struct rte_arp_hdr *arp_hdr = rte_pktmbuf_mtod_offset(mbuf, struct rte_arp_hdr *, sizeof(struct rte_ether_hdr));    
    
    if (unlikely(arp_hdr->arp_hardware != rte_cpu_to_be_16(RTE_ARP_HRD_ETHER) ||                 
    arp_hdr->arp_protocol != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4) ||                 
    arp_hdr->arp_hlen != RTE_ETHER_ADDR_LEN ||                  
    arp_hdr->arp_plen != sizeof(uint32_t) ||                    
    arp_hdr->arp_opcode   != rte_cpu_to_be_16(RTE_ARP_OP_REQUEST))) {        
        return ACTION_DROP;     
    }    
    if (arp_hdr->arp_data.arp_tip != ctx->vip) return ACTION_DROP;     
    
    rte_ether_addr_copy(&eth_hdr->src_addr, &eth_hdr->dst_addr);    
    rte_ether_addr_copy(&ctx->port_mac, &eth_hdr->src_addr);    
    rte_ether_addr_copy(&arp_hdr->arp_data.arp_sha, &arp_hdr->arp_data.arp_tha);    
    arp_hdr->arp_data.arp_tip = arp_hdr->arp_data.arp_sip;    
    rte_ether_addr_copy(&ctx->port_mac, &arp_hdr->arp_data.arp_sha);    
    arp_hdr->arp_data.arp_sip = ctx->vip;    
    arp_hdr->arp_opcode = rte_cpu_to_be_16(RTE_ARP_OP_REPLY);    
    
    return ACTION_TX;
}