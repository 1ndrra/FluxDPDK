#include <charconv>
#include <algorithm>
#include <cstring>
#include <rte_cycles.h>

#include "edge/tcp.hpp"
#include "edge/api.hpp"
#include "core/net.hpp"
#include "edge/router.hpp"

void send_tcp_segment(TCB* tcb, WorkerContext* ctx, const char* payload, size_t payload_len, uint8_t flags, struct rte_mbuf* reuse_mbuf) {    
    struct rte_mbuf* tx_mbuf = reuse_mbuf;    
    constexpr uint16_t hdr_len = sizeof(PacketTemplate);        
    
    if (tx_mbuf && unlikely(hdr_len + payload_len > tx_mbuf->buf_len - RTE_PKTMBUF_HEADROOM)) {        
        rte_pktmbuf_free(tx_mbuf);        
        tx_mbuf = nullptr;    
    }    
    
    if (!tx_mbuf) {        
        tx_mbuf = rte_pktmbuf_alloc(ctx->mbuf_pool);        
        if (unlikely(!tx_mbuf)) {            
            ctx->tx_alloc_drops++;            
            return;         
        }    
    } else {       
         rte_pktmbuf_reset(tx_mbuf);    
    }        
    
    tx_mbuf->data_len = hdr_len + payload_len;    
    tx_mbuf->pkt_len = hdr_len + payload_len;    
    char* pkt_data = rte_pktmbuf_mtod(tx_mbuf, char*);        
    
    const PacketTemplate& tmpl = get_tcp_template();    
    std::memcpy(pkt_data, &tmpl, sizeof(PacketTemplate));         
    
    struct rte_ether_hdr* eth_hdr = reinterpret_cast<struct rte_ether_hdr*>(pkt_data);    
    rte_ether_addr_copy(&tcb->client_mac, &eth_hdr->dst_addr);    
    rte_ether_addr_copy(&tcb->local_mac, &eth_hdr->src_addr);        
    
    struct rte_ipv4_hdr* ipv4_hdr = reinterpret_cast<struct rte_ipv4_hdr*>(pkt_data + sizeof(struct rte_ether_hdr));    
    ipv4_hdr->total_length = rte_cpu_to_be_16(sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_tcp_hdr) + payload_len);    
    ipv4_hdr->src_addr = tcb->local_ip;    
    ipv4_hdr->dst_addr = tcb->client_ip;        
    
    struct rte_tcp_hdr* tcp_hdr = reinterpret_cast<struct rte_tcp_hdr*>(pkt_data + sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));    
    tcp_hdr->src_port = rte_cpu_to_be_16(80);    
    tcp_hdr->dst_port = tcb->client_port;    
    tcp_hdr->sent_seq = tcb->snd_nxt;    
    tcp_hdr->recv_ack = tcb->rcv_nxt;    
    tcp_hdr->tcp_flags = flags;    
    tcp_hdr->rx_win = rte_cpu_to_be_16(WINDOW_SLOTS);        
    
    if (payload_len > 0 && payload != nullptr) std::memcpy(pkt_data + hdr_len, payload, payload_len);        
    
    tx_mbuf->l2_len = sizeof(struct rte_ether_hdr);    
    tx_mbuf->l3_len = sizeof(struct rte_ipv4_hdr);    
    tx_mbuf->l4_len = sizeof(struct rte_tcp_hdr);    
    tx_mbuf->ol_flags |= TX_OFFLOAD_FLAGS;    
    ipv4_hdr->hdr_checksum = 0;    
    tcp_hdr->cksum = rte_ipv4_phdr_cksum(ipv4_hdr, tx_mbuf->ol_flags);        
    
    tcb->snd_nxt = rte_cpu_to_be_32(rte_be_to_cpu_32(tcb->snd_nxt) + payload_len);    
    ctx->bufs_to_tx[(*ctx->tx_count)++] = tx_mbuf;
}

void cleanup_tcb(TCB* tcb, WorkerContext* ctx, struct rte_mbuf* pending_chain) {    
    struct rte_mbuf* current_ooo = tcb->ooo_head;    
    while (current_ooo != nullptr) {        
        struct rte_mbuf* next = current_ooo->next;        
        rte_pktmbuf_free(current_ooo);        
        current_ooo = next;    
    }    
    
    struct rte_mbuf* current_ready = tcb->rx_ready_head;    
    while (current_ready != nullptr) {        
        struct rte_mbuf* next = current_ready->next;        
        rte_pktmbuf_free(current_ready);        
        current_ready = next;    
    }    
    
    while (pending_chain != nullptr) {        
        struct rte_mbuf* next = pending_chain->next;        
        rte_pktmbuf_free(pending_chain);        
        pending_chain = next;    
    }    
    
    if (tcb->prev) tcb->prev->next = tcb->next; else ctx->lru_head = tcb->next;    
    if (tcb->next) tcb->next->prev = tcb->prev; else ctx->lru_tail = tcb->prev;    
    
    rte_hash_del_key_with_hash(ctx->local_hash_map, &tcb->hash_key, tcb->precomputed_hash);        
    
    tcb->state = STATE_CLOSED;    
    tcb->ooo_head = nullptr;    
    tcb->rx_ready_head = nullptr;    
    tcb->rx_ready_tail = nullptr;    
    tcb->last_parsed_mbuf = nullptr;    
    tcb->prev = nullptr;    
    tcb->next = nullptr;    
    tcb->frag_count = 0;    
    tcb->slab_len = 0;    
    tcb->is_straddling = false;    
    tcb->header_len = 0;    
    tcb->param_count = 0;    
    tcb->content_length = 0;    
    tcb->bytes_received = 0;    
    tcb->matched_handler = nullptr;    
    tcb->http_state = HttpParserState::EXPECT_METHOD;    
    
    rte_mempool_put(ctx->local_tcb_pool, tcb);
}

static inline std::string_view get_mbuf_payload_view(struct rte_mbuf* mbuf) {    
    char* payload = rte_pktmbuf_mtod(mbuf, char*);    
    return std::string_view(payload, mbuf->data_len);
}

static ParseStatus http_fsm_parse_chunk(TCB* tcb, WorkerContext* ctx, std::string_view chunk, size_t& pos) {    
    while (pos < chunk.length()) {        
        switch (tcb->http_state) {            
            case HttpParserState::EXPECT_METHOD: {                
                size_t space_idx = chunk.find(' ', pos);                
                if (space_idx != std::string_view::npos) {                    
                    pos = space_idx + 1;                    
                    tcb->frag_count = 0;                    
                    tcb->is_straddling = false;                    
                    tcb->http_state = HttpParserState::EXPECT_URL;                
                } else {                    
                    if (tcb->frag_count < MAX_FRAGMENTS) tcb->url_fragments[tcb->frag_count++] = {chunk.data() + pos, chunk.length() - pos};                    
                    else return ParseStatus::ERROR;                    
                    tcb->is_straddling = true;                    
                    return ParseStatus::NEED_MORE_DATA;                
                }                
                break;            
            }            
            case HttpParserState::EXPECT_URL: {                
                size_t space_idx = chunk.find(' ', pos);                
                if (space_idx != std::string_view::npos) {                    
                    if (tcb->is_straddling) {                        
                        if (tcb->frag_count < MAX_FRAGMENTS) tcb->url_fragments[tcb->frag_count++] = {chunk.data() + pos, space_idx - pos};                        
                        else return ParseStatus::ERROR;                    
                    } else {                        
                        tcb->url_fragments[0] = {chunk.data() + pos, space_idx - pos};                        
                        tcb->frag_count = 1;                    
                    }                    
                    ctx->router->dispatch_fragmented(tcb, ctx);                    
                    pos = space_idx + 1;                    
                    tcb->http_state = HttpParserState::EXPECT_HEADERS;                 
                } else {                    
                    if (tcb->frag_count < MAX_FRAGMENTS) tcb->url_fragments[tcb->frag_count++] = {chunk.data() + pos, chunk.length() - pos};                    
                    else return ParseStatus::ERROR;                    
                    tcb->is_straddling = true;                    
                    return ParseStatus::NEED_MORE_DATA;                
                }                
                break;            
            }            
            case HttpParserState::EXPECT_HEADERS: {                
                if (likely(tcb->header_len == 0)) {                    
                    size_t rnrn_idx = chunk.find("\r\n\r\n", pos);                    
                    if (likely(rnrn_idx != std::string_view::npos)) {                        
                        size_t cl_pos = chunk.find("Content-Length: ", pos);                        
                        if (cl_pos != std::string_view::npos && cl_pos < rnrn_idx) {                            
                            cl_pos += 16;                            
                            size_t end_line = chunk.find("\r\n", cl_pos);                            
                            if (end_line != std::string_view::npos && end_line <= rnrn_idx) {                                
                                std::from_chars(chunk.data() + cl_pos, chunk.data() + end_line, tcb->content_length);                            
                            }                        }                        
                            pos = rnrn_idx + 4;                        
                            if (tcb->content_length > 0) tcb->http_state = HttpParserState::EXPECT_BODY;                        
                            else return ParseStatus::DONE;                        
                            break;                    
                        }                
                    }                
                    size_t remaining = chunk.length() - pos;                
                    size_t to_copy = std::min(remaining, (size_t)(MAX_HEADER_SIZE - tcb->header_len));                                
                    
                    uint16_t prior_len = tcb->header_len;                
                    size_t search_start = (prior_len >= 3) ? (prior_len - 3) : 0;                                
                    
                    std::memcpy(tcb->header_buf + prior_len, chunk.data() + pos, to_copy);                
                    std::string_view h_view(tcb->header_buf, prior_len + to_copy);                
                    size_t rnrn_idx = h_view.find("\r\n\r\n", search_start);                                
                    
                    if (rnrn_idx != std::string_view::npos) {                    
                        size_t cl_pos = h_view.find("Content-Length: ");                    
                        if (cl_pos != std::string_view::npos && cl_pos < rnrn_idx) {                        
                            cl_pos += 16;                        
                            size_t end_line = h_view.find("\r\n", cl_pos);                        
                            if (end_line != std::string_view::npos && end_line <= rnrn_idx) {                            
                                std::from_chars(h_view.data() + cl_pos, h_view.data() + end_line, tcb->content_length);                        
                            }                    
                        }                                        
                        
                        size_t newly_consumed = (rnrn_idx + 4) - prior_len;                    
                        pos += newly_consumed;                                        
                        
                        if (tcb->content_length > 0) tcb->http_state = HttpParserState::EXPECT_BODY;                    
                        else return ParseStatus::DONE;                 
                    } else {                    
                        tcb->header_len = prior_len + to_copy;                    
                        if (tcb->header_len >= MAX_HEADER_SIZE) return ParseStatus::ERROR;                                         
                        
                        pos += to_copy;                    
                        return ParseStatus::NEED_MORE_DATA;                
                    }                
                    break;            
                }            
                case HttpParserState::EXPECT_BODY: {                
                    size_t remaining_in_chunk = chunk.length() - pos;                
                    tcb->bytes_received += remaining_in_chunk;                
                    pos = chunk.length();                                 
                    
                    if (tcb->bytes_received >= tcb->content_length) return ParseStatus::DONE;                
                    return ParseStatus::NEED_MORE_DATA;            
                }        
            }    
        }    
        return ParseStatus::NEED_MORE_DATA;
    }
    
    static PacketAction handle_established(TCB* tcb, struct rte_mbuf* mbuf, struct rte_tcp_hdr* tcp_hdr, WorkerContext* ctx, uint32_t total_header_len) {    
        if (unlikely(mbuf->data_len < total_header_len)) return ACTION_DROP;    
        
        uint32_t pkt_seq = rte_be_to_cpu_32(tcp_hdr->sent_seq);    
        uint32_t expected_seq = rte_be_to_cpu_32(tcb->rcv_nxt);    
        int32_t seq_diff = (int32_t)(pkt_seq - expected_seq);    
        uint32_t payload_len = mbuf->data_len - total_header_len;    
        
        if (payload_len == 0 || seq_diff < 0) return ACTION_DROP;         
        
        if (seq_diff > 0) {        
            struct rte_mbuf** current = &tcb->ooo_head;        
            while (*current != nullptr) {            
                uint8_t current_ip_hlen = (rte_pktmbuf_mtod_offset(*current, struct rte_ipv4_hdr*, sizeof(struct rte_ether_hdr))->version_ihl & RTE_IPV4_HDR_IHL_MASK) * RTE_IPV4_IHL_MULTIPLIER;            
                struct rte_tcp_hdr* buffered_tcp = rte_pktmbuf_mtod_offset(*current, struct rte_tcp_hdr*, sizeof(struct rte_ether_hdr) + current_ip_hlen);            
                uint32_t buffered_seq = rte_be_to_cpu_32(buffered_tcp->sent_seq);            
                if (pkt_seq < buffered_seq) break;             
                if (pkt_seq == buffered_seq) return ACTION_DROP;             
                current = &(*current)->next;        
            }        
            mbuf->next = *current;        
            *current = mbuf;        
            return ACTION_KEEP;     
        }        
        
        rte_pktmbuf_adj(mbuf, total_header_len);     
        mbuf->next = nullptr;        
        
        if (!tcb->rx_ready_head) { tcb->rx_ready_head = mbuf; tcb->rx_ready_tail = mbuf; }     
        else { tcb->rx_ready_tail->next = mbuf; tcb->rx_ready_tail = mbuf; }    
        expected_seq += payload_len;        
        
        while (tcb->ooo_head != nullptr) {        
            struct rte_mbuf* ooo_mbuf = tcb->ooo_head;        
            uint8_t ooo_ip_hlen = (rte_pktmbuf_mtod_offset(ooo_mbuf, struct rte_ipv4_hdr*, sizeof(struct rte_ether_hdr))->version_ihl & RTE_IPV4_HDR_IHL_MASK) * RTE_IPV4_IHL_MULTIPLIER;        
            struct rte_tcp_hdr* ooo_tcp = rte_pktmbuf_mtod_offset(ooo_mbuf, struct rte_tcp_hdr*, sizeof(struct rte_ether_hdr) + ooo_ip_hlen);        
            uint32_t ooo_seq = rte_be_to_cpu_32(ooo_tcp->sent_seq);                
            
            if (ooo_seq == expected_seq) {            
                tcb->ooo_head = ooo_mbuf->next;            
                uint32_t ooo_hdr_len = sizeof(struct rte_ether_hdr) + ooo_ip_hlen + ((ooo_tcp->data_off >> 4) * 4);            
                uint32_t ooo_payload_len = ooo_mbuf->data_len - ooo_hdr_len;            
                rte_pktmbuf_adj(ooo_mbuf, ooo_hdr_len);            
                ooo_mbuf->next = nullptr;            
                tcb->rx_ready_tail->next = ooo_mbuf;            
                tcb->rx_ready_tail = ooo_mbuf;            
                expected_seq += ooo_payload_len;        
            } else break;    
        }        
        
        tcb->rcv_nxt = rte_cpu_to_be_32(expected_seq);    
        
        struct rte_mbuf* current_mbuf = tcb->last_parsed_mbuf ? tcb->last_parsed_mbuf->next : tcb->rx_ready_head;    
        ParseStatus status = ParseStatus::NEED_MORE_DATA;    
        
        while (current_mbuf != nullptr) {        
            std::string_view chunk = get_mbuf_payload_view(current_mbuf);        
            size_t pos = 0;        
            status = http_fsm_parse_chunk(tcb, ctx, chunk, pos);        
            tcb->last_parsed_mbuf = current_mbuf;         
            if (status == ParseStatus::DONE || status == ParseStatus::ERROR) break;         
            current_mbuf = current_mbuf->next;    
        }    
        
        if (status == ParseStatus::DONE) {        
            struct rte_mbuf* head_mbuf = tcb->rx_ready_head;        
            struct rte_mbuf* next_mbuf = head_mbuf->next;                
            
            tcb->rx_ready_head = nullptr;        
            tcb->rx_ready_tail = nullptr;        
            
            if (likely(tcb->matched_handler != nullptr)) tcb->matched_handler(tcb, ctx, head_mbuf);        
            else send_static_error(tcb, ctx, 404, head_mbuf);                
            
            if (unlikely(tcb->state == STATE_CLOSED)) {            
                cleanup_tcb(tcb, ctx);            
                struct rte_mbuf* free_ptr = next_mbuf;            
                while (free_ptr != nullptr) {                
                    struct rte_mbuf* next = free_ptr->next;                
                    rte_pktmbuf_free(free_ptr);                
                    free_ptr = next;            
                }            
                return ACTION_KEEP;         
            }                
            
            tcb->http_state = HttpParserState::EXPECT_METHOD;        
            tcb->frag_count = 0;        
            tcb->slab_len = 0;         
            tcb->is_straddling = false;        
            tcb->header_len = 0;        
            tcb->param_count = 0;        
            tcb->content_length = 0;        
            tcb->bytes_received = 0;        
            tcb->matched_handler = nullptr;        
            tcb->last_parsed_mbuf = nullptr;                 
            
            struct rte_mbuf* free_ptr = next_mbuf;        
            while (free_ptr != nullptr) {            
                struct rte_mbuf* next = free_ptr->next;            
                rte_pktmbuf_free(free_ptr);            
                free_ptr = next;        
            }                
            
            return ACTION_KEEP;     
        }     
        else if (status == ParseStatus::ERROR) {        
            cleanup_tcb(tcb, ctx);        
            return ACTION_KEEP;     
        }        
        
        return ACTION_KEEP;
    }
    
    PacketAction process_tcp(    
        struct rte_mbuf *mbuf, struct rte_ether_hdr *eth_hdr,     
        struct rte_ipv4_hdr *ipv4_hdr, struct rte_tcp_hdr *tcp_hdr,     
        WorkerContext* ctx, const TcpConnectionKey* key, void* tcb_ptr, uint32_t precomputed_hash) 
        {    
            if (unlikely(tcb_ptr == nullptr)) {        
                if (tcp_hdr->tcp_flags & RTE_TCP_SYN_FLAG) {            
                    uint16_t client_mss = parse_mss_option(tcp_hdr);            
                    uint32_t isn = generate_syn_cookie(*key, ctx->cookie_secret, client_mss);            
                    struct rte_mbuf* tx_packet = craft_stateless_syn_ack(mbuf, eth_hdr, ipv4_hdr, tcp_hdr, isn);            
                    if (tx_packet) {                
                        ctx->bufs_to_tx[(*ctx->tx_count)++] = tx_packet;                
                        return ACTION_KEEP;            
                    }            
                    return ACTION_DROP;        
                }         
                else if ((tcp_hdr->tcp_flags & RTE_TCP_ACK_FLAG) != 0) {            
                    uint16_t recovered_mss = 536;            
                    uint32_t expected_isn = rte_be_to_cpu_32(tcp_hdr->recv_ack) - 1;                        
                    if (!validate_syn_cookie(expected_isn, *key, ctx->cookie_secret, recovered_mss)) return ACTION_DROP;                         
                    
                    if (unlikely(rte_mempool_get(ctx->local_tcb_pool, &tcb_ptr) < 0)) return ACTION_DROP;                         
                    
                    TCB* tcb = static_cast<TCB*>(tcb_ptr);            
                    tcb->client_ip = ipv4_hdr->src_addr;            
                    tcb->local_ip = ipv4_hdr->dst_addr;            
                    tcb->client_port = tcp_hdr->src_port;            
                    rte_ether_addr_copy(&eth_hdr->src_addr, &tcb->client_mac);            
                    rte_ether_addr_copy(&eth_hdr->dst_addr, &tcb->local_mac);            
                    
                    tcb->hash_key = *key;            
                    tcb->precomputed_hash = precomputed_hash;            
                    
                    if (ctx->lru_tail) { ctx->lru_tail->next = tcb; tcb->prev = ctx->lru_tail; ctx->lru_tail = tcb; }             
                    else { ctx->lru_head = ctx->lru_tail = tcb; }            
                    
                    tcb->rcv_nxt = rte_cpu_to_be_32(rte_be_to_cpu_32(tcp_hdr->sent_seq));             
                    tcb->snd_nxt = rte_cpu_to_be_32(expected_isn + 1);             
                    tcb->state = STATE_ESTABLISHED;            
                    tcb->client_mss = recovered_mss;            
                    tcb->last_activity_tsc = rte_rdtsc();            
                    
                    if (unlikely(rte_hash_add_key_with_hash_data(ctx->local_hash_map, key, precomputed_hash, tcb_ptr) < 0)) {                
                        cleanup_tcb(tcb, ctx);                
                        return ACTION_DROP;            
                    }                        
                    
                    uint8_t ip_hlen = (ipv4_hdr->version_ihl & RTE_IPV4_HDR_IHL_MASK) * RTE_IPV4_IHL_MULTIPLIER;            
                    uint32_t total_hdr_len = sizeof(struct rte_ether_hdr) + ip_hlen + ((tcp_hdr->data_off >> 4) * 4);                        
                    
                    if (unlikely(mbuf->data_len < total_hdr_len)) return ACTION_DROP;                         
                    
                    if (mbuf->data_len > total_hdr_len) {                
                        return handle_established(tcb, mbuf, tcp_hdr, ctx, total_hdr_len);            
                    }            
                    return ACTION_DROP;         
                }        
                return ACTION_DROP;    
            }         
            
            TCB* tcb = static_cast<TCB*>(tcb_ptr);    
            
            if (tcb != ctx->lru_tail) {        
                if (tcb->prev) tcb->prev->next = tcb->next; else ctx->lru_head = tcb->next;        
                if (tcb->next) tcb->next->prev = tcb->prev;        
                tcb->next = nullptr; tcb->prev = ctx->lru_tail;        
                ctx->lru_tail->next = tcb; ctx->lru_tail = tcb;    
            }    
            tcb->last_activity_tsc = rte_rdtsc();    
            
            if (unlikely((tcp_hdr->tcp_flags & RTE_TCP_RST_FLAG) != 0)) {        
                uint32_t seq = rte_be_to_cpu_32(tcp_hdr->sent_seq);        
                uint32_t rcv_nxt = rte_be_to_cpu_32(tcb->rcv_nxt);        
                if (seq >= rcv_nxt && seq < rcv_nxt + WINDOW_SLOTS) cleanup_tcb(tcb, ctx);        
                return ACTION_DROP;    
            }    
            
            if (unlikely((tcp_hdr->tcp_flags & RTE_TCP_FIN_FLAG) != 0)) {        
                tcb->rcv_nxt = rte_cpu_to_be_32(rte_be_to_cpu_32(tcb->rcv_nxt) + 1);         
                send_tcp_segment(tcb, ctx, nullptr, 0, RTE_TCP_FIN_FLAG | RTE_TCP_ACK_FLAG, mbuf);        
                cleanup_tcb(tcb, ctx);         
                return ACTION_KEEP;     
            }    
            
            uint8_t ip_hdr_len = (ipv4_hdr->version_ihl & RTE_IPV4_HDR_IHL_MASK) * RTE_IPV4_IHL_MULTIPLIER;    
            uint32_t total_header_len = sizeof(struct rte_ether_hdr) + ip_hdr_len + ((tcp_hdr->data_off >> 4) * 4);    
            
            if (likely(tcb->state == STATE_ESTABLISHED)) {        
                return handle_established(tcb, mbuf, tcp_hdr, ctx, total_header_len);    
            }    
            return ACTION_DROP;
        }