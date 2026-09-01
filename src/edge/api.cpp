#include <charconv>
#include <cstring>
#include <algorithm>
#include "edge/api.hpp"
#include "edge/tcp.hpp"

static constexpr std::string_view HTTP_200_STATIC_HDR =     
  "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: keep-alive\r\nContent-Length: ";
  
void send_static_error(TCB* tcb, WorkerContext* ctx, int code, struct rte_mbuf* reuse_mbuf) {    
    std::string_view err_payload;    
    if (code == 404) err_payload = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";    
    else err_payload = "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";        
    
    send_tcp_segment(tcb, ctx, err_payload.data(), err_payload.size(), RTE_TCP_ACK_FLAG | RTE_TCP_PSH_FLAG | RTE_TCP_FIN_FLAG, reuse_mbuf);    
    tcb->state = STATE_CLOSED; 
}

void handle_get_user(TCB* tcb, WorkerContext* ctx, struct rte_mbuf* rx_mbuf) {    
    std::string_view raw_uid = tcb->route_params[0];    
    char safe_uid_buf[MAX_PARAM_LEN];    
    size_t copy_len = std::min(raw_uid.length(), (size_t)MAX_PARAM_LEN);    
    std::memcpy(safe_uid_buf, raw_uid.data(), copy_len);    
    std::string_view user_id(safe_uid_buf, copy_len);    
    
    constexpr std::string_view p1 = "{\"status\":\"success\",\"user_id\":\"";    
    constexpr std::string_view p2 = "\"}";    
    size_t actual_payload_len = p1.length() + user_id.length() + p2.length();        
    
    char content_len_buf[16];    
    auto [ptr_end, ec] = std::to_chars(content_len_buf, content_len_buf + sizeof(content_len_buf), actual_payload_len);    
    if (unlikely(ec != std::errc())) {        
        send_static_error(tcb, ctx, 500, rx_mbuf);        
        return;    
    }    
    int str_len = ptr_end - content_len_buf;        
    
    uint32_t http_len = HTTP_200_STATIC_HDR.size() + str_len + 4 + actual_payload_len;        
    
    char http_resp[4096];     
    if (unlikely(http_len > sizeof(http_resp))) {        
        send_static_error(tcb, ctx, 500, rx_mbuf);        
        return;    
    }   
    
    char* ptr = http_resp;    
    std::memcpy(ptr, HTTP_200_STATIC_HDR.data(), HTTP_200_STATIC_HDR.size()); ptr += HTTP_200_STATIC_HDR.size();    
    std::memcpy(ptr, content_len_buf, str_len); ptr += str_len;    
    std::memcpy(ptr, "\r\n\r\n", 4); ptr += 4;    
    std::memcpy(ptr, p1.data(), p1.length()); ptr += p1.length();    
    std::memcpy(ptr, user_id.data(), user_id.length()); ptr += user_id.length();    
    std::memcpy(ptr, p2.data(), p2.length()); ptr += p2.length();        
    
    size_t total_len = ptr - http_resp;    
    size_t offset = 0;        
    
    struct rte_mbuf* current_reuse = rx_mbuf;    
    uint64_t initial_drops = ctx->tx_alloc_drops;    
    
    while(total_len > 0) {        
        size_t chunk = std::min(total_len, (size_t)tcb->client_mss);        
        uint8_t flags = RTE_TCP_ACK_FLAG;        
        if (chunk == total_len) flags |= RTE_TCP_PSH_FLAG;                
        
        send_tcp_segment(tcb, ctx, http_resp + offset, chunk, flags, current_reuse);        
        current_reuse = nullptr;                 
        
        if (unlikely(ctx->tx_alloc_drops > initial_drops)) {            
            tcb->state = STATE_CLOSED;             
            break;        
        }        
        
        total_len -= chunk;        
        offset += chunk;    
    }
}