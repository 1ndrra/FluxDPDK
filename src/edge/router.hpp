#pragma once
#include <cstring>
#include <algorithm>
#include "core/context.hpp"

constexpr uint16_t MAX_RADIX_NODES = 1024;

struct FlatRadixNode {
    char path_segment[32];
    uint8_t path_len{0};
    uint8_t child_count{0};
    bool is_param{false};
    uint16_t children[16];
    RouteHandler handler{nullptr};
};

class ZeroCopyRouter {
    private:   
     FlatRadixNode nodes[MAX_RADIX_NODES];    
     uint16_t node_count{1};         
     
     __rte_always_inline void match_url(TCB* tcb, std::string_view url) const {        
        uint16_t curr_idx = 0;        
        size_t url_pos = 0;        
        tcb->param_count = 0;        
        
        if (url.length() > 0 && url[0] == '/') url_pos = 1;        
        
        while (url_pos < url.length()) {            
            bool matched = false;            
            for (uint8_t i = 0; i < nodes[curr_idx].child_count; ++i) {                
                uint16_t child_idx = nodes[curr_idx].children[i];                
                const FlatRadixNode& child = nodes[child_idx];                
                
                if (child.is_param) {                    
                    size_t next_slash = url.find('/', url_pos);                    
                    size_t param_len = (next_slash == std::string_view::npos) ? (url.length() - url_pos) : (next_slash - url_pos);                                        
                    
                    if (unlikely(param_len > MAX_PARAM_LEN)) { tcb->matched_handler = nullptr; return; }                    
                    if (likely(tcb->param_count < MAX_ROUTE_PARAMS)) {                        
                        tcb->route_params[tcb->param_count++] = url.substr(url_pos, param_len);                    
                    }                                        
                    
                    url_pos += param_len;                    
                    if (url_pos < url.length() && url[url_pos] == '/') url_pos++;                     
                    curr_idx = child_idx;                    
                    matched = true;                    
                    break;                
                } else {                   
                    std::string_view child_seg(child.path_segment, child.path_len);                    
                    if (url.compare(url_pos, child.path_len, child_seg) == 0) {                        
                        url_pos += child.path_len;                        
                        if (url_pos < url.length() && url[url_pos] == '/') url_pos++;                        
                        curr_idx = child_idx;                        
                        matched = true;                        
                        break;                    
                    }                
                }            
            }            
            if (unlikely(!matched)) { tcb->matched_handler = nullptr; return; }        
        }        
        tcb->matched_handler = nodes[curr_idx].handler;    
    }
    
    public:    
        ZeroCopyRouter() { std::memset(nodes, 0, sizeof(nodes)); }    
        
        void add_route(const std::string_view& path, RouteHandler handler) {        
            uint16_t curr_idx = 0;        
            size_t pos = (path.length() > 0 && path[0] == '/') ? 1 : 0;        
            
            while (pos < path.length()) {            
                size_t next_slash = path.find('/', pos);            
                size_t seg_len = (next_slash == std::string_view::npos) ? (path.length() - pos) : (next_slash - pos);            
                if (seg_len == 0) { pos++; continue; }            
                std::string_view segment = path.substr(pos, seg_len);                       
                
                bool found = false;            
                for (uint8_t i = 0; i < nodes[curr_idx].child_count; ++i) {                
                    uint16_t child_idx = nodes[curr_idx].children[i];                
                    if ((nodes[child_idx].is_param && segment[0] == ':') ||                     
                        (!nodes[child_idx].is_param && std::string_view(nodes[child_idx].path_segment, nodes[child_idx].path_len) == segment)) {                    
                            curr_idx = child_idx; found = true; break;               
                        }            
                    }                        
                    
                    if (!found) {                
                        if (node_count >= MAX_RADIX_NODES || nodes[curr_idx].child_count >= 16) return;                 
                        uint16_t new_idx = node_count++;                
                        if (segment[0] == ':') {                    
                            nodes[new_idx].is_param = true;                
                        } else {                    
                            size_t copy_len = std::min(segment.length(), (size_t)31);                    
                            std::memcpy(nodes[new_idx].path_segment, segment.data(), copy_len);                    
                            nodes[new_idx].path_len = copy_len;                
                        }                
                        nodes[curr_idx].children[nodes[curr_idx].child_count++] = new_idx;                
                        curr_idx = new_idx;            
                    }            
                    pos += seg_len;            
                    if (pos < path.length() && path[pos] == '/') pos++;        
                }       
                 nodes[curr_idx].handler = handler;    
                }    
                
                __rte_always_inline void dispatch_fragmented(TCB* tcb, WorkerContext* ctx) const {        
                    if (likely(tcb->frag_count == 1)) {            
                        match_url(tcb, std::string_view(tcb->url_fragments[0].ptr, tcb->url_fragments[0].len));        
                    } else if (tcb->frag_count > 1) {            
                        tcb->slab_len = 0;            
                        for (uint8_t i = 0; i < tcb->frag_count; ++i) {                
                            size_t frag_len = tcb->url_fragments[i].len;                
                            if (unlikely(tcb->slab_len + frag_len > TOKEN_SLAB_SIZE)) { tcb->matched_handler = nullptr; return; }                
                            std::memcpy(tcb->token_slab + tcb->slab_len, tcb->url_fragments[i].ptr, frag_len);                
                            tcb->slab_len += frag_len;            
                        }            
                        match_url(tcb, std::string_view(tcb->token_slab, tcb->slab_len));        
                    }    
                }
            };