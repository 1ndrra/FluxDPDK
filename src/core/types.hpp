#pragma once
#include <cstdint>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>

constexpr uint16_t RX_RING_SIZE = 1024;
constexpr uint16_t TX_RING_SIZE = 1024;
constexpr uint32_t NUM_MBUFS = 8191;
constexpr uint32_t MBUF_CACHE_SIZE = 256;
constexpr uint16_t BURST_SIZE = 64; 
constexpr int PREFETCH_OFFSET = 4;

constexpr uint32_t MAX_CONNECTIONS_PER_CORE = 262144; 
constexpr uint32_t WINDOW_SLOTS = 512;
constexpr uint16_t TOKEN_SLAB_SIZE = 512;
constexpr uint8_t MAX_ROUTE_PARAMS = 4;
constexpr uint8_t MAX_FRAGMENTS = 8;
 constexpr uint16_t MAX_PARAM_LEN = 256; 
 constexpr uint16_t MAX_HEADER_SIZE = 2048;

 constexpr uint32_t MAX_TENANTS = 4096;
 constexpr int32_t TENANT_TOKENS_PER_SEC = 50000;
 constexpr uint32_t TENANT_IDLE_TIMEOUT_SEC = 300; 
 
 #define TX_OFFLOAD_FLAGS (RTE_MBUF_F_TX_IPV4 | RTE_MBUF_F_TX_IP_CKSUM | RTE_MBUF_F_TX_TCP_CKSUM)
 
 enum PacketAction { ACTION_DROP, ACTION_TX, ACTION_KEEP };
 enum TcpState : uint32_t { STATE_CLOSED = 0, STATE_LISTEN = 1, STATE_SYN_RCVD = 2, STATE_ESTABLISHED = 3 };
 enum class HttpParserState : uint32_t { EXPECT_METHOD, EXPECT_URL, EXPECT_HEADERS, EXPECT_BODY };
 enum class ParseStatus { NEED_MORE_DATA, DONE, ERROR };
 
 struct alignas(16) InternalComputeHeader {    
    uint32_t tenant_id;            
    uint32_t computation_id;       
    uint16_t command_opcode;       
    uint16_t payload_length;       
    uint32_t sequence_tag;    
 };
 
 struct alignas(16) TcpConnectionKey {    
    uint32_t src_ip;    
    uint32_t dst_ip;    
    uint16_t src_port;    
    uint16_t dst_port;    
    uint32_t _padding{0}; 
};
    
struct TokenFragment {    
    const char* ptr;    
    size_t len;
};

struct PacketMeta {    
    struct rte_mbuf* mbuf;    
    struct rte_ether_hdr* eth_hdr;    
    struct rte_ipv4_hdr* ip_hdr;    
    struct rte_tcp_hdr* tcp_hdr;    
    uint32_t precomputed_hash;
};

struct alignas(16) PacketTemplate {    
    struct rte_ether_hdr eth;    
    struct rte_ipv4_hdr ip;    
    struct rte_tcp_hdr tcp;
} __attribute__((packed));