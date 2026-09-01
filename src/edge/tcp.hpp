#pragma once
#include "core/context.hpp"

void send_tcp_segment(TCB* tcb, WorkerContext* ctx, const char* payload, size_t payload_len, uint8_t flags, struct rte_mbuf* reuse_mbuf = nullptr);
void cleanup_tcb(TCB* tcb, WorkerContext* ctx, struct rte_mbuf* pending_chain = nullptr);
PacketAction process_tcp(struct rte_mbuf *mbuf, struct rte_ether_hdr *eth_hdr, struct rte_ipv4_hdr *ipv4_hdr, struct rte_tcp_hdr *tcp_hdr, WorkerContext* ctx, const TcpConnectionKey* key, void* tcb_ptr, uint32_t precomputed_hash);