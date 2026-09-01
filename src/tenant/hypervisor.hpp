#pragma once
#include "core/context.hpp"

static inline bool hypervisor_dispatch_compute(uint32_t tenant_id, uint16_t opcode, InternalComputeHeader* hdr, struct rte_mbuf* mbuf) {    
    (void)tenant_id; (void)opcode; (void)hdr; (void)mbuf;    
    return false; // Return true if pipeline assumes mbuf ownership
    }