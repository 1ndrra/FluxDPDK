#pragma once
#include "core/context.hpp"

void send_static_error(TCB* tcb, WorkerContext* ctx, int code, struct rte_mbuf* reuse_mbuf = nullptr);
void handle_get_user(TCB* tcb, WorkerContext* ctx, struct rte_mbuf* rx_mbuf);