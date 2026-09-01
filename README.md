# FluxDPDK

FluxDPDK is a highly specialized, heterogeneous, kernel-bypassing network node written in C++17 on top of the Data Plane Development Kit (DPDK).

It is engineered specifically for ultra-low-latency "East-West" traffic inside tightly controlled, lossless datacenter fabrics (e.g., using Priority Flow Control). By abandoning standard Linux sockets, context switching, and dynamic memory allocations, it explores the absolute limits of mechanical sympathy and zero-copy data paths.

## Architecture Overview

The stack operates as a dual-mode edge gateway and internal compute node.It strictly isolates Layer 7 (HTTP) traffic from internal binary interconnect protocols at hardware level.

### Hardware Flow Steering(rte_flow)

Standard DPDK applications often utilize Receive Side Scaling(RSS) to spray packets across all CPU cores, forcing software threads to branch logic based on packet type. FluxDPDK eliminated this software branching via physical hardware flow steering.

* Edge TCP Cores (Even Cores): The NIC physically steers external TCP traffic (Port 80) to dedicated edge cores. These cores operate a custom TCP state machine, stateless SYN-cookies, and an optimistic zero-copy HTTP/1.1 parser.
* Internal UDP Cores (Odd Cores): UDP traffic is steered to dedicated compute cores. These cores expect a tightly packed binary InternalComputeHeader and act as a lock-free hypervisor dispatch layer. 
* ARP Management: ARP requests are broadcast across all queues, allowing any core to handle address resolution independently without a centralized control bottleneck.

## Core Optimizations

Achieving line-rate performance allocating requires strict adherence to memory locality and the elimination of run time allocations.

### Cache-Line Packing (CACHE LINE 0)
In a high-churn TCP environment, fetching the Task Control Block (TCB) is the most frequent memory operation. The TCB struct is manually aligned to 64 bytes (alignas(64)). The most critical execution variables-LRU pointers (prev, next), packet queues (rx_ready_head), and sequence numbers (rcv_nxt, snd_nxt)-are packed into the first 64 bytes (CACHE LINE 0). Updating a connection's state requires exactly one L1 cache fetch. Slower L7 metadata is pushed to subsequent cache lines.

### Zero-Allocation Flat Radix Router
Traditional C++ routing implementations rely on heap allocations (new Node) and dynamic arrays (std::vector). ZeroCopyRouter utilizes a FlatRadixNode structure-a single, pre-allocated contiguous array of 2,048 nodes. Tree traversal is resolved using uint16_t integer indices. This guarantees zero heap allocations during the routing phase and maintains highly predictable spatial locality.

### Optimistic Zero-Copy HTTP FSM
The HTTP parser maps directly over the raw NIC DMA memory (rte_mbuf).
* Fast Path: The FSM locates the header boundary (\r\n\r\n) within the contiguous mbuf memory using std::string_view and extracts numeric headers using C++17 std::from_chars. No dynamic buffers or memcpy operations occur.
* Slow Path: If headers straddle the MTU boundary across multiple fragmented packets, the stack transparently falls back to localized reassembly.
* Zero-Copy Egress: Responses bypass snprintf. The stack calculates explicit rte_pktmbuf_tailroom capacity. If the outbound payload fits within the original RX buffer, it is written in-place. If it exceeds capacity, a fresh TX mbuf is safely allocated.

### Lock-Free Multi-Tenant QoS
The internal UDP layer enforces multi-tenant fairness using a globally shared rte_hash map (backed by Intel TSX via RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY).Tokens are managed using a strict, lock-free compare_exchange_weak loop to prevent math hazards. To avoid cross-core cache invalidation, fast-path UDP workers never execute table evictions; a dedicated control-plane loop periodically garbage-collects stale state.

## Design Assumptions & RFC Deviations
This software operates under the assumption of a pristine, lossless datacenter fabric. It intentionally violates RFC 793 to prioritize absolute throughput and minimum latency over general-purpose reliability.Do not deploy this stack directly on a public internet IP.
* No Retransmission Timer: The stack expects a zero-packet-loss environment. Out-of-order packets are buffered, but no retransmission queues are maintained. Network drops require client-side timeouts.   
* No Congestion Control: Standard algorithms (AIMD, CUBIC, BBR, Slow Start) are removed. The server transmits data at maximum physical line rate.
* Bypassed TIME_WAIT: To support extreme connection churn, FIN packets trigger immediate teardown and return the TCB to the mempool without entering TIME_WAIT.

## Dual-mode Architecture
Standard web servers apply the same threading model and buffer management to all traffic. FluxDPDK recognizes that external API ingress and internal East-West datacenter traffic have fundamentally different requirements.

### Mode 1: The Edge TCP/HTTP Gateway (Even Cores)
This mode acts as the fortress. It absorbs "messy," untrusted HTTP/REST traffic from the outside world, parsing text and managing stateful connections.
* Shared-Nothing Architecture: Each core operates entirely independently with its own local rte_mempool and Cuckoo hash map. There is zero cross-core locking.
* Stateless SYN Cookies: To survive high-churn environments and SYN-floods, no Task Control Block (TCB) memory is allocated until a cryptographically validated ACK is returned.
* Optimistic Zero-Copy HTTP FSM: The HTTP parser maps std::string_view directly over the raw NIC DMA memory (rte_mbuf). It extracts headers and routing parameters in-place without memcpy. Only if a header straddles a packet boundary does it fall back to a localized assembly buffer.
* Zero-Allocation Flat Radix Router: Tree traversal for URL routing resolves using uint16_t indices on a pre-allocated contiguous array. Heap allocations (new) are strictly forbidden in the fast path.

### Mode 2: Internal Tenant Interconnect (Odd Cores)
This mode handles trusted, East-West internal RPC traffic. It drops the overhead of TCP and text parsing entirely, expecting tightly packed binary UDP payloads (InternalComputeHeader).
* Global QoS Enforcement: Unlike Mode 1, Mode 2 must enforce cross-core, multi-tenant fairness. It uses a globally shared Cuckoo hash map to track active tenants.
* Zero-Copy Hypervisor Dispatch: Packets are cast directly to binary structs and immediately evaluated. The application layer (hypervisor_dispatch_compute) is given the option to assume lifecycle ownership of the mbuf, preventing use-after-free faults in zero-copy hardware pipelines.

## NUMA-Aware Memory Topologies
If an lcore on CPU Socket 0 attempts to read memory physically connected to CPU Socket 1, the request traverses the inter-socket bus (UPI/QPI), introducing massive latency spikes.   
* This application resolves the physical PCIe bus mapping of the active NIC (rte_eth_dev_socket_id).
*  Every structural component—including WorkerContext blocks, hash tables, rings, and memory pools—is explicitly allocated on the RAM banks attached to that specific CPU socket using rte_zmalloc_socket and localized API variants.

## Hugepage Pre-Allocation
Processing millions of fragmented packets across standard 4KB memory pages causes the CPU's TLB to thrash, destroying throughput.    
* This stack leverages DPDK to map 2MB or 1GB continuous physical Hugepages at the OS level.
* All required memory for the application's maximum theoretical lifetime is pre-allocated at startup. There are no runtime memory allocations.
*  This guarantees zero OS page faults and maintains near-perfect TLB cache hit rates under maximum saturation.


## System Architecture
```
                                                     [ External Network ]
                                                               |
                          +-------------------------------------------------------------------------+
                          |                          Physical NIC Silicon                           |
                          |  +-------------------------------------------------------------------+  |
                          |  |                Hardware Flow Steering (rte_flow)                  |  |
                          |  +-------------------------------------------------------------------+  |
                          +---------|-----------------------------------------------------|---------+
                                    | (TCP Dst Port 80)                                   | (UDP)
                                    v                                                     v
                          +-----------------------+                             +-----------------------+
                          |  MODE 1: EDGE CORES   |                             | MODE 2: INTERNAL CORES|
                          |  (Even Rx/Tx Queues)  |                             | (Odd Rx/Tx Queues)    |
                          |                       |                             |                       |
                          |  [ Local TCP Hash ]   |                             | [ UDP Parse ]         |
                          |  [ NUMA TCB Mempool]  |                             | [ Hypervisor Dispatch]|
                          |  [ Zero-Copy Router]  |                             +----------|------------+
                          +-----------------------+                                        | (CAS)
                                                                                +----------v------------+
                                                                                | GLOBAL QOS TIER       |
                                                                                | [ Cuckoo Hash Map ]   |
                                                                                | [ Token Buckets ]     |
                                                                                +----------^------------+
                                                                                           | (Async)
                                                                                +-----------------------+
                                                                                | MASTER CORE 0         |
                                                                                | [ Signal Handling ]   |
                                                                                | [ Garbage Collector ] |
                                                                                +-----------------------+
```
