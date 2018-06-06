#include <rte_common.h>
#include <rte_config.h>
#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_ip.h>
#include <rte_mbuf.h>
#include <string>
#include <thread>
#include "eth_helpers.h"

#include <gflags/gflags.h>
DEFINE_uint64(is_sender, 0, "Is this process the sender?");
DEFINE_uint64(num_threads, 1, "Number of sender threads");

static inline void rt_assert(bool condition, std::string throw_str) {
  if (unlikely(!condition)) throw std::runtime_error(throw_str);
}

static inline void rt_assert(bool condition) {
  if (unlikely(!condition)) throw std::runtime_error("Error");
}

static constexpr size_t kAppMTU = 1024;
static constexpr size_t kAppPortId = 0;
static constexpr size_t kAppNumaNode = 0;
static constexpr size_t kAppDataSize = 16;  // App-level data size

static constexpr size_t kAppNumRingDesc = 256;
static constexpr size_t kAppRxBatchSize = 32;
static constexpr size_t kAppTxBatchSize = 32;
static constexpr size_t kAppNumMbufs = 8191;
static constexpr size_t kAppNumCacheMbufs = 32;

static constexpr size_t kAppRxQueueId = 0;
static constexpr size_t kAppTxQueueId = 0;

uint8_t kDstMAC[6] = {0x3c, 0xfd, 0xfe, 0x56, 0x07, 0x42};
char kDstIP[] = "10.10.1.1";

uint8_t kSrcMAC[6] = {0x3c, 0xfd, 0xfe, 0x56, 0x19, 0x82};
char kSrcIP[] = "10.10.1.2";

// Per-element size for the packet buffer memory pool
static constexpr size_t kAppMbufSize =
    (2048 + static_cast<uint32_t>(sizeof(struct rte_mbuf)) +
     RTE_PKTMBUF_HEADROOM);

void sender_thread_func(struct rte_mempool *pktmbuf_pool, size_t thread_id) {
  rte_mbuf *tx_mbufs[kAppTxBatchSize];

  while (true) {
    for (size_t i = 0; i < kAppTxBatchSize; i++) {
      tx_mbufs[i] = rte_pktmbuf_alloc(pktmbuf_pool);
      rt_assert(tx_mbufs[i] != nullptr);

      uint8_t *pkt = rte_pktmbuf_mtod(tx_mbufs[i], uint8_t *);

      // For now, don't use DPDK's header defines
      auto *eth_hdr = reinterpret_cast<eth_hdr_t *>(pkt);
      auto *ip_hdr = reinterpret_cast<ipv4_hdr_t *>(pkt + sizeof(eth_hdr_t));
      auto *udp_hdr = reinterpret_cast<udp_hdr_t *>(pkt + sizeof(eth_hdr_t) +
                                                    sizeof(ipv4_hdr_t));

      gen_eth_header(eth_hdr, kSrcMAC, kDstMAC);
      gen_ipv4_header(ip_hdr, ip_from_str(kSrcIP), ip_from_str(kDstIP),
                      kAppDataSize);
      gen_udp_header(udp_hdr, 31850, 31850, kAppDataSize);

      tx_mbufs[i]->nb_segs = 1;
      tx_mbufs[i]->pkt_len = kTotHdrSz + kAppDataSize;
      tx_mbufs[i]->data_len = tx_mbufs[i]->pkt_len;
    }

    size_t nb_tx_new =
        rte_eth_tx_burst(kAppPortId, thread_id, tx_mbufs, kAppTxBatchSize);

    for (size_t i = nb_tx_new; i < kAppTxBatchSize; i++) {
      rte_pktmbuf_free(tx_mbufs[i]);
    }
  }
}

void receiver_thread_func(size_t thread_id) {
  struct rte_mbuf *rx_pkts[kAppRxBatchSize];

  while (true) {
    size_t nb_rx =
        rte_eth_rx_burst(kAppPortId, thread_id, rx_pkts, kAppRxBatchSize);
    if (nb_rx > 0) printf("nb_rx = %zu\n", nb_rx);
    for (size_t i = 0; i < nb_rx; i++) rte_pktmbuf_free(rx_pkts[i]);
  }
}

int main(int argc, char **argv) {
  gflags::ParseCommandLineFlags(&argc, &argv, true);

  const char *rte_argv[] = {"-c", "1", "-n", "4", nullptr};
  int rte_argc = static_cast<int>(sizeof(argv) / sizeof(argv[0])) - 1;
  int ret = rte_eal_init(rte_argc, const_cast<char **>(rte_argv));
  rt_assert(ret >= 0, "rte_eal_init failed");

  uint16_t num_ports = rte_eth_dev_count_avail();
  rt_assert(num_ports > kAppPortId, "Too few ports");

  // Create per-thread RX and TX queues
  struct rte_eth_conf port_conf;
  memset(&port_conf, 0, sizeof(port_conf));
  rte_eth_dev_configure(kAppPortId, FLAGS_num_threads, FLAGS_num_threads,
                        &port_conf);

  auto *mempools = new rte_mempool *[FLAGS_num_threads];

  for (size_t i = 0; i < FLAGS_num_threads; i++) {
    mempools[i] = rte_pktmbuf_pool_create("", kAppNumMbufs, kAppNumCacheMbufs,
                                          0, kAppMbufSize, kAppNumaNode);
    rt_assert(mempools[i] != nullptr, "Failed to create mempool");

    ret = rte_eth_rx_queue_setup(kAppPortId, i, kAppNumRingDesc, kAppNumaNode,
                                 nullptr, mempools[i]);
    rt_assert(ret == 0, "Failed to setup RX queue");

    ret = rte_eth_tx_queue_setup(kAppPortId, i, kAppNumRingDesc, kAppNumaNode,
                                 nullptr);
    rt_assert(ret == 0, "Faield to setup TX queue");
  }

  ret = rte_eth_dev_set_mtu(kAppPortId, kAppMTU);
  rt_assert(ret >= 0, "Failed to set MTU");

  ret = rte_eth_dev_start(kAppPortId);  // This starts the RX/TX queues
  rt_assert(ret >= 0, "Failed to start port");

  // Retrieve the link speed and compute information based on it.
  struct rte_eth_link link;
  rte_eth_link_get(kAppPortId, &link);
  rt_assert(link.link_status > 0, "Failed to detect link");
  rt_assert(link.link_speed != ETH_SPEED_NUM_NONE, "Failed to get bw");
  printf("Link bandwidth = %u Mbps\n", link.link_speed);

  // rte_eth_promiscuous_enable(kAppPortId);
  auto thread_arr = new std::thread[FLAGS_num_threads];
  for (size_t i = 0; i < FLAGS_num_threads; i++) {
    if (FLAGS_is_sender == 0) {
      thread_arr[i] = std::thread(receiver_thread_func, i);
    } else {
      thread_arr[i] = std::thread(sender_thread_func, mempools[i], i);
    }
  }

  for (size_t i = 0; i < FLAGS_num_threads; i++) thread_arr[i].join();
}
