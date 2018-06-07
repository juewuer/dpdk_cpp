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

inline uint32_t fastrand(uint64_t &seed) {
  seed = seed * 1103515245 + 12345;
  return static_cast<uint32_t>(seed >> 32);
}

static constexpr size_t kAppMTU = 1024;
static constexpr size_t kAppPortId = 0;
static constexpr size_t kAppNumaNode = 0;
static constexpr size_t kAppDataSize = 16;  // App-level data size

static constexpr size_t kAppNumRingDesc = 256;
static constexpr size_t kAppRxBatchSize = 32;
static constexpr size_t kAppTxBatchSize = 32;
static constexpr size_t kAppNumMbufs = 8191;
static constexpr size_t kAppZeroCacheMbufs = 0;

static constexpr size_t kAppRxQueueId = 0;
static constexpr size_t kAppTxQueueId = 0;

// uint8_t kDstMAC[6] = {0xa0, 0x36, 0x9f, 0x2a, 0x5c, 0x54};
uint8_t kDstMAC[6] = {0x3c, 0xfd, 0xfe, 0x55, 0xff, 0x62};
char kDstIP[] = "10.10.1.1";

uint8_t kSrcMAC[6] = {0x3c, 0xfd, 0xfe, 0x55, 0x47, 0xfa};
char kSrcIP[] = "10.10.1.2";

uint16_t kBaseUDPPort = 3185;

// Per-element size for the packet buffer memory pool
static constexpr size_t kAppMbufSize =
    (2048 + static_cast<uint32_t>(sizeof(struct rte_mbuf)) +
     RTE_PKTMBUF_HEADROOM);

void sender_thread_func(struct rte_mempool *pktmbuf_pool, size_t thread_id) {
  rte_mbuf *tx_mbufs[kAppTxBatchSize];
  uint64_t seed = 0xdeadbeef;

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
      gen_udp_header(udp_hdr, kBaseUDPPort, kBaseUDPPort, kAppDataSize);
      udp_hdr->dst_port = htons(kBaseUDPPort + fastrand(seed) % 2);
      udp_hdr->src_port = htons(kBaseUDPPort + fastrand(seed) % 2);

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
    if (nb_rx > 0) printf("Thread %zu: nb_rx = %zu\n", thread_id, nb_rx);
    for (size_t i = 0; i < nb_rx; i++) rte_pktmbuf_free(rx_pkts[i]);
  }
}

// Steer packets received on udp_port to queue_id
void add_fdir_filter(size_t queue_id, uint16_t udp_port) {
  // Receive packets for UDP port kBaseUDPPort + i
  rte_eth_fdir_filter filter;
  memset(&filter, 0, sizeof(filter));
  filter.soft_id = queue_id;
  filter.input.flow_type = RTE_ETH_FLOW_NONFRAG_IPV4_UDP;
  filter.input.flow.udp4_flow.dst_port = htons(udp_port);
  filter.action.rx_queue = queue_id;
  filter.action.behavior = RTE_ETH_FDIR_ACCEPT;
  filter.action.report_status = RTE_ETH_FDIR_NO_REPORT_STATUS;

  int ret = rte_eth_dev_filter_ctrl(kAppPortId, RTE_ETH_FILTER_FDIR,
                                    RTE_ETH_FILTER_ADD, &filter);
  rt_assert(ret == 0,
            "Failed to add fdir entry " + std::string(rte_strerror(errno)));
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
  rte_eth_conf eth_conf;
  memset(&eth_conf, 0, sizeof(eth_conf));

  eth_conf.rxmode.mq_mode = ETH_MQ_RX_NONE;
  eth_conf.rxmode.max_rx_pkt_len = ETHER_MAX_LEN;
  eth_conf.rxmode.ignore_offload_bitfield = 1;  // Use offloads below instead
  eth_conf.rxmode.offloads = 0;

  // XXX: ixgbe does not support fast free offload, but i40e does
  eth_conf.txmode.mq_mode = ETH_MQ_TX_NONE;
  eth_conf.txmode.offloads = DEV_TX_OFFLOAD_MULTI_SEGS;

  eth_conf.fdir_conf.mode = RTE_FDIR_MODE_PERFECT;
  eth_conf.fdir_conf.pballoc = RTE_FDIR_PBALLOC_64K;
  eth_conf.fdir_conf.status = RTE_FDIR_NO_REPORT_STATUS;
  eth_conf.fdir_conf.mask.dst_port_mask = 0xffff;
  eth_conf.fdir_conf.drop_queue = 0;

  // XXX: Are these thresh and txq_flags value optimal?
  rte_eth_rxconf eth_rx_conf;
  memset(&eth_rx_conf, 0, sizeof(eth_rx_conf));
  eth_rx_conf.rx_thresh.pthresh = 8;
  eth_rx_conf.rx_thresh.hthresh = 0;
  eth_rx_conf.rx_thresh.wthresh = 0;
  eth_rx_conf.rx_free_thresh = 0;
  eth_rx_conf.rx_drop_en = 0;

  rte_eth_txconf eth_tx_conf;
  memset(&eth_tx_conf, 0, sizeof(eth_tx_conf));
  eth_tx_conf.tx_thresh.pthresh = 32;
  eth_tx_conf.tx_thresh.hthresh = 0;
  eth_tx_conf.tx_thresh.wthresh = 0;
  eth_tx_conf.tx_free_thresh = 0;
  eth_tx_conf.tx_rs_thresh = 0;
  eth_tx_conf.txq_flags = ETH_TXQ_FLAGS_IGNORE;  // Use offloads below instead
  eth_tx_conf.offloads = eth_conf.txmode.offloads;

  ret = rte_eth_dev_configure(kAppPortId, FLAGS_num_threads, FLAGS_num_threads,
                              &eth_conf);
  rt_assert(ret == 0, "Dev config err " + std::string(rte_strerror(rte_errno)));

  struct ether_addr mac;
  rte_eth_macaddr_get(kAppPortId, &mac);
  printf("Ether addr = %s\n", mac_to_string(mac.addr_bytes).c_str());

  auto *mempools = new rte_mempool *[FLAGS_num_threads];

  for (size_t i = 0; i < FLAGS_num_threads; i++) {
    // We won't use DPDK's lcore threads, so mempool cache won't work. Instead,
    // use per-thread pools with zero cached mbufs
    std::string pname = "mempool-" + std::to_string(i);
    mempools[i] =
        rte_pktmbuf_pool_create(pname.c_str(), kAppNumMbufs, kAppZeroCacheMbufs,
                                0, kAppMbufSize, kAppNumaNode);
    rt_assert(mempools[i] != nullptr,
              "Mempool create failed " + std::string(rte_strerror(rte_errno)));

    ret = rte_eth_rx_queue_setup(kAppPortId, i, kAppNumRingDesc, kAppNumaNode,
                                 &eth_rx_conf, mempools[i]);
    rt_assert(ret == 0, "Failed to setup RX queue " + std::to_string(i));

    ret = rte_eth_tx_queue_setup(kAppPortId, i, kAppNumRingDesc, kAppNumaNode,
                                 &eth_tx_conf);
    rt_assert(ret == 0, "Failed to setup TX queue " + std::to_string(i));
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
