#include <gflags/gflags.h>
#include <rte_common.h>
#include <rte_config.h>
#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_ip.h>
#include <rte_mbuf.h>
#include <string>
#include <thread>
#include "eth_common.h"

DEFINE_uint64(is_sender, 0, "Is this process the sender?");
DEFINE_uint64(num_threads, 1, "Number of sender threads");

static_assert(RTE_VER_YEAR >= 19, "DPDK 19.11 required");

static constexpr bool kAppTwoSegs = false;
static constexpr bool kAppVerbose = false;

inline uint32_t fastrand(uint64_t &seed) {
  seed = seed * 1103515245 + 12345;
  return static_cast<uint32_t>(seed >> 32);
}

static constexpr size_t kAppMTU = 1024;
static constexpr size_t kAppPortId = 0;
static constexpr size_t kAppNumaNode = 0;
static constexpr size_t kAppDataSize = 32;  // App-level data size

static constexpr size_t kAppNumRxRingDesc = 4096;
static constexpr size_t kAppNumTxRingDesc = 128;
static constexpr size_t kAppRxBatchSize = 32;
static constexpr size_t kAppTxBatchSize = 32;

static constexpr size_t kAppNumMbufs = (kAppNumRxRingDesc * 2 - 1);
static constexpr size_t kAppZeroCacheMbufs = 0;
static constexpr bool kInstallFlowRules = false;

char kServerMAC[] = "00:0d:3a:e4:0f:e8";
char kServerIP[] = "172.18.50.8";

char kClientMAC[] = "00:0d:3a:7d:ec:bd";
char kClientIP[] = "172.18.50.10";

uint16_t kBaseUDPPort = 10000;

bool ntuple_filter_supported = false;
bool fdir_filter_supported = false;

// Per-element size for the packet buffer memory pool
static constexpr size_t kAppMbufSize =
    (2048 + static_cast<uint32_t>(sizeof(struct rte_mbuf)) +
     RTE_PKTMBUF_HEADROOM);

void sender_thread_func(struct rte_mempool *pktmbuf_pool, size_t thread_id) {
  // mbufs for first and second segment
  rte_mbuf *tx_mbufs[kAppTxBatchSize];

  uint64_t seed = 0xdeadbeef;

  uint32_t client_ip = ipv4_from_str(kClientIP);
  uint32_t server_ip = ipv4_from_str(kServerIP);
  uint8_t client_mac[6], server_mac[6];
  mac_from_str(kClientMAC, client_mac);
  mac_from_str(kServerMAC, server_mac);

  struct timespec start, end;
  clock_gettime(CLOCK_REALTIME, &start);
  size_t nb_tx = 0;

  while (true) {
    for (size_t i = 0; i < kAppTxBatchSize; i++) {
      // XXX: raw_alloc?
      tx_mbufs[i] = rte_pktmbuf_alloc(pktmbuf_pool);
      assert(tx_mbufs[i] != nullptr);

      uint8_t *pkt = rte_pktmbuf_mtod(tx_mbufs[i], uint8_t *);

      // For now, don't use DPDK's header defines
      auto *eth_hdr = reinterpret_cast<eth_hdr_t *>(pkt);
      auto *ip_hdr = reinterpret_cast<ipv4_hdr_t *>(pkt + sizeof(eth_hdr_t));
      auto *udp_hdr = reinterpret_cast<udp_hdr_t *>(pkt + sizeof(eth_hdr_t) +
                                                    sizeof(ipv4_hdr_t));

      gen_eth_header(eth_hdr, client_mac, server_mac);
      gen_ipv4_header(ip_hdr, client_ip, server_ip, kAppDataSize);
      gen_udp_header(udp_hdr, kBaseUDPPort, kBaseUDPPort, kAppDataSize);
      udp_hdr->dst_port =
          htons(kBaseUDPPort + fastrand(seed) % FLAGS_num_threads);

      if (!kAppTwoSegs) {
        tx_mbufs[i]->nb_segs = 1;
        tx_mbufs[i]->pkt_len = kInetHdrsTotSize + kAppDataSize;
        tx_mbufs[i]->data_len = tx_mbufs[i]->pkt_len;
      } else {
        tx_mbufs[i]->nb_segs = 2;
        tx_mbufs[i]->pkt_len = kInetHdrsTotSize + kAppDataSize;
        tx_mbufs[i]->data_len = kInetHdrsTotSize;  // First segment contains hdr
        tx_mbufs[i]->next = rte_pktmbuf_alloc(pktmbuf_pool);

        assert(tx_mbufs[i]->next != nullptr);
        tx_mbufs[i]->next->data_len = kAppDataSize;
      }

      if (kAppVerbose) {
        printf("Thread %zu: Sending packet %s\n", thread_id,
               frame_header_to_string(rte_pktmbuf_mtod(tx_mbufs[i], uint8_t *))
                   .c_str());
      }
    }

    size_t nb_tx_new =
        rte_eth_tx_burst(kAppPortId, thread_id, tx_mbufs, kAppTxBatchSize);
    for (size_t i = nb_tx_new; i < kAppTxBatchSize; i++) {
      rte_pktmbuf_free(tx_mbufs[i]);  // This frees chained segs
    }

    nb_tx += nb_tx_new;
    if (kAppVerbose && nb_tx_new > 0) {
      printf("Thread %zu: nb_tx_new = %zu, nb_tx = %zu\n", thread_id, nb_tx_new,
             nb_tx);
    }

    if (nb_tx >= 1000000) {
      clock_gettime(CLOCK_REALTIME, &end);
      double seconds = (end.tv_sec - start.tv_sec) +
                       (end.tv_nsec - start.tv_nsec) / 1000000000.0;
      double mpps = nb_tx / (seconds * 1000000);
      printf("Thread %zu, TX rate = %.2f Mpps\n", thread_id, mpps);

      clock_gettime(CLOCK_REALTIME, &start);
      nb_tx = 0;
    }
  }
}

void receiver_thread_func(size_t thread_id) {
  printf("Thread %zu starting packet RX\n", thread_id);
  struct rte_mbuf *rx_pkts[kAppRxBatchSize];

  struct timespec start, end;
  clock_gettime(CLOCK_REALTIME, &start);
  size_t nb_rx = 0;

  while (true) {
    size_t nb_rx_new =
        rte_eth_rx_burst(kAppPortId, thread_id, rx_pkts, kAppRxBatchSize);
    if (kAppVerbose && nb_rx_new > 0) {
      printf("Thread %zu: nb_rx_new = %zu, nb_rx = %zu\n", thread_id, nb_rx_new,
             nb_rx);
    }

    for (size_t i = 0; i < nb_rx_new; i++) rte_pktmbuf_free(rx_pkts[i]);
    nb_rx += nb_rx_new;

    if (nb_rx >= 1000000) {
      clock_gettime(CLOCK_REALTIME, &end);
      double seconds = (end.tv_sec - start.tv_sec) +
                       (end.tv_nsec - start.tv_nsec) / 1000000000.0;
      double mpps = nb_rx / (seconds * 1000000);
      printf("Thread %zu, RX rate = %.2f Mpps\n", thread_id, mpps);

      clock_gettime(CLOCK_REALTIME, &start);
      nb_rx = 0;
    }
  }
}

// Steer packets received on udp_port to queue_id
void add_filter_rule(size_t queue_id, uint16_t udp_port) {
  if (ntuple_filter_supported) {
    // Use 5-tuple filter for ixgbe even though it technically supports
    // FILTER_FDIR. I couldn't get FILTER_FDIR to work with ixgbe.
    struct rte_eth_ntuple_filter ntuple;
    memset(&ntuple, 0, sizeof(ntuple));
    ntuple.flags = RTE_5TUPLE_FLAGS;
    ntuple.dst_port = rte_cpu_to_be_16(udp_port);
    ntuple.dst_port_mask = UINT16_MAX;
    ntuple.proto = IPPROTO_UDP;
    ntuple.proto_mask = UINT8_MAX;
    ntuple.priority = 1;
    ntuple.queue = queue_id;

    int ret = rte_eth_dev_filter_ctrl(kAppPortId, RTE_ETH_FILTER_NTUPLE,
                                      RTE_ETH_FILTER_ADD, &ntuple);
    rt_assert(ret == 0, "Failed to add ntuple filter");
    printf("Added ntuple filter. Queue %zu, port %u\n", queue_id, udp_port);
  } else if (fdir_filter_supported) {
    // Use fdir filter for i40e (5-tuple not supported)
    rte_eth_fdir_filter filter;
    memset(&filter, 0, sizeof(filter));
    filter.soft_id = queue_id;
    filter.input.flow_type = RTE_ETH_FLOW_NONFRAG_IPV4_UDP;
    filter.input.flow.udp4_flow.dst_port = rte_cpu_to_be_16(udp_port);
    filter.input.flow.udp4_flow.ip.dst_ip = ipv4_from_str(kServerIP);
    filter.action.rx_queue = queue_id;
    filter.action.behavior = RTE_ETH_FDIR_ACCEPT;
    filter.action.report_status = RTE_ETH_FDIR_NO_REPORT_STATUS;

    int ret = rte_eth_dev_filter_ctrl(kAppPortId, RTE_ETH_FILTER_FDIR,
                                      RTE_ETH_FILTER_ADD, &filter);
    rt_assert(ret == 0, "Failed to add fdir filter");
    printf("Added fdir filter. Queue %zu, port %u\n", queue_id, udp_port);
  } else {
    rt_assert(false, "No flow director filters supported");
  }
}

static void check_supported_filters(uint8_t phy_port) {
  if (rte_eth_dev_filter_supported(phy_port, RTE_ETH_FILTER_FDIR) == 0) {
    printf("dpdk_cpp: Port %u supports flow director filter.\n", phy_port);
    fdir_filter_supported = true;
  } else {
    printf("dpdk_cpp: Port %u does not support fdir filter.\n", phy_port);
  }

  if (rte_eth_dev_filter_supported(phy_port, RTE_ETH_FILTER_NTUPLE) == 0) {
    printf("dpdk_cpp: Port %u supports ntuple filter.\n", phy_port);
    ntuple_filter_supported = true;
  } else {
    printf("dpdk_cpp: Port %u does not support ntuple filter.\n", phy_port);
  }
}

int main(int argc, char **argv) {
  gflags::ParseCommandLineFlags(&argc, &argv, true);

  const char *rte_argv[] = {"-c", "1", "-n", "4", "-m", "512", nullptr};
  int rte_argc = static_cast<int>(sizeof(rte_argv) / sizeof(rte_argv[0])) - 1;
  int ret = rte_eal_init(rte_argc, const_cast<char **>(rte_argv));
  rt_assert(ret >= 0, "rte_eal_init failed");

  uint16_t num_ports = rte_eth_dev_count_avail();
  rt_assert(num_ports > kAppPortId, "Too few ports");

  rte_eth_dev_info dev_info;
  rte_eth_dev_info_get(kAppPortId, &dev_info);
  rt_assert(dev_info.rx_desc_lim.nb_max >= kAppNumRxRingDesc,
            "Device RX ring too small");
  rt_assert(dev_info.tx_desc_lim.nb_max >= kAppNumTxRingDesc,
            "Device TX ring too small");

  // Create per-thread RX and TX queues
  rte_eth_conf eth_conf;
  memset(&eth_conf, 0, sizeof(eth_conf));

  eth_conf.rxmode.mq_mode = ETH_MQ_RX_NONE;
  eth_conf.rxmode.max_rx_pkt_len = RTE_ETHER_MAX_LEN;
  eth_conf.rxmode.offloads = 0;

  // XXX: ixgbe does not support fast free offload, but i40e does
  eth_conf.txmode.mq_mode = ETH_MQ_TX_NONE;
  eth_conf.txmode.offloads = DEV_TX_OFFLOAD_MULTI_SEGS;

  eth_conf.fdir_conf.mode = RTE_FDIR_MODE_PERFECT;
  eth_conf.fdir_conf.pballoc = RTE_FDIR_PBALLOC_64K;
  eth_conf.fdir_conf.status = RTE_FDIR_NO_REPORT_STATUS;
  eth_conf.fdir_conf.mask.dst_port_mask = 0xffff;
  eth_conf.fdir_conf.drop_queue = 0;

  ret = rte_eth_dev_configure(kAppPortId, FLAGS_num_threads, FLAGS_num_threads,
                              &eth_conf);
  rt_assert(ret == 0, "Dev config err " + std::string(rte_strerror(rte_errno)));

  check_supported_filters(kAppPortId);

  // FILTER_SET fails for ixgbe, even though it supports flow director. As a
  // workaround, don't call FILTER_SET if ntuple filter is supported.
  if (kInstallFlowRules &&
      rte_eth_dev_filter_supported(kAppPortId, RTE_ETH_FILTER_NTUPLE) != 0) {
    struct rte_eth_fdir_filter_info fi;
    memset(&fi, 0, sizeof(fi));
    fi.info_type = RTE_ETH_FDIR_FILTER_INPUT_SET_SELECT;
    fi.info.input_set_conf.flow_type = RTE_ETH_FLOW_NONFRAG_IPV4_UDP;
    fi.info.input_set_conf.inset_size = 2;
    fi.info.input_set_conf.field[0] = RTE_ETH_INPUT_SET_L3_DST_IP4;
    fi.info.input_set_conf.field[1] = RTE_ETH_INPUT_SET_L4_UDP_DST_PORT;
    fi.info.input_set_conf.op = RTE_ETH_INPUT_SET_SELECT;
    ret = rte_eth_dev_filter_ctrl(kAppPortId, RTE_ETH_FILTER_FDIR,
                                  RTE_ETH_FILTER_SET, &fi);
    printf("Failed to configure fdir fields. This could be survivable.\n");
  }

  struct rte_ether_addr mac;
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

    // XXX: Are these thresh and txq_flags value optimal?
    rte_eth_rxconf eth_rx_conf;
    memset(&eth_rx_conf, 0, sizeof(eth_rx_conf));
    eth_rx_conf.rx_thresh.pthresh = 8;
    eth_rx_conf.rx_thresh.hthresh = 0;
    eth_rx_conf.rx_thresh.wthresh = 0;
    eth_rx_conf.rx_free_thresh = 0;
    eth_rx_conf.rx_drop_en = 0;
    ret = rte_eth_rx_queue_setup(kAppPortId, i, kAppNumRxRingDesc, kAppNumaNode,
                                 &eth_rx_conf, mempools[i]);
    rt_assert(ret == 0, "Failed to setup RX queue " + std::to_string(i));

    rte_eth_txconf eth_tx_conf;
    memset(&eth_tx_conf, 0, sizeof(eth_tx_conf));
    eth_tx_conf.tx_thresh.pthresh = 32;
    eth_tx_conf.tx_thresh.hthresh = 0;
    eth_tx_conf.tx_thresh.wthresh = 0;
    eth_tx_conf.tx_free_thresh = 0;
    eth_tx_conf.tx_rs_thresh = 0;
    eth_tx_conf.offloads = eth_conf.txmode.offloads;

    ret = rte_eth_tx_queue_setup(kAppPortId, i, kAppNumTxRingDesc, kAppNumaNode,
                                 &eth_tx_conf);
    rt_assert(ret == 0, "Failed to setup TX queue " + std::to_string(i));

    if (kInstallFlowRules) add_filter_rule(i, kBaseUDPPort + i);
  }

  ret = rte_eth_dev_set_mtu(kAppPortId, kAppMTU);
  rt_assert(ret >= 0, "Failed to set MTU");

  ret = rte_eth_dev_start(kAppPortId);  // This starts the RX/TX queues
  rt_assert(ret >= 0, "Failed to start port");

  // Retrieve the link speed and compute information based on it.
  struct rte_eth_link link;
  rte_eth_link_get(kAppPortId, &link);
  rt_assert(link.link_status > 0, "Failed to detect link");
  printf("Link bandwidth = %u Mbps\n", link.link_speed);

  // rte_eth_promiscuous_enable(kAppPortId);
  auto thread_arr = new std::thread[FLAGS_num_threads];
  for (size_t i = 0; i < FLAGS_num_threads; i++) {
    if (FLAGS_is_sender == 0) {
      thread_arr[i] = std::thread(receiver_thread_func, i);
    } else {
      thread_arr[i] = std::thread(sender_thread_func, mempools[i], i);
    }

    // Bind thread i to core i
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(i, &cpuset);
    int rc = pthread_setaffinity_np(thread_arr[i].native_handle(),
                                    sizeof(cpu_set_t), &cpuset);
    rt_assert(rc == 0, "Error setting thread affinity");
  }

  for (size_t i = 0; i < FLAGS_num_threads; i++) thread_arr[i].join();
}
