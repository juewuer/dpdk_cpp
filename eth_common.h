/**
 * @file eth_common.h
 * @brief Common definitons for Ethernet-based transports
 */

#pragma once

#include <arpa/inet.h>
#include <assert.h>
#include <ifaddrs.h>
#include <linux/if_arp.h>
#include <linux/if_packet.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <sstream>
#include <string>

static constexpr uint16_t kIPEtherType = 0x800;
static constexpr uint16_t kIPHdrProtocol = 0x11;

/// The datapath destination UDP port for Rpc ID x is based on
/// kBaseEthUDPPort and the Rpc's NUMA node
static constexpr uint16_t kBaseEthUDPPort = 10000;

/// Check a condition at runtime. If the condition is false, throw exception.
static inline void rt_assert(bool condition, std::string throw_str, char* s) {
  if (unlikely(!condition)) {
    throw std::runtime_error(throw_str + std::string(s));
  }
}

/// Check a condition at runtime. If the condition is false, throw exception.
static inline void rt_assert(bool condition, std::string throw_str) {
  if (unlikely(!condition)) throw std::runtime_error(throw_str);
}

/// Check a condition at runtime. If the condition is false, throw exception.
/// This is faster than rt_assert(cond, str) as it avoids string construction.
static inline void rt_assert(bool condition) {
  if (unlikely(!condition)) throw std::runtime_error("Error");
}

/// Convert a MAC string like "9c:dc:71:5b:32:90" to an array of bytes
static void mac_from_str(const char* str, uint8_t* mac) {
  sscanf(str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &mac[0], &mac[1], &mac[2],
         &mac[3], &mac[4], &mac[5]);
}

static std::string mac_to_string(const uint8_t* mac) {
  std::ostringstream ret;
  for (size_t i = 0; i < 6; i++) {
    ret << std::hex << static_cast<uint32_t>(mac[i]);
    if (i != 5) ret << ":";
  }
  return ret.str();
}

static uint32_t ipv4_from_str(const char* ip) {
  uint32_t addr;
  int ret = inet_pton(AF_INET, ip, &addr);
  rt_assert(ret == 1, "inet_pton() failed for " + std::string(ip));
  return addr;
}

static std::string ipv4_to_string(uint32_t ipv4_addr) {
  char str[INET_ADDRSTRLEN];
  const char* ret = inet_ntop(AF_INET, &ipv4_addr, str, sizeof(str));
  rt_assert(ret == str, "inet_ntop failed");
  str[INET_ADDRSTRLEN - 1] = 0;  // Null-terminate
  return str;
}

/// eRPC session endpoint routing info for Ethernet-based transports
struct eth_routing_info_t {
  uint8_t mac[6];
  uint32_t ipv4_addr;
  uint16_t udp_port;

  std::string to_string() {
    std::ostringstream ret;
    ret << "[MAC " << mac_to_string(mac) << ", IP " << ipv4_to_string(ipv4_addr)
        << ", UDP port " << std::to_string(udp_port) << "]";

    return std::string(ret.str());
  }
};

struct eth_hdr_t {
  uint8_t dst_mac[6];
  uint8_t src_mac[6];
  uint16_t eth_type;

  std::string to_string() const {
    std::ostringstream ret;
    ret << "[ETH: dst " << mac_to_string(dst_mac) << ", src "
        << mac_to_string(src_mac) << ", eth_type "
        << std::to_string(ntohs(eth_type)) << "]";
    return ret.str();
  }
} __attribute__((packed));

struct ipv4_hdr_t {
  uint8_t version_ihl;
  uint8_t type_of_service;
  uint16_t tot_len;
  uint16_t id;
  uint16_t frag_off;
  uint8_t ttl;
  uint8_t protocol;
  uint16_t check;
  uint32_t src_ip;
  uint32_t dst_ip;

  std::string to_string() const {
    std::ostringstream ret;
    ret << "[IPv4: version_ihl " << std::to_string(version_ihl)
        << ", type_of_service " << std::to_string(type_of_service)
        << ", tot_len " << std::to_string(ntohs(tot_len)) << ", id "
        << std::to_string(ntohs(id)) << ", frag_off "
        << std::to_string(ntohs(frag_off)) << ", ttl " << std::to_string(ttl)
        << ", protocol " << std::to_string(protocol) << ", check "
        << std::to_string(check) << ", src IP " << ipv4_to_string(src_ip)
        << ", dst IP " << ipv4_to_string(dst_ip) << "]";
    return ret.str();
  }
} __attribute__((packed));

struct udp_hdr_t {
  uint16_t src_port;
  uint16_t dst_port;
  uint16_t len;
  uint16_t check;

  std::string to_string() const {
    std::ostringstream ret;
    ret << "[UDP: src_port " << std::to_string(ntohs(src_port)) << ", dst_port "
        << std::to_string(ntohs(dst_port)) << ", len "
        << std::to_string(ntohs(len)) << ", check " << std::to_string(check)
        << "]";
    return ret.str();
  }
} __attribute__((packed));

static constexpr size_t kInetHdrsTotSize =
    sizeof(eth_hdr_t) + sizeof(ipv4_hdr_t) + sizeof(udp_hdr_t);
static_assert(kInetHdrsTotSize == 42, "");

static std::string frame_header_to_string(uint8_t* buf) {
  auto* eth_hdr = reinterpret_cast<eth_hdr_t*>(buf);
  auto* ipv4_hdr = reinterpret_cast<ipv4_hdr_t*>(&eth_hdr[1]);
  auto* udp_hdr = reinterpret_cast<udp_hdr_t*>(&ipv4_hdr[1]);

  return eth_hdr->to_string() + ", " + ipv4_hdr->to_string() + ", " +
         udp_hdr->to_string();
}

static void gen_eth_header(eth_hdr_t* eth_header, const uint8_t* src_mac,
                           const uint8_t* dst_mac) {
  memcpy(eth_header->src_mac, src_mac, 6);
  memcpy(eth_header->dst_mac, dst_mac, 6);
  eth_header->eth_type = htons(kIPEtherType);
}

/// Format the IPv4 header for a UDP packet. Note that \p data_size is the
/// payload size in the UDP packet.
static void gen_ipv4_header(ipv4_hdr_t* ipv4_hdr, uint32_t src_ip,
                            uint32_t dst_ip, uint16_t data_size) {
  ipv4_hdr->version_ihl = 0x40 | 0x05;
  ipv4_hdr->type_of_service = 0;
  ipv4_hdr->tot_len = htons(sizeof(ipv4_hdr_t) + sizeof(udp_hdr_t) + data_size);
  ipv4_hdr->id = htons(0);
  ipv4_hdr->frag_off = htons(0);
  ipv4_hdr->ttl = 128;
  ipv4_hdr->protocol = kIPHdrProtocol;
  ipv4_hdr->src_ip = src_ip;
  ipv4_hdr->dst_ip = dst_ip;

  // Compute IP header checksum (copied from DPDK testpmd). On some bare-metal
  // clusters, packets go through with a zero IP checksum. But not on Azure.
  uint16_t* ptr16 = reinterpret_cast<uint16_t*>(ipv4_hdr);
  uint32_t ip_cksum = 0;
  ip_cksum += ptr16[0];
  ip_cksum += ptr16[1];
  ip_cksum += ptr16[2];
  ip_cksum += ptr16[3];
  ip_cksum += ptr16[4];
  ip_cksum += ptr16[6];
  ip_cksum += ptr16[7];
  ip_cksum += ptr16[8];
  ip_cksum += ptr16[9];
  ip_cksum = ((ip_cksum & 0xFFFF0000) >> 16) + (ip_cksum & 0x0000FFFF);
  if (ip_cksum > 65535) ip_cksum -= 65535;
  ip_cksum = (~ip_cksum) & 0x0000FFFF;
  if (ip_cksum == 0) ip_cksum = 0xFFFF;
  ipv4_hdr->check = static_cast<uint16_t>(ip_cksum);
}

/// Format the UDP header for a UDP packet. Note that \p data_size is the
/// payload size in the UDP packet.
static void gen_udp_header(udp_hdr_t* udp_hdr, uint16_t src_port,
                           uint16_t dst_port, uint16_t data_size) {
  udp_hdr->src_port = htons(src_port);
  udp_hdr->dst_port = htons(dst_port);
  udp_hdr->len = htons(sizeof(udp_hdr_t) + data_size);
  udp_hdr->check = 0;
}

/// Return the IPv4 address of a kernel-visible interface
static uint32_t get_interface_ipv4_addr(std::string interface) {
  struct ifaddrs *ifaddr, *ifa;
  rt_assert(getifaddrs(&ifaddr) == 0);
  uint32_t ipv4_addr = 0;

  for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
    if (ifa->ifa_addr->sa_family != AF_INET) continue;  // IP address
    if (strcmp(ifa->ifa_name, interface.c_str()) != 0) continue;

    auto sin_addr = reinterpret_cast<sockaddr_in*>(ifa->ifa_addr);
    ipv4_addr = *reinterpret_cast<uint32_t*>(&sin_addr->sin_addr);
  }

  freeifaddrs(ifaddr);
  return ipv4_addr;
}

/// Fill the MAC address of kernel-visible interface
static void fill_interface_mac(std::string interface, uint8_t* mac) {
  struct ifreq ifr;
  ifr.ifr_addr.sa_family = AF_INET;
  strncpy(ifr.ifr_name, interface.c_str(), IFNAMSIZ - 1);

  int fd = socket(AF_INET, SOCK_DGRAM, 0);
  assert(fd >= 0);

  int ret = ioctl(fd, SIOCGIFHWADDR, &ifr);
  rt_assert(ret == 0, "MAC address IOCTL failed");
  close(fd);

  for (size_t i = 0; i < 6; i++) {
    mac[i] = static_cast<uint8_t>(ifr.ifr_hwaddr.sa_data[i]);
  }
}
