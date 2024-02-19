#include <asm-generic/socket.h>
#include <bitset>
#include <chrono>
#include <cstdint>
#include <format>
#include <iostream>
#include <iterator>
#include <limits>
#include <linux/if_packet.h>
#include <netinet/in.h>
#include <ranges>
#include <set>
#include <sockpp/sock_address.h>
#include <thread>
#include <unordered_map>
#include <vector>

#include <net/if.h>
#include <net/if_arp.h>

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>

#include <sys/socket.h>

#include "sockpp/inet6_address.h"
#include "sockpp/inet_address.h"
#include "sockpp/raw_socket.h"

#include "flags/flags.h"

auto MY_ETH_OTHER = std::numeric_limits<unsigned short>::max();

const std::unordered_map<std::string, unsigned short> eth_types = {
    {"ETH_P_ALL", 0x0003},          /* Every packet (be careful!!!) */
    {"MY_ETH_OTHER", MY_ETH_OTHER}, /* Every packet (be careful!!!) */
    {"ETH_P_LOOP", 0x0060},         /* Ethernet Loopback packet	*/
    {"ETH_P_PUP", 0x0200},          /* Xerox PUP packet		*/
    {"ETH_P_PUPAT", 0x0201},        /* Xerox PUP Addr Trans packet	*/
    {"ETH_P_TSN", 0x22F0},          /* TSN (IEEE 1722) packet	*/
    {"ETH_P_ERSPAN2", 0x22EB},      /* ERSPAN version 2 (type III)	*/
    {"ETH_P_IP", 0x0800},           /* Internet Protocol packet	*/
    {"ETH_P_X25", 0x0805},          /* CCITT X.25			*/
    {"ETH_P_ARP", 0x0806},          /* Address Resolution packet	*/
    {"ETH_P_BPQ", 0x08FF},          /* G8BPQ AX.25 Ethernet Packet	[ NOT AN
                                       OFFICIALLY          REGISTERED ID ] */
    {"ETH_P_IEEEPUP", 0x0a00},      /* Xerox IEEE802.3 PUP packet */
    {"ETH_P_IEEEPUPAT", 0x0a01},    /* Xerox IEEE802.3 PUP Addr Trans packet */
    {"ETH_P_BATMAN", 0x4305},       /* B.A.T.M.A.N.-Advanced packet [ NOT AN
                                       OFFICIALLY REGISTERED ID ] */
    {"ETH_P_DEC", 0x6000},          /* DEC Assigned proto           */
    {"ETH_P_DNA_DL", 0x6001},       /* DEC DNA Dump/Load            */
    {"ETH_P_DNA_RC", 0x6002},       /* DEC DNA Remote Console       */
    {"ETH_P_DNA_RT", 0x6003},       /* DEC DNA Routing              */
    {"ETH_P_LAT", 0x6004},          /* DEC LAT                      */
    {"ETH_P_DIAG", 0x6005},         /* DEC Diagnostics              */
    {"ETH_P_CUST", 0x6006},         /* DEC Customer use             */
    {"ETH_P_SCA", 0x6007},          /* DEC Systems Comms Arch       */
    {"ETH_P_TEB", 0x6558},          /* Trans Ether Bridging		*/
    {"ETH_P_RARP", 0x8035},         /* Reverse Addr Res packet	*/
    {"ETH_P_ATALK", 0x809B},        /* Appletalk DDP		*/
    {"ETH_P_AARP", 0x80F3},         /* Appletalk AARP		*/
    {"ETH_P_8021Q", 0x8100},        /* 802.1Q VLAN Extended Header  */
    {"ETH_P_ERSPAN", 0x88BE},       /* ERSPAN type II		*/
    {"ETH_P_IPX", 0x8137},          /* IPX over DIX			*/
    {"ETH_P_IPV6", 0x86DD},         /* IPv6 over bluebook		*/
    {"ETH_P_PAUSE", 0x8808},        /* IEEE Pause frames. See 802.3 31B */
    {"ETH_P_SLOW", 0x8809},         /* Slow Protocol. See 802.3ad 43B */
    {"ETH_P_WCCP", 0x883E},     /* Web-cache coordination protocol defined in
                                   draft-wilson-wrec-wccp-v2-00.txt */
    {"ETH_P_MPLS_UC", 0x8847},  /* MPLS Unicast traffic		*/
    {"ETH_P_MPLS_MC", 0x8848},  /* MPLS Multicast traffic	*/
    {"ETH_P_ATMMPOA", 0x884c},  /* MultiProtocol Over ATM	*/
    {"ETH_P_PPP_DISC", 0x8863}, /* PPPoE discovery messages     */
    {"ETH_P_PPP_SES", 0x8864},  /* PPPoE session messages	*/
    {"ETH_P_LINK_CTL", 0x886c}, /* HPNA, wlan link local tunnel */
    {"ETH_P_ATMFATE", 0x8884},  /* Frame-based ATM Transport over Ethernet */
    {"ETH_P_PAE", 0x888E},      /* Port Access Entity (IEEE 802.1X) */
    {"ETH_P_PROFINET", 0x8892}, /* PROFINET			*/
    {"ETH_P_REALTEK", 0x8899},  /* Multiple proprietary protocols */
    {"ETH_P_AOE", 0x88A2},      /* ATA over Ethernet		*/
    {"ETH_P_ETHERCAT", 0x88A4}, /* EtherCAT			*/
    {"ETH_P_8021AD", 0x88A8},   /* 802.1ad Service VLAN		*/
    {"ETH_P_802EX1", 0x88B5},   /* 802.1 Local Experimental 1.  */
    {"ETH_P_PREAUTH", 0x88C7},  /* 802.11 Preauthentication */
    {"ETH_P_TIPC", 0x88CA},     /* TIPC 			*/
    {"ETH_P_LLDP", 0x88CC},     /* Link Layer Discovery Protocol */
    {"ETH_P_MRP", 0x88E3},      /* Media Redundancy Protocol	*/
    {"ETH_P_MACSEC", 0x88E5},   /* 802.1ae MACsec */
    {"ETH_P_8021AH", 0x88E7},   /* 802.1ah Backbone Service Tag */
    {"ETH_P_MVRP", 0x88F5},     /* 802.1Q MVRP                  */
    {"ETH_P_1588", 0x88F7},     /* IEEE 1588 Timesync */
    {"ETH_P_NCSI", 0x88F8},     /* NCSI protocol		*/
    {"ETH_P_PRP", 0x88FB},      /* IEC 62439-3 PRP/HSRv0	*/
    {"ETH_P_CFM", 0x8902},      /* Connectivity Fault Management */
    {"ETH_P_FCOE", 0x8906},     /* Fibre Channel over Ethernet  */
    {"ETH_P_IBOE", 0x8915},     /* Infiniband over Ethernet	*/
    {"ETH_P_TDLS", 0x890D},     /* TDLS */
    {"ETH_P_FIP", 0x8914},      /* FCoE Initialization Protocol */
    {"ETH_P_80221",
     0x8917},              /* IEEE 802.21 Media Independent Handover Protocol */
    {"ETH_P_HSR", 0x892F}, /* IEC 62439-3 HSRv1	*/
    {"ETH_P_NSH", 0x894F}, /* Network Service Header */
    {"ETH_P_LOOPBACK", 0x9000}, /* Ethernet loopback packet, per IEEE 802.3 */
    {"ETH_P_QINQ1",
     0x9100}, /* deprecated QinQ VLAN [ NOT AN OFFICIALLY REGISTERED ID ] */
    {"ETH_P_QINQ2",
     0x9200}, /* deprecated QinQ VLAN [ NOT AN OFFICIALLY REGISTERED ID ] */
    {"ETH_P_QINQ3",
     0x9300}, /* deprecated QinQ VLAN [ NOT AN OFFICIALLY REGISTERED ID ] */
    {"ETH_P_EDSA",
     0xDADA}, /* Ethertype DSA [ NOT AN OFFICIALLY REGISTERED ID ] */
    {"ETH_P_DSA_8021Q",
     0xDADB}, /* Fake VLAN Header for DSA [ NOT AN OFFICIALLY REGISTERED ID ] */
    {"ETH_P_DSA_A5PSW",
     0xE001}, /* A5PSW Tag Value [ NOT AN OFFICIALLY REGISTERED ID ] */
    {"ETH_P_IFE", 0xED3E}, /* ForCES inter-FE LFB type */
    {"ETH_P_AF_IUCV",
     0xFBFB} /* IBM af_iucv [ NOT AN OFFICIALLY REGISTERED ID ] */
};
void hexdump(std::span<char> buffer);

int main(int argc, char *argv[]) {
  const flags::args args(argc, argv);
  auto ether_type_filter_vec =
      args.get_multiple<std::string>("filter", "ETH_P_ALL");
  std::set<unsigned short> ether_type_filter;
  for (const auto &f : ether_type_filter_vec) {
    ether_type_filter.insert(eth_types.at(f));
  }
  if (ether_type_filter.empty()) {
    ether_type_filter.insert(ETH_P_ALL);
  }

  auto recv_interface = args.get<std::string>("i");
  auto interface = recv_interface.value_or("lo");

  auto print_raw = args.get<bool>("dump");

  std::cout << std::format("Hello from sock.cpp. Listening on interface={}.\n",
                           interface);
  auto ETH_HDR_SIZE = interface == "tun0" ? 0 : sizeof(ethhdr);
  if (auto handle =
          sockpp::socket::create_handle(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
      handle) {
    sockpp::raw_socket sock(handle.value());
    sockaddr_ll iface;
    memset(&iface, 0, sizeof(sockaddr_ll));
    iface.sll_family = AF_PACKET;
    iface.sll_protocol = htons(ETH_P_ALL);
    iface.sll_ifindex = static_cast<int>(if_nametoindex(interface.c_str()));
    sockpp::sock_address_any interface_addr(
        reinterpret_cast<const sockaddr *>(&iface), sizeof(sockaddr_ll));
    auto set_interface = sock.bind(interface_addr);
    if (not set_interface) {
      std::cerr << std::format(
          "Error: Could not bind socket to interface {} (#={}) (\"{}\").\n",
          interface, iface.sll_ifindex, set_interface.error_message());
      return 1;
    }
    while (true) {
      std::vector<char> msg(1518);
      if (auto recv = sock.recv(msg.data(), msg.size()); recv) {
        auto tpid = reinterpret_cast<const uint16_t *>(msg.data() + 12);
        if (*tpid == 0x8100) {
          std::cout << "VLAN eth frame is not supported.\n";
        } else {
          std::string eth_hdr_string;
          std::string ip_hdr_string;
          std::string ip6_hdr_string;
          std::string arp_hdr_string;
          std::string pup_hdr_string;
          std::string other_hdr_string;
          const ethhdr *eth = reinterpret_cast<const ethhdr *>(msg.data());
          auto ether_type = eth->h_proto;
          std::format_to(std::back_inserter(eth_hdr_string),
                         "Received data through raw socket (size={}).\n",
                         recv.value());
          std::format_to(std::back_inserter(eth_hdr_string),
                         "  Ethernet header:\n");
          std::format_to(std::back_inserter(eth_hdr_string),
                         "    src={:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}\n",
                         eth->h_source[0], eth->h_source[1], eth->h_source[2],
                         eth->h_source[3], eth->h_source[4], eth->h_source[5]);
          std::format_to(std::back_inserter(eth_hdr_string),
                         "    dst={:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}\n",
                         eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
                         eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
          std::format_to(std::back_inserter(eth_hdr_string),
                         "    type={0} ({0:04X})\n", ntohs(ether_type));
          if (interface == "tun0") {
            const iphdr *ip =
                reinterpret_cast<const iphdr *>(msg.data() + ETH_HDR_SIZE);
            ether_type = ip->version == 4 ? htons(ETH_P_IP) : htons(ETH_P_IPV6);
          }
          switch (ntohs(ether_type)) {
          case ETH_P_IP: {
            if (not ether_type_filter.contains(ETH_P_IP) and
                not ether_type_filter.contains(ETH_P_ALL)) {
              break;
            }
            if (interface != "tun0") {
              std::cout << eth_hdr_string;
            }
            const iphdr *ip =
                reinterpret_cast<const iphdr *>(msg.data() + ETH_HDR_SIZE);
            sockpp::inet_address src_ip{};
            sockpp::inet_address dst_ip{};
            src_ip.sockaddr_in_ptr()->sin_addr.s_addr = ip->saddr;
            dst_ip.sockaddr_in_ptr()->sin_addr.s_addr = ip->daddr;
            std::format_to(std::back_inserter(ip_hdr_string),
                           "  IPv4 header:\n");
            std::format_to(std::back_inserter(ip_hdr_string),
                           "    version={:d}\n", ip->version);
            std::format_to(std::back_inserter(ip_hdr_string),
                           "    type of service={}\n",
                           static_cast<unsigned int>(ip->tos));
            std::format_to(std::back_inserter(ip_hdr_string),
                           "    protocol={}\n", ip->protocol);
            std::format_to(std::back_inserter(ip_hdr_string), "    src={}\n",
                           src_ip.to_string());
            std::format_to(std::back_inserter(ip_hdr_string), "    dst={}\n",
                           dst_ip.to_string());
            std::cout << ip_hdr_string;
            if (print_raw) {
              hexdump(std::span<char>(msg.data(), recv.value()));
            }

            break;
          }
          case ETH_P_IPV6: {
            if (not ether_type_filter.contains(ETH_P_IPV6) and
                not ether_type_filter.contains(ETH_P_ALL)) {
              break;
            }
            if (interface != "tun0") {
              std::cout << eth_hdr_string;
            }
            const ipv6hdr *ip =
                reinterpret_cast<const ipv6hdr *>(msg.data() + ETH_HDR_SIZE);
            sockpp::inet6_address src_ip{};
            sockpp::inet6_address dst_ip{};
            src_ip.sockaddr_in6_ptr()->sin6_addr = ip->saddr;
            dst_ip.sockaddr_in6_ptr()->sin6_addr = ip->daddr;
            std::format_to(std::back_inserter(ip6_hdr_string),
                           "  IPv6 header:\n");
            std::format_to(std::back_inserter(ip6_hdr_string),
                           "    version={:d}\n", ip->version);
            std::format_to(std::back_inserter(ip6_hdr_string),
                           "    protocol={}\n", ip->nexthdr);
            std::format_to(std::back_inserter(ip6_hdr_string), "    src={}\n",
                           src_ip.to_string());
            std::format_to(std::back_inserter(ip6_hdr_string), "    dst={}\n",
                           dst_ip.to_string());
            std::cout << ip6_hdr_string;
            if (print_raw) {
              hexdump(std::span<char>(msg.data(), recv.value()));
            }

            break;
          }
          case ETH_P_ARP: {
            if (not ether_type_filter.contains(ETH_P_ARP) and
                not ether_type_filter.contains(ETH_P_ALL)) {
              break;
            }
            if (interface != "tun0") {
              std::cout << eth_hdr_string;
            }
            const arphdr *arp =
                reinterpret_cast<const arphdr *>(msg.data() + ETH_HDR_SIZE);
            std::format_to(std::back_inserter(arp_hdr_string),
                           "  ARP header:\n");
            sockpp::inet_address src_ip(
                ntohl(*reinterpret_cast<const uint32_t *>(
                    msg.data() + ETH_HDR_SIZE + sizeof(arphdr) + 6)),
                0);
            sockpp::inet_address dst_ip(
                ntohl(*reinterpret_cast<const uint32_t *>(
                    msg.data() + ETH_HDR_SIZE + sizeof(arphdr) + 16)),
                0);
            std::format_to(std::back_inserter(arp_hdr_string), "    src={}\n",
                           src_ip.to_string());
            std::format_to(std::back_inserter(arp_hdr_string), "    dst={}\n",
                           dst_ip.to_string());
            std::format_to(std::back_inserter(arp_hdr_string), "    op={}\n",
                           arp->ar_op == 1 ? "REQUEST" : "RESPONSE");
            std::cout << arp_hdr_string;
            if (print_raw) {
              hexdump(std::span<char>(msg.data(), recv.value()));
            }

            break;
          }
          case ETH_P_IEEEPUP: {
            if (not ether_type_filter.contains(ETH_P_IEEEPUP) and
                not ether_type_filter.contains(ETH_P_ALL)) {
              break;
            }
            if (interface != "tun0") {
              std::cout << eth_hdr_string;
            }
            std::format_to(std::back_inserter(pup_hdr_string),
                           "  PUP header:\n");
            const uint8_t *src_addr = reinterpret_cast<const uint8_t *>(
                msg.data() + ETH_HDR_SIZE + 14);
            const uint8_t *src_host = reinterpret_cast<const uint8_t *>(
                msg.data() + ETH_HDR_SIZE + 15);
            const uint32_t *src_socket = reinterpret_cast<const uint32_t *>(
                msg.data() + ETH_HDR_SIZE + 16);
            const uint8_t *dst_addr = reinterpret_cast<const uint8_t *>(
                msg.data() + ETH_HDR_SIZE + 8);
            const uint8_t *dst_host = reinterpret_cast<const uint8_t *>(
                msg.data() + ETH_HDR_SIZE + 9);
            const uint32_t *dst_socket = reinterpret_cast<const uint32_t *>(
                msg.data() + ETH_HDR_SIZE + 10);
            std::format_to(std::back_inserter(pup_hdr_string),
                           "    src addr={}\n", *src_addr);
            std::format_to(std::back_inserter(pup_hdr_string),
                           "    src port={}\n", *src_host);
            std::format_to(std::back_inserter(pup_hdr_string),
                           "    src socket={}\n", *src_socket);
            std::format_to(std::back_inserter(pup_hdr_string),
                           "    dst addr={}\n", *dst_addr);
            std::format_to(std::back_inserter(pup_hdr_string),
                           "    dst port={}\n", *dst_host);
            std::format_to(std::back_inserter(pup_hdr_string),
                           "    dst socket={}\n", *dst_socket);
            std::cout << pup_hdr_string;
            if (print_raw) {
              hexdump(std::span<char>(msg.data(), recv.value()));
            }

            break;
          }
          default: {
            if (not ether_type_filter.contains(MY_ETH_OTHER) and
                not ether_type_filter.contains(ETH_P_ALL)) {
              break;
            }
            if (interface != "tun0") {
              std::cout << eth_hdr_string;
            }
            std::format_to(std::back_inserter(other_hdr_string),
                           "  Other header:\n");
            std::cout << other_hdr_string;
            if (print_raw) {
              hexdump(std::span<char>(msg.data(), recv.value()));
            }
          }
          }
        }
      } else {
        std::cout << std::format("Failed to receive data.\n");
      }
      using namespace std::chrono_literals;
      // std::this_thread::sleep_for(5s);
      // std::cout << std::endl;
    }
  } else {
    std::cout << std::format("Failed to receive handle to raw socket: {}.\n",
                             handle.error_message());
  }

  std::cout << std::format("Goodbye from sock.cpp.\n");
}

void hexdump(std::span<char> buffer) {
  const std::array<char, 16> hex_chars = {'0', '1', '2', '3', '4', '5',
                                          '6', '7', '8', '9', 'A', 'B',
                                          'C', 'D', 'E', 'F'};
  std::cout << "Raw packet:\n";
  for (auto count = 0; auto c : buffer) {
    if (count % 6 == 0 and count > 0) {
      std::cout << std::endl;
    }
    std::cout << std::format("{}", hex_chars[(c & 0xF0) >> 4]);
    std::cout << std::format("{} ", hex_chars[(c & 0x0F) >> 0]);
    // std::cout << std::format("{:08b} ", static_cast<uint8_t>(c));
    ++count;
  }
  std::cout << std::endl;
}
