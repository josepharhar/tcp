#ifndef PACKETS_H_
#define PACKETS_H_

#include <arpa/inet.h>

#include <iostream>
#include <string>
#include <sstream>
#include <iomanip>

// https://www.tcpdump.org/pcap.html

#define ETHERTYPE_IP 0x0800
#define ETHERTYPE_ARP 0x0806
#define ETHERTYPE_IPV6 0x86DD

#define PROTOCOL_ICMP 1
#define PROTOCOL_TCP 6
#define PROTOCOL_UDP 17

#define OPCODE_REQUEST 1
#define OPCODE_REPLY 2

#define ICMP_PING_REQUEST 8
#define ICMP_PING_REPLY 0

static std::string EthertypeToString(uint16_t type) {
  switch (type) {
    case ETHERTYPE_IP:
      return "IP";
    case ETHERTYPE_ARP:
      return "ARP";
    case ETHERTYPE_IPV6:
      return "IPv6";
    default:
      char string[100];
      snprintf(string, 100, "unknown ethertype: 0x%X", type);
      return std::string(string);
  }
}

static std::string IPToString(uint8_t* ip) {
  std::stringstream stream;
  stream << (int)ip[0] << "." << (int)ip[1] << "." << (int)ip[2] << "."
         << (int)ip[3];
  return stream.str();
}

static std::string MACToString(const uint8_t* mac) {
  char buffer[100];
  snprintf(buffer, 100, "%02X:%02X:%02X:%02X:%02X:%02X", (int)mac[0],
           (int)mac[1], (int)mac[2], (int)mac[3], (int)mac[4], (int)mac[5]);
  return std::string(buffer);
}

class MAC {
 public:
  MAC() {}
  MAC(const uint8_t* new_addr) { memcpy(addr, new_addr, 6); }

  uint8_t addr[6];

  uint64_t ToNumber() const {
    uint64_t number = 0;
    memcpy(&number, addr, 6);
    return number;
  }

  std::string ToString() const { return MACToString(addr); }

  bool operator==(const MAC& other) {
    for (int i = 0; i < 6; i++) {
      if (addr[i] != other.addr[i]) {
        return false;
      }
    }
    return true;
  }
  bool operator!=(const MAC& other) { return !operator==(other); }
  friend bool operator<(const MAC& left, const MAC& right) {
    return left.ToNumber() < right.ToNumber();
  }
} __attribute__((packed));

class Ethernet {
 public:
  uint8_t mac_dest[6];
  uint8_t mac_src[6];

 private:
  uint16_t type;

 public:
  uint16_t GetType() { return ntohs(type); }
  void SetType(uint16_t new_type) { type = htons(new_type); }
  std::string SrcToString() { return MACToString(mac_src); }
  std::string DestToString() { return MACToString(mac_dest); }
  std::string TypeToString() { return EthertypeToString(GetType()); }
} __attribute__((packed));

static const uint8_t MAC_BCAST_ARRAY[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
static const MAC MAC_BCAST(MAC_BCAST_ARRAY);

class IP {
 public:
  uint8_t version : 4;
  uint8_t length : 4;                     // sizeof this struct / 32
  uint8_t differentiated_services_field;  // aka TOS
 private:
  uint16_t total_length;  // entire packet - sizeof ethernet header
  uint16_t identification;

 public:
  uint8_t flags;
  uint8_t fragment_offset;
  uint8_t time_to_live;
  uint8_t protocol;  // TCP = 6
 private:
  uint16_t checksum;

 public:
  uint8_t source[4];
  uint8_t destination[4];

 public:
  uint16_t GetTotalLength() { return ntohs(total_length); }
  uint16_t GetId() { return ntohs(identification); }
  uint16_t GetChecksum() { return ntohs(checksum); }
} __attribute__((packed));

class TCP {
 private:
  uint16_t src_port;
  uint16_t dest_port;
  uint32_t seq;
  uint32_t ack_number;

 public:
  /*uint8_t data_offset : 4; // length of header / 32
  uint8_t reserved : 3;
  uint8_t ns : 1;*/
  uint8_t ns : 1;
  uint8_t reserved : 3;
  uint8_t data_offset : 4;

  /*uint8_t cwr : 1;
  uint8_t ece : 1;
  uint8_t urg : 1;
  uint8_t ack : 1;
  uint8_t psh : 1;
  uint8_t rst : 1;
  uint8_t syn : 1;
  uint8_t fin : 1;*/

  uint8_t fin : 1;
  uint8_t syn : 1;
  uint8_t rst : 1;
  uint8_t psh : 1;
  uint8_t ack : 1;
  uint8_t urg : 1;
  uint8_t ece : 1;
  uint8_t cwr : 1;

 private:
  uint16_t window_size;

 public:
  uint16_t checksum;

 private:
  uint16_t urgent_pointer;

 public:
  uint16_t GetSrcPort() { return ntohs(src_port); }
  void SetSrcPort(uint16_t new_src_port) { src_port = htons(new_src_port); }
  uint16_t GetDestPort() { return ntohs(dest_port); }
  void SetDestPort(uint16_t new_dest_port) { dest_port = htons(new_dest_port); }
  uint32_t GetSeq() { return ntohl(seq); }
  void SetSeq(uint32_t new_seq) { seq = htonl(new_seq); }
  uint32_t GetAckNumber() { return ntohl(ack_number); }
  void SetAckNumber(uint32_t new_ack_number) {
    ack_number = htonl(new_ack_number);
  }
  uint16_t GetWindowSize() { return ntohs(window_size); }
  void SetWindowSize(uint16_t new_window_size) {
    window_size = htons(new_window_size);
  }
} __attribute__((packed));
static_assert(sizeof(TCP) == 20, "wrong TCP size");

class TCPPseudoHeader {
 public:
  uint8_t src_ip[4];
  uint8_t dest_ip[4];
  uint8_t reserved;
  uint8_t protocol;

 private:
  uint16_t tcp_length;

 public:
  void SetTcpLength(uint16_t new_tcp_length) {
    tcp_length = htons(new_tcp_length);
  }
} __attribute__((packed));

#endif  // PACKETS_H_
