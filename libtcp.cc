#include "libtcp.h"

#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>
#include <assert.h>

//#include <linux/ip_fw.h>
//#include <libiptc/libiptc.h>
#include <linux/if_ether.h>

#include <map>
#include <vector>

#include "packets.h"
#include "checksum.h"

#define IP_PROTOCOL_TCP 6
#define IP_PROTOCOL_UNKNOWN 250

#define BUFFER_SIZE 2048

#ifdef DEBUG
#define printd(...)                                      \
  fprintf(stderr, "[%s:%03d] ", __FUNCTION__, __LINE__); \
  fprintf(stderr, __VA_ARGS__);
#else
#define printd(...) \
  while (0)         \
    ;
#endif

static int read_socket = -1;

static LibTcpLoopFunction g_loop_function = 0;

class TCPClient {
 public:
  // https://upload.wikimedia.org/wikipedia/commons/thumb/f/f6/Tcp_state_diagram_fixed_new.svg/1280px-Tcp_state_diagram_fixed_new.svg.png
  enum State {
    kUninitialized = 0,
    kClosed = 1,
    kSynSent = 2,
    kEstablished = 3,
  };

  TCPClient() : state_(kUninitialized) {}

  void Start(int send_socket,
             uint8_t* my_ip,
             uint8_t* other_ip,
             uint16_t my_port,
             uint16_t other_port) {
    SetState(kClosed);
    send_socket_ = send_socket;

    memcpy(my_ip_, my_ip, 4);
    memcpy(other_ip_, other_ip, 4);

    my_port_ = my_port;
    other_port_ = other_port;

    my_seq_ = rand() % UINT32_MAX + 1;
    init_my_seq_ = my_seq_;
    other_seq_ = 0;

    TCPFlags send_flags;
    send_flags.syn = 1;
    Send(0, 0, send_flags.GetValue());
    SetState(kSynSent);

    // invisible syn byte
    my_seq_++;
  }

  int Receive(Ethernet* ethernet, int size) {
    if (size >= (int)sizeof(Ethernet) && ethernet->GetType() == ETHERTYPE_IP) {
      return Receive((IP*)(ethernet + 1), size - sizeof(Ethernet));
    }
    return 0;
  }

  int Receive(IP* ip, int size) {
    if (size >= (int)sizeof(IP) && IPAddr(my_ip_) == ip->GetDest() &&
        IPAddr(other_ip_) == ip->GetSrc() && ip->protocol == PROTOCOL_TCP) {
      return Receive((TCP*)(ip + 1),
                     ip->GetTotalLength() - ip->GetHeaderLength());
    }
    return 0;
  }

  // returns 1 if the socket is closed
  int Receive(TCP* tcp, int size) {
    if (size < (int)sizeof(TCP) || tcp->GetSrcPort() != other_port_ ||
        tcp->GetDestPort() != my_port_) {
      return 0;
    }

    int payload_size = size - tcp->data_offset * 4;

    printd("received tcp. state: %d\n", state_);
    printd("  fin: %d, syn: %d, rst: %d, psh: %d\n", tcp->GetFlags()->fin,
           tcp->GetFlags()->syn, tcp->GetFlags()->rst, tcp->GetFlags()->psh);
    printd("  ack: %d, urg: %d, ece: %d, cwr: %d\n", tcp->GetFlags()->ack,
           tcp->GetFlags()->urg, tcp->GetFlags()->ece, tcp->GetFlags()->cwr);

    switch (state_) {
      case kUninitialized:
        assert(false);
        break;

      case kClosed:
        printd("  state is kClosed, ignoring received packet\n");
        break;

      case kSynSent: {
        // packet coming back should be SYN-ACK
        TCPFlags expected_flags;
        expected_flags.syn = 1;
        expected_flags.ack = 1;
        if (*(tcp->GetFlags()) != expected_flags) {
          printd("  packet coming back should have been synack.\n");
          Cancel();
          break;
        }
        init_other_seq_ = tcp->GetSeq();
        other_seq_ = tcp->GetSeq();

        other_seq_++;  // TODO when exactly should this be incremented?
        // the ack number we send back is supposed to be
        // the last seq we fully received + 1.

        // send an ack
        printd("  got synack. sending ack\n");
        TCPFlags ack_flags;
        ack_flags.ack = 1;
        Send(0, 0, ack_flags.GetValue());

        SetState(kEstablished);

        // send all buffered packets
        for (unsigned i = 0; i < buffered_packets_to_send_.size(); i++) {
          auto buffered_packet = buffered_packets_to_send_[i];
          Send(buffered_packet.first, buffered_packet.second);
        }

        break;
      }

      case kEstablished:
        if (tcp->GetSeq() != other_seq_) {
          printd("  BAD tcp->GetSeq(): %u\n", tcp->GetSeq());
          printd("         other_seq_: %u\n", other_seq_);
          printd("    init_other_seq_: %u\n", init_other_seq_);
          break;
        }
        if (payload_size) {
          /*char* payload = (char*)calloc(1, payload_size + 1);
          memcpy(payload, tcp + 1, payload_size);
          printd("  %d byte payload:\n%s\n", payload_size, payload);*/
          /*printd(
              "  sizeof(TCP): %lu, tcp->GetHeaderLength(): %d, full size: %d\n",
              sizeof(TCP), tcp->GetHeaderLength(), size);*/
          if (g_loop_function) {
            g_loop_function(tcp + 1, payload_size);
          }
        }
        if (!payload_size) {
          // printd("  no payload, should other_seq_ be incremented??\n");
        }
        other_seq_ += payload_size;

        if (tcp->GetFlags()->fin) {
          // TODO only send fin back when we are done sending data n stuff.
          printd("  received fin, sending fin back.\n");
          TCPFlags fin_flags;
          fin_flags.fin = 1;
          fin_flags.ack = 1;
          other_seq_++;  // TODO delet this
          Send(0, 0, fin_flags.GetValue());

          return 1;
        }

        break;
    }

    return 0;
  }

  void Cancel() {
    switch (state_) {
      case kUninitialized:
      case kClosed:
        break;
      case kSynSent:
      case kEstablished: {
        printd("  sending reset\n");
        TCPFlags reset_flags;
        reset_flags.rst = 1;
        Send(0, 0, reset_flags.GetValue());
        break;
      }
    }
    SetState(kClosed);
  }

  void Send(const void* buffer, int buffer_length) {
    switch (state_) {
      case kUninitialized:
      case kClosed:
      case kSynSent: {
        void* buffer_copy = malloc(buffer_length);
        memcpy(buffer_copy, buffer, buffer_length);
        buffered_packets_to_send_.push_back(
            std::pair<const void*, int>(buffer_copy, buffer_length));
        return;
      }

      case kEstablished:
        break;
    }

    TCPFlags flags;
    flags.ack = 1;
    flags.psh = 1;
    Send(buffer, buffer_length, flags.GetValue());
  }

 private:
  State state_;
  int send_socket_;

  uint16_t my_port_;
  uint16_t other_port_;

  uint8_t my_ip_[4];
  uint8_t other_ip_[4];

  uint32_t my_seq_;
  uint32_t other_seq_;

  uint32_t init_my_seq_;
  uint32_t init_other_seq_;

  // this buffers packets sent using Send() but only before
  // state kEstablished is reached
  std::vector<std::pair<const void*, int>> buffered_packets_to_send_;

  void Send(const void* buffer, int buffer_length, uint8_t flags) {
    // includes data after tcp header
    uint16_t tcp_length = sizeof(TCP) + buffer_length;
    uint16_t tcp_pseudo_length = sizeof(TCPPseudoHeader) + tcp_length;

    TCPPseudoHeader* pseudo_header =
        (TCPPseudoHeader*)malloc(tcp_pseudo_length);
    memset(pseudo_header, 0, tcp_pseudo_length);

    memcpy(pseudo_header->src_ip, my_ip_, 4);
    memcpy(pseudo_header->dest_ip, other_ip_, 4);
    pseudo_header->reserved = 0;
    pseudo_header->protocol = IP_PROTOCOL_TCP;
    pseudo_header->SetTcpLength(tcp_length);

    TCP* tcp = (TCP*)(pseudo_header + 1);
    tcp->SetSrcPort(my_port_);
    tcp->SetDestPort(other_port_);
    tcp->SetSeq(my_seq_);

    my_seq_ += buffer_length;
    if (!buffer_length) {
      /*printd(
          "  sending with no buffer_length. should my_seq_ be
         incremented??\n");*/
    }

    tcp->SetAckNumber(other_seq_);
    // tcp->SetAckNumber(other_seq_ + 1);
    // data_offset must increase if using tcp options
    tcp->data_offset = sizeof(TCP) / 4;
    *(tcp->GetFlags()) = flags;
    tcp->SetWindowSize(29200);

    memcpy(tcp + 1, buffer, buffer_length);

    tcp->checksum = in_cksum((short unsigned*)pseudo_header, tcp_pseudo_length);
    //tcp->checksum = htons(ntohs(tcp->checksum) + 0x81);
    //tcp->checksum += 0x8100;

    int bytes_written = write(send_socket_, tcp, tcp_length);
    free(pseudo_header);
    if (bytes_written != tcp_length) {
      printd("  UNABLE TO write() ENTIRE PACKET! wrote %d, expected %d\n",
             bytes_written, tcp_length);
      assert(false);
    }
  }

  void SetState(State new_state) {
    switch (new_state) {
      case kUninitialized:
        assert(false);
        break;
      case kClosed:
        break;
      case kSynSent:
        if (state_ != kClosed) {
          printd("state_: %d, new_state: %d\n", state_, new_state);
        }
        assert(state_ == kClosed);
        break;
      case kEstablished:
        assert(state_ == kSynSent);
        break;
    }
    state_ = new_state;
  }
};

static std::map<int, TCPClient*> libtcp_fd_to_client;

static int FindUnusedFd() {
  for (int i = 0; i < 65536; i++) {
    if (libtcp_fd_to_client.find(i) == libtcp_fd_to_client.end()) {
      return i;
    }
  }
  return -1;
}

int libtcp_open(uint8_t* my_ip,
                uint8_t* dest_ip,
                uint16_t my_port,
                uint16_t dest_port) {
  addrinfo hints, *res = 0;
  memset(&hints, 0, sizeof(addrinfo));
  /*hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  getaddrinfo("www.example.com", "3490", &hints, &res);*/

  char dest_ip_string[50];
  memset(dest_ip_string, 0, 50);
  snprintf(dest_ip_string, 50, "%d.%d.%d.%d", (int)dest_ip[0], (int)dest_ip[1],
           (int)dest_ip[2], (int)dest_ip[3]);
  printd("dest_ip_string: %s\n", dest_ip_string);

  char dest_port_string[50];
  memset(dest_port_string, 0, 50);
  snprintf(dest_port_string, 50, "%d", dest_port);
  printd("dest_port_string: %s\n", dest_port_string);

  int getaddrinfo_retval =
      getaddrinfo(dest_ip_string, dest_port_string, &hints, &res);
  if (getaddrinfo_retval) {
    printd("getaddrinfo() returned %d, gai_strerror(): %s\n",
           getaddrinfo_retval, gai_strerror(getaddrinfo_retval));
    return -1;
  }

  int send_socket_fd = socket(AF_INET, SOCK_RAW, IP_PROTOCOL_TCP);
  if (send_socket_fd < 0) {
    printd("socket() returned %d. strerror(): %s\n", send_socket_fd,
           strerror(errno));
    return -1;
  }

  if (connect(send_socket_fd, res->ai_addr, res->ai_addrlen)) {
    printd("connect() failed. strerror(): %s\n", strerror(errno));
    return -1;
  }

  int libtcp_fd = FindUnusedFd();
  TCPClient* new_client = new TCPClient();
  libtcp_fd_to_client[libtcp_fd] = new_client;
  new_client->Start(send_socket_fd, my_ip, dest_ip, my_port, dest_port);

  return libtcp_fd;
}

int libtcp_send(int libtcp_fd, const void* buffer, int length) {
  if (libtcp_fd_to_client.find(libtcp_fd) == libtcp_fd_to_client.end()) {
    return -1;
  }
  TCPClient* client = libtcp_fd_to_client[libtcp_fd];
  // TODO will this work?
  client->Send(buffer, length);

  return length;  // TODO
}

void libtcp_loop(LibTcpLoopFunction loop_function) {
  g_loop_function = loop_function;

  if (read_socket < 0) {
    read_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
    if (read_socket < 0) {
      printd("socket(AF_PACKET) returned %d. strerror(): %s\n", read_socket,
             strerror(errno));
      return;
    }
  }

  uint8_t buffer[BUFFER_SIZE];
  while (1) {
    memset(buffer, 0, BUFFER_SIZE);
    int bytes_read = read(read_socket, buffer, BUFFER_SIZE);
    for (auto it = libtcp_fd_to_client.begin(); it != libtcp_fd_to_client.end();
         it++) {
      TCPClient* client = it->second;

      if (client->Receive((Ethernet*)buffer, bytes_read)) {
        return;
      }
    }
  }
}
