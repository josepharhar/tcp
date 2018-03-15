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

static int read_socket = -1;
static uint8_t buffer[BUFFER_SIZE];

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

  void Receive(Ethernet* ethernet, int size) {
    if (size >= (int)sizeof(Ethernet) && ethernet->GetType() == ETHERTYPE_IP) {
      Receive((IP*)(ethernet + 1), size - sizeof(Ethernet));
    }
  }

  void Receive(IP* ip, int size) {
    if (size >= (int)sizeof(IP) && IPAddr(my_ip_) == ip->GetDest() &&
        IPAddr(other_ip_) == ip->GetSrc() && ip->protocol == PROTOCOL_TCP) {
      Receive((TCP*)(ip + 1), ip->GetTotalLength() - ip->GetHeaderLength());
    }
  }

  void Receive(TCP* tcp, int size) {
    if (size < (int)sizeof(TCP) || tcp->GetSrcPort() != other_port_ ||
        tcp->GetDestPort() != my_port_) {
      return;
    }

    int payload_size = size - tcp->data_offset * 4;

    /*printf("received tcp. state: %d\n", state_);
    printf("  fin: %d, syn: %d, rst: %d, psh: %d\n", tcp->GetFlags()->fin,
           tcp->GetFlags()->syn, tcp->GetFlags()->rst, tcp->GetFlags()->psh);
    printf("  ack: %d, urg: %d, ece: %d, cwr: %d\n", tcp->GetFlags()->ack,
           tcp->GetFlags()->urg, tcp->GetFlags()->ece, tcp->GetFlags()->cwr);*/

    switch (state_) {
      case kUninitialized:
        assert(false);
        break;

      case kClosed:
        printf("  state is kClosed. nani!?\n");
        break;

      case kSynSent: {
        // packet coming back should be SYN-ACK
        TCPFlags expected_flags;
        expected_flags.syn = 1;
        expected_flags.ack = 1;
        if (*(tcp->GetFlags()) != expected_flags) {
          printf("  packet coming back should have been synack.\n");
          Cancel();
          break;
        }
        init_other_seq_ = tcp->GetSeq();
        other_seq_ = tcp->GetSeq();

        other_seq_++;  // TODO when exactly should this be incremented?
        // the ack number we send back is supposed to be
        // the last seq we fully received + 1.

        // send an ack
        printf("  got synack. sending ack\n");
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
          printf("  BAD tcp->GetSeq(): %u\n", tcp->GetSeq());
          printf("         other_seq_: %u\n", other_seq_);
          printf("    init_other_seq_: %u\n", init_other_seq_);
          break;
        }
        if (payload_size) {
          /*char* payload = (char*)calloc(1, payload_size + 1);
          memcpy(payload, tcp + 1, payload_size);
          printf("  %d byte payload:\n%s\n", payload_size, payload);*/
          /*printf(
              "  sizeof(TCP): %lu, tcp->GetHeaderLength(): %d, full size: %d\n",
              sizeof(TCP), tcp->GetHeaderLength(), size);*/
          if (g_loop_function) {
            g_loop_function(tcp + 1, payload_size);
          }
        }
        if (!payload_size) {
          // printf("  no payload, should other_seq_ be incremented??\n");
        }
        other_seq_ += payload_size;

        if (tcp->GetFlags()->fin) {
          // TODO only send fin back when we are done sending data n stuff.
          printf("  received fin, sending fin back.\n");
          TCPFlags fin_flags;
          fin_flags.fin = 1;
          fin_flags.ack = 1;
          other_seq_++;  // TODO delet this
          Send(0, 0, fin_flags.GetValue());
        }

        break;
    }
  }

  void Cancel() {
    switch (state_) {
      case kUninitialized:
      case kClosed:
        break;
      case kSynSent:
      case kEstablished: {
        printf("  sending reset\n");
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
    tcp->SetSrcPort(48881);
    tcp->SetDestPort(48880);
    tcp->SetSeq(my_seq_);

    my_seq_ += buffer_length;
    if (!buffer_length) {
      /*printf(
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

    int bytes_written = write(send_socket_, tcp, tcp_length);
    free(pseudo_header);
    if (bytes_written != tcp_length) {
      printf("  UNABLE TO write() ENTIRE PACKET! wrote %d, expected %d\n",
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
          printf("state_: %d, new_state: %d\n", state_, new_state);
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

static void ReadFromSocket(int socket) {
  memset(buffer, 0, BUFFER_SIZE);
  int bytes_read = read(socket, buffer, BUFFER_SIZE);
  // printf("read() %d bytes\n", bytes_read);
  for (auto it = libtcp_fd_to_client.begin(); it != libtcp_fd_to_client.end();
       it++) {
    TCPClient* client = it->second;
    client->Receive((Ethernet*)buffer, bytes_read);
  }
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
  printf("dest_ip_string: %s\n", dest_ip_string);

  char dest_port_string[50];
  memset(dest_port_string, 0, 50);
  snprintf(dest_port_string, 50, "%d", dest_port);
  printf("dest_port_string: %s\n", dest_port_string);

  int getaddrinfo_retval =
      getaddrinfo(dest_ip_string, dest_port_string, &hints, &res);
  if (getaddrinfo_retval) {
    printf("[libtcp_open] getaddrinfo() returned %d, gai_strerror(): %s\n",
           getaddrinfo_retval, gai_strerror(getaddrinfo_retval));
    return -1;
  }

  int send_socket_fd = socket(AF_INET, SOCK_RAW, IP_PROTOCOL_TCP);
  if (send_socket_fd < 0) {
    printf("[libtcp_open] socket() returned %d. strerror(): %s\n",
           send_socket_fd, strerror(errno));
    return -1;
  }

  if (connect(send_socket_fd, res->ai_addr, res->ai_addrlen)) {
    printf("[libtcp_open] connect() failed. strerror(): %s\n", strerror(errno));
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
      printf("socket(AF_PACKET) returned %d. strerror(): %s\n", read_socket,
             strerror(errno));
      return;
    }
  }

  while (1) {
    ReadFromSocket(read_socket);
  }
}

/*int main(int argc, char** argv) {
  addrinfo hints, *res = 0;
  memset(&hints, 0, sizeof(addrinfo));
  //hints.ai_family = AF_UNSPEC;
  //hints.ai_socktype = SOCK_STREAM;
  //getaddrinfo("www.example.com", "3490", &hints, &res);
  int getaddrinfo_retval =
      getaddrinfo("192.168.248.130", "48880", &hints, &res);
  if (getaddrinfo_retval) {
    printf("getaddrinfo() returned %d, gai_strerror(): %s\n",
           getaddrinfo_retval, gai_strerror(getaddrinfo_retval));
    return 1;
  }

  socket_fd = socket(AF_INET, SOCK_RAW, IP_PROTOCOL_TCP);
  if (socket_fd < 0) {
    printf("socket() returned %d. strerror(): %s\n", socket_fd,
           strerror(errno));
    return 1;
  }

  read_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
  if (read_socket < 0) {
    printf("socket(AF_PACKET) returned %d. strerror(): %s\n", read_socket,
           strerror(errno));
  }

  if (connect(socket_fd, res->ai_addr, res->ai_addrlen)) {
    printf("connect() failed. strerror(): %s\n", strerror(errno));
    return 1;
  }

  uint8_t my_ip[4] = {192, 168, 248, 10};
  uint8_t other_ip[4] = {192, 168, 248, 130};

  printf("starting client\n");
  tcp_client.Start(socket_fd, my_ip, other_ip, 48881, 48880);

  while (1) {
    ReadFromSocket(read_socket);
  }
  return 0;
}*/
