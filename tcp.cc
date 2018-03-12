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

#include "packets.h"
#include "checksum.h"

#define IP_PROTOCOL_TCP 6
#define IP_PROTOCOL_UNKNOWN 250

#define BUFFER_SIZE 2048

#define SRC_PORT 48881
#define DEST_PORT 48880

static int socket_fd = -1;
static int read_socket = -1;
static uint8_t buffer[BUFFER_SIZE];

class TCPClient {
 public:
  // https://upload.wikimedia.org/wikipedia/commons/thumb/f/f6/Tcp_state_diagram_fixed_new.svg/1280px-Tcp_state_diagram_fixed_new.svg.png
  enum State {
    kUninitialized = 0,
    kClosed = 1,
    kSynSent = 2,
    kEstablished = 3,
  };

  TCPClient() : state_(kUninitialized) {
    // TODO make send_seq_ random
  }

  void Start(int send_socket, uint8_t* my_ip, uint8_t* other_ip) {
    SetState(kClosed);
    send_socket_ = send_socket;
    memcpy(my_ip_, my_ip, 4);
    memcpy(other_ip_, other_ip, 4);

    my_seq_ = 4880;
    other_seq_ = 0;

    TCPFlags send_flags;
    send_flags.syn = 1;
    Send(0, 0, send_flags.GetValue());
    SetState(kSynSent);
  }

  void Receive(TCP* tcp) {
    printf("received tcp\n");
    printf("  fin: %d, syn: %d, rst: %d, psh: %d\n", tcp->GetFlags()->fin,
           tcp->GetFlags()->syn, tcp->GetFlags()->rst, tcp->GetFlags()->psh);
    printf("  ack: %d, urg: %d, ece: %d, cwr: %d\n", tcp->GetFlags()->ack,
           tcp->GetFlags()->urg, tcp->GetFlags()->ece, tcp->GetFlags()->cwr);

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
        other_seq_ = tcp->GetSeq();
        // send an ack
        printf("  got synack. sending ack\n");
        TCPFlags ack_flags;
        ack_flags.ack = 1;
        Send(0, 0, ack_flags.GetValue());
        SetState(kEstablished);
        break;
      }
      case kEstablished:
        // TODO
        printf("  kEstablished\n");
        break;
    }
  }

  void Cancel() { SetState(kClosed); }

  void Send(void* buffer, int buffer_length);

 private:
  State state_;
  uint32_t my_seq_;
  uint32_t other_seq_;
  int send_socket_;

  uint8_t my_ip_[4];
  uint8_t other_ip_[4];

  void Send(void* buffer, int buffer_length, uint8_t flags) {
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
    tcp->SetSeq(my_seq_++);
    tcp->SetAckNumber(other_seq_);
    //tcp->SetAckNumber(other_seq_ + 1);
    // data_offset must increase if using tcp options
    tcp->data_offset = sizeof(TCP) / 4;
    *(tcp->GetFlags()) = flags;
    tcp->SetWindowSize(29200);

    memcpy(tcp + 1, buffer, buffer_length);

    tcp->checksum = in_cksum((short unsigned*)pseudo_header, tcp_pseudo_length);

    int bytes_written = write(socket_fd, tcp, tcp_length);
    free(pseudo_header);
    if (bytes_written != tcp_length) {
      printf("  UNABLE TO write() ENTIRE PACKET\n");
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

TCPClient tcp_client;

static void ReadFromSocket(int socket) {
  memset(buffer, 0, BUFFER_SIZE);
  /*int bytes_read = */ read(socket, buffer, BUFFER_SIZE);
  // printf("read %d bytes from socket\n", bytes_read);

  Ethernet* ethernet = (Ethernet*)buffer;
  // printf("  ethernet dest: %s\n", ethernet->DestToString().c_str());
  // printf("  ethernet src: %s\n", ethernet->SrcToString().c_str());
  // printf("  ethernet type: %s\n", ethernet->TypeToString().c_str());

  if (ethernet->GetType() == ETHERTYPE_IP) {
    IP* ip = (IP*)(ethernet + 1);
    // printf("  ip->version: %d\n", ip->version);
    // printf("  ip->length: %d\n", ip->length);
    // printf("  ip->GetTotalLength(): %d\n", ip->GetTotalLength());
    // printf("  ip src: %s\n", IPToString(ip->source).c_str());
    // printf("  ip dest: %s\n", IPToString(ip->destination).c_str());
    // printf("  ip->protocol: %d\n", ip->protocol);

    if (ip->protocol == PROTOCOL_TCP) {
      TCP* tcp = (TCP*)(ip + 1);
      // printf("  tcp src port: %d\n", tcp->GetSrcPort());
      // printf("  tcp dest port: %d\n", tcp->GetDestPort());

      if (tcp->GetSrcPort() == DEST_PORT && tcp->GetDestPort() == SRC_PORT) {
        tcp_client.Receive(tcp);
      }
    }
  }
}

int main(int argc, char** argv) {
  addrinfo hints, *res = 0;
  memset(&hints, 0, sizeof(addrinfo));
  /*hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  getaddrinfo("www.example.com", "3490", &hints, &res);*/
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

  printf("writing to socket\n");

  /*const char* payload = "hello_world";
  int payload_length = strlen(payload);*/
  /*const char* payload = "";
  int payload_length = 0;

  // includes data after tcp header
  uint16_t tcp_length = sizeof(TCP) + payload_length;
  uint16_t tcp_pseudo_length = sizeof(TCPPseudoHeader) + tcp_length;

  TCPPseudoHeader* pseudo_header = (TCPPseudoHeader*)malloc(tcp_pseudo_length);
  memset(pseudo_header, 0, tcp_pseudo_length);

  pseudo_header->src_ip[0] = 192;
  pseudo_header->src_ip[1] = 168;
  pseudo_header->src_ip[2] = 248;
  pseudo_header->src_ip[3] = 1;
  pseudo_header->dest_ip[0] = 192;
  pseudo_header->dest_ip[1] = 168;
  pseudo_header->dest_ip[2] = 248;
  pseudo_header->dest_ip[3] = 130;
  pseudo_header->reserved = 0;
  pseudo_header->protocol = IP_PROTOCOL_TCP;
  pseudo_header->SetTcpLength(tcp_length);

  TCP* tcp = (TCP*)(pseudo_header + 1);
  tcp->SetSrcPort(48881);
  tcp->SetDestPort(48880);
  tcp->SetSeq(0xd2113773);
  // data_offset must increase if using tcp options
  tcp->data_offset = sizeof(TCP) / 4;
  tcp->syn = 1;
  tcp->SetWindowSize(29200);

  memcpy(tcp + 1, payload, payload_length);

  tcp->checksum = in_cksum((short unsigned*)pseudo_header, tcp_pseudo_length);

  printf("tcp_length to write: %d\n", tcp_length);
  int bytes_written = write(socket_fd, tcp, tcp_length);
  free(pseudo_header);
  printf("write() returned %d\n", bytes_written);*/

  uint8_t my_ip[4];
  my_ip[0] = 192;
  my_ip[1] = 168;
  my_ip[2] = 248;
  my_ip[3] = 1;
  uint8_t other_ip[4];
  other_ip[0] = 192;
  other_ip[1] = 168;
  other_ip[2] = 248;
  other_ip[3] = 130;

  printf("starting client\n");
  tcp_client.Start(socket_fd, my_ip, other_ip);

  while (1) {
    ReadFromSocket(read_socket);
  }
  return 0;
}
