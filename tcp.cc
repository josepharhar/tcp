#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>

//#include <linux/ip_fw.h>
//#include <libiptc/libiptc.h>
#include <linux/if_ether.h>

#include "packets.h"
#include "checksum.h"

#define IP_PROTOCOL_TCP 6
#define IP_PROTOCOL_UNKNOWN 250

#define BUFFER_SIZE 2048

static int socket_fd = -1;
static int read_socket = -1;
static uint8_t buffer[BUFFER_SIZE];

static void ReadFromSocket(int socket) {
  memset(buffer, 0, BUFFER_SIZE);
  int bytes_read = read(socket, buffer, BUFFER_SIZE);
  printf("read %d bytes from socket\n", bytes_read);

  IP* ip = (IP*)buffer;
  printf("  ip->version: %d\n", ip->version);
  printf("  ip->length: %d\n", ip->length);
  printf("  ip->GetTotalLength(): %d\n", ip->GetTotalLength());
  printf("  src: %s\n", IPToString(ip->source).c_str());
  printf("  dest: %s\n", IPToString(ip->destination).c_str());

  Ethernet* ethernet = (Ethernet*)buffer;
  printf("  ethernet dest: %s\n", ethernet->DestToString().c_str());
  printf("  ethernet src: %s\n", ethernet->SrcToString().c_str());
  printf("  ethernet type: %s\n", ethernet->TypeToString().c_str());

  if (ethernet->GetType() == ETHERTYPE_IP) {
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
  const char* payload = "";
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
  printf("write() returned %d\n", bytes_written);

  while (1) {
    ReadFromSocket(read_socket);
  }
  return 0;
}
