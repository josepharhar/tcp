#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>

//#include <linux/ip_fw.h>

#include "packets.h"
#include "checksum.h"

#define IP_PROTOCOL_TCP 6
#define IP_PROTOCOL_UNKNOWN 250

int main(int argc, char** argv) {
  addrinfo hints, *res = 0;
  memset(&hints, 0, sizeof(addrinfo));
  /*hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  getaddrinfo("www.example.com", "3490", &hints, &res);*/
  int getaddrinfo_retval =
      getaddrinfo("192.168.248.130", "51371", &hints, &res);
  if (getaddrinfo_retval) {
    printf("getaddrinfo() returned %d, gai_strerror(): %s\n",
           getaddrinfo_retval, gai_strerror(getaddrinfo_retval));
    return 1;
  }

  int fd = socket(AF_INET, SOCK_RAW, IP_PROTOCOL_TCP);
  // int fd = socket(AF_INET, SOCK_RAW, IP_PROTOCOL_UNKNOWN);
  if (fd < 0) {
    printf("socket() returned %d. strerror(): %s\n", fd, strerror(errno));
    return 1;
  }

  if (connect(fd, res->ai_addr, res->ai_addrlen)) {
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

  /*uint8_t* asdf = (uint8_t*)pseudo_header;
  for (unsigned i = 0; i < tcp_pseudo_length; i++) {
    printf("%02X", (int)asdf[i]);
    if ((i + 1) % 8 == 0) {
      printf(" ");
    }
    if ((i + 1) % 16 == 0) {
      printf("\n");
    }
  }*/
  tcp->checksum = in_cksum((short unsigned*)pseudo_header, tcp_pseudo_length);

  printf("tcp_length to write: %d\n", tcp_length);
  int bytes_written = write(fd, tcp, tcp_length);
  free(pseudo_header);
  printf("write() returned %d\n", bytes_written);

  return 0;
}
