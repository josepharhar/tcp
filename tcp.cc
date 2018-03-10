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
  memset(&hints, 0, sizeof(hints));
  /*hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  getaddrinfo("www.example.com", "3490", &hints, &res);*/
  int getaddrinfo_retval = getaddrinfo("192.168.248.1", "51371", &hints, &res);
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

  uint16_t tcp_length = sizeof(TCP);
  TCPPseudoHeader* pseudo_header =
      (TCPPseudoHeader*)calloc(1, sizeof(TCPPseudoHeader) + tcp_length);

  pseudo_header->src_ip[0] = 192;
  pseudo_header->src_ip[1] = 168;
  pseudo_header->src_ip[2] = 248;
  pseudo_header->src_ip[3] = 10;
  pseudo_header->dest_ip[0] = 192;
  pseudo_header->dest_ip[1] = 168;
  pseudo_header->dest_ip[2] = 248;
  pseudo_header->dest_ip[3] = 1;
  pseudo_header->protocol = IP_PROTOCOL_TCP;
  pseudo_header->SetTcpLength(tcp_length);

  TCP* tcp = (TCP*)pseudo_header + 1;

  tcp->SetSrcPort(48881);
  tcp->SetDestPort(48880);
  tcp->SetSeq(0xd2113773);
  tcp->data_offset = sizeof(tcp) / 4;
  tcp->syn = 1;
  tcp->SetWindowSize(29200);
  tcp->checksum = in_cksum((short unsigned int*)pseudo_header, tcp_length);

  int bytes_written = write(fd, &tcp, sizeof(tcp));
  free(pseudo_header);

  printf("write() returned %d\n", bytes_written);

  return 0;
}
