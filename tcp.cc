#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>

//#include <linux/ip_fw.h>

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

  // int fd = socket(AF_INET, SOCK_RAW, IP_PROTOCOL_TCP);
  int fd = socket(AF_INET, SOCK_RAW, IP_PROTOCOL_UNKNOWN);
  if (fd < 0) {
    printf("socket() returned %d. strerror(): %s\n", fd, strerror(errno));
    return 1;
  }

  if (connect(fd, res->ai_addr, res->ai_addrlen)) {
    printf("connect() failed. strerror(): %s\n", strerror(errno));
    return 1;
  }

  printf("writing to socket\n");
  uint8_t asdf = 0xA;
  int bytes_written = write(fd, &asdf, 1);
  printf("write() returned %d\n", bytes_written);

  return 0;
}
