#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

#include <linux/ip_fw.h>

#define IP_PROTOCOL_TCP 6
#define IP_PROTOCOL_UNKNOWN 250

int main(int argc, char** argv) {

  //int fd = socket(AF_INET, SOCK_RAW, IP_PROTOCOL_TCP);
  int fd = socket(AF_INET, SOCK_RAW, IP_PROTOCOL_UNKNOWN);
  printf("socket() returned fd: %d\n", fd);

  uint8_t asdf = 0xA;
  int bytes_written = write(fd, &asdf, 1);
  printf("write() returned %d\n", bytes_written);

  return 0;
}
