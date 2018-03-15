#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "libtcp.h"

static int libtcp_socket = -1;

static void LoopFunction(const void* buffer, int buffer_length) {
  char* payload = (char*)calloc(1, buffer_length + 1);
  memcpy(payload, buffer, buffer_length);
  printf("%d byte payload:\n%s\n", buffer_length, payload);
}

int main(int argc, char** argv) {
  uint8_t my_ip[4] = {192, 168, 248, 10};
  uint8_t dest_ip[4] = {192, 168, 248, 130};
  uint16_t my_port = 48881;
  uint16_t dest_port = 48880;

  libtcp_socket = libtcp_open(my_ip, dest_ip, my_port, dest_port);
  if (libtcp_socket < 0) {
    printf("libtcp_open() returned %d\n", libtcp_socket);
    return 1;
  }

  const char* http_request = "GET /asdf\n\n";
  libtcp_send(libtcp_socket, http_request, strlen(http_request));

  libtcp_loop(LoopFunction);

  return 0;
}
