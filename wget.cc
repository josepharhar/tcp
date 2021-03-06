#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <string>

#include "libtcp.h"

char path_buffer[256];
static int libtcp_socket = -1;
char data_buffer[65535] = {0};
uint32_t current_position = 0;

static void LoopFunction(const void* buffer, int buffer_length) {
  memcpy(data_buffer + current_position, buffer, buffer_length);
  current_position += buffer_length;

  /*char* payload = (char*)calloc(1, buffer_length + 1);
  memcpy(payload, buffer, buffer_length);
  printf("%d byte payload:\n%s\n", buffer_length, payload);*/
}

int main(int argc, char** argv) {
  uint8_t my_ip[4] = {192, 168, 248, 1};

  uint8_t dest_ip[4] = {0, 0, 0, 0};
  uint16_t my_port = 48881;
  uint16_t dest_port = 0;

  FILE* fp;

  if (argc != 2) {
    printf("Usage: wget [URL]\n");
    exit(-1);
  }

  unsigned temp_ip_addr[4] = {0, 0, 0, 0};
  sscanf(argv[1], "%u.%u.%u.%u:%hu%s\n", &temp_ip_addr[0], &temp_ip_addr[1],
         &temp_ip_addr[2], &temp_ip_addr[3], &dest_port, path_buffer);
  dest_ip[0] = (uint8_t)temp_ip_addr[0];
  dest_ip[1] = (uint8_t)temp_ip_addr[1];
  dest_ip[2] = (uint8_t)temp_ip_addr[2];
  dest_ip[3] = (uint8_t)temp_ip_addr[3];

  libtcp_socket = libtcp_open(my_ip, dest_ip, my_port, dest_port);
  if (libtcp_socket < 0) {
    printf("libtcp_open() returned %d\n", libtcp_socket);
    return 1;
  }
  // const char* http_request = "GET /json/implemented.json\n\n";
  const char* http_method = "GET";
  char buffer[256] = {0};
  std::string path = (std::string)path_buffer;
  size_t found = path.find_last_of("/\\");
  fp = fopen(path.substr(found + 1).c_str(), "w+");
  sprintf(buffer, "%s %s\n\n", http_method, path_buffer);
  printf("URL: %s\n", buffer);
  // libtcp_send(libtcp_socket, http_request, strlen(http_request));
  libtcp_send(libtcp_socket, buffer, strlen(buffer));

  libtcp_loop(LoopFunction);
  printf("finished http request, writing to file...\n");
  fwrite(data_buffer, sizeof(char), current_position, fp);
  fclose(fp);

  return 0;
}
