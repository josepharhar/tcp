#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <string>

#include "libtcp.h"

unsigned int ip_addr[4];
uint32_t port = 0;
char path_buffer[256];
static int libtcp_socket = -1;
char data_buffer[65535] = {0};
uint32_t current_position = 0;

static void LoopFunction(const void* buffer, int buffer_length) {
  char* payload = (char*)calloc(1, buffer_length + 1);
  memcpy(data_buffer + current_position, buffer, buffer_length);
  current_position += buffer_length;
  memcpy(payload, buffer, buffer_length);
  printf("%d byte payload:\n%s\n", buffer_length, payload);
}

int main(int argc, char** argv) {
  uint8_t my_ip[4] = {192, 168, 56, 101};
  uint8_t dest_ip[4] = {192, 168, 56, 1};
  // uint8_t dest_ip[4] = {0};
  uint16_t my_port = 48881;
  uint16_t dest_port = 48880;
  FILE *fp;
  
  
  if (argc != 2) {
    printf("Usage: wget [URL]\n");
    exit(-1);
  }
  
  sscanf(argv[1], "%u.%u.%u.%u:%d%s\n", &ip_addr[0], &ip_addr[1], &ip_addr[2], &ip_addr[3], &port, path_buffer);
  printf("HERE: %u.%u.%u.%u:%d%s\n", ip_addr[0], ip_addr[1], ip_addr[2], ip_addr[3], port, path_buffer);
  // dest_ip[0] = (uint8_t) ip_addr[0];
  // dest_ip[1] = (uint8_t) ip_addr[1];
  // dest_ip[2] = (uint8_t) ip_addr[2];
  // dest_ip[3] = (uint8_t) ip_addr[3];

  // uint8_t dest_ip[4] = {0};
  char dest_ip_string[50];
  snprintf(dest_ip_string, 50, "%d.%d.%d.%d", (int)dest_ip[0], (int)dest_ip[1],
           (int)dest_ip[2], (int)dest_ip[3]);
  printf("dest_ip_string: %s\n", dest_ip_string);

  libtcp_socket = libtcp_open(my_ip, dest_ip, my_port, dest_port);
  if (libtcp_socket < 0) {
    printf("libtcp_open() returned %d\n", libtcp_socket);
    return 1;
  }
  printf("HERE1\n");
  // const char* http_request = "GET /json/implemented.json\n\n";
  const char* http_method = "GET";
  char buffer[256] = {0};
  std::string path = (std::string) path_buffer;
  size_t found = path.find_last_of("/\\");
  fp = fopen(path.substr(found + 1).c_str(), "w+");
  sprintf(buffer, "%s %s\n\n", http_method, path_buffer);
  printf("URL: %s\n", buffer);
  // libtcp_send(libtcp_socket, http_request, strlen(http_request));
  printf("HERE2\n");
  libtcp_send(libtcp_socket, buffer, strlen(buffer));

  printf("HERE3\n");
  libtcp_loop(LoopFunction);
  printf("HERE4\n");
  printf("libtcp_loop returned\n");
  fwrite(data_buffer, sizeof(char), current_position, fp);
  fclose(fp);

  return 0;
}
