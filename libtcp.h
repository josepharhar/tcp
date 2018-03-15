#ifndef LIBTCP_H_
#define LIBTCP_H_

#include <stdint.h>

int libtcp_open(uint8_t* my_ip,
                uint8_t* dest_ip,
                uint16_t my_port,
                uint16_t dest_port);
int libtcp_send(int libtcp_fd, const void* src_buffer, int write_length);

typedef void (*LibTcpLoopFunction)(const void* buffer, int buffer_length);
void libtcp_loop(LibTcpLoopFunction loop_function);

#endif  // LIBTCP_H_
