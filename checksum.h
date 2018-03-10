#ifndef CHECKSUM_H_
#define CHECKSUM_H_

#ifdef __cplusplus
extern "C" {
#endif

unsigned short in_cksum(unsigned short *addr,int len);

#ifdef __cplusplus
}
#endif

#endif  // CHECKSUM_H_
