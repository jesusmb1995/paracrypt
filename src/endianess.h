//#include "openssl/aes_locl.h"
#include <endian.h>
#include <stdint.h>

#ifndef HEADER_ENDIANESS_H
#define HEADER_ENDIANESS_H

//#define SWAP_ENDIAN(pt) (((u32)(pt)[0] << 24) | ((u32)(pt)[1] << 16) | ((u32)(pt)[2] <<  8) | ((u32)(pt)[3]))

void big(uint32_t* little, uint32_t* store, int n);

#endif /* !HEADER_ENDIANESS_H */