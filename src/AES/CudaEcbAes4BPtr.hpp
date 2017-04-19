#pragma once

#include "CudaEcbAes.hpp"

namespace paracrypt {

    class CudaEcbAES4BPtr:public CudaEcbAES {
    protected:
  int getThreadsPerCipherBlock();
  int cuda_ecb_aes_encrypt(
  		int gridSize,
  		int threadsPerBlock,
  		unsigned char * data,
  		int n_blocks,
  		uint32_t* key,
  		int rounds,
  		uint32_t* deviceTe0,
  		uint32_t* deviceTe1,
  		uint32_t* deviceTe2,
  		uint32_t* deviceTe3
  		);
  int cuda_ecb_aes_decrypt(
  		int gridSize,
  		int threadsPerBlock,
  		unsigned char * data,
  		int n_blocks,
  		uint32_t* key,
  		int rounds,
  		uint32_t* deviceTd0,
  		uint32_t* deviceTd1,
  		uint32_t* deviceTd2,
  		uint32_t* deviceTd3,
  		uint8_t* deviceTd4
  		);
    };

}
