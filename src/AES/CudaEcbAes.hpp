#pragma once

#include "AES.hpp"
#include "CudaAES.hpp"

namespace paracrypt {

    class CudaEcbAES:public CudaAES {
    public:
    	CudaEcbAES() {};
    	~CudaEcbAES() {};
    protected:
  virtual int getThreadsPerCipherBlock() = 0;
  virtual int cuda_ecb_aes_encrypt(
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
  		) = 0;
  virtual int cuda_ecb_aes_decrypt(
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
  		) = 0;
    public:
	int encrypt(const unsigned char in[],
		    const unsigned char out[], int n_blocks);
	int decrypt(const unsigned char in[],
		    const unsigned char out[], int n_blocks);
    };

}
