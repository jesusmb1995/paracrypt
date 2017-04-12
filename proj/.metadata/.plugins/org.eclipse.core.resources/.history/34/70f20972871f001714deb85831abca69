#include "CudaEcbAes16B.hpp"
#include "CudaEcbAes16B.cuh"

int paracrypt::CudaEcbAES16B::cuda_ecb_aes_encrypt(
   		int gridSize,
   		int threadsPerBlock,
   		unsigned char * data,
   		int n_blocks,
   		uint32_t* key,
   		int rounds,
   		uint32_t* deviceTe0,
   		uint32_t* deviceTe1,
   		uint32_t* deviceTe2,
   		uint32_t* deviceTe3,
   		uint32_t* deviceTd0,
   		uint32_t* deviceTd1,
   		uint32_t* deviceTd2,
   		uint32_t* deviceTd3,
   		uint8_t* deviceTd4
   		){
	 	if(rounds == 10) {
			LOG_TRACE(boost::format("cuda_ecb_aes128_16b_encrypt("
					"gridSize=%d"
					", threadsPerBlock=%d"
					", data=%x"
					", n_blocks=%d"
					", expanded_key=%x"
					", rounds=%d)")
				% gridSize
				% threadsPerBlock
				% (void*) (this->data)
				% n_blocks
				% key
				% rounds);
			cuda_ecb_aes128_16b_encrypt(
					gridSize,
					threadsPerBlock,
					n_blocks,
					this->data,
					key,
			   		deviceTe0,
			   		deviceTe1,
			   		deviceTe2,
			   		deviceTe3
			);
	 	}
	 return 0;
}

int paracrypt::CudaEcbAES16B::cuda_ecb_aes_decrypt(
   		int gridSize,
   		int threadsPerBlock,
   		unsigned char * data,
   		int n_blocks,
   		uint32_t* key,
   		int rounds,
   		uint32_t* deviceKey,
   		uint32_t* deviceTe0,
   		uint32_t* deviceTe1,
   		uint32_t* deviceTe2,
   		uint32_t* deviceTe3,
   		uint32_t* deviceTd0,
   		uint32_t* deviceTd1,
   		uint32_t* deviceTd2,
   		uint32_t* deviceTd3,
   		uint8_t* deviceTd4
    	){
	// TODO
	return 0;
}
