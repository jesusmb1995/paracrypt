#include "CudaEcbAes4BPtr.hpp"
#include "CudaEcbAes4BPtr.cuh"

int paracrypt::CudaEcbAES4BPtr::getThreadsPerCipherBlock() {
	return 4;
}

int paracrypt::CudaEcbAES4BPtr::cuda_ecb_aes_encrypt(
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
   		){
	int key_bits = 0;
	switch(rounds) {
	case 10:
		key_bits = 128;
		break;
	case 12:
		key_bits = 192;
		break;
	case 14:
		key_bits = 256;
		break;
	default:
		return -1;
	}
	LOG_TRACE(boost::format("cuda_ecb_aes_4b_encrypt("
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
	cuda_ecb_aes_4b_ptr_encrypt(
			gridSize,
			threadsPerBlock,
			n_blocks,
			this->data,
			key,
			key_bits,
	   		deviceTe0,
	   		deviceTe1,
	   		deviceTe2,
	   		deviceTe3
	);
	return 0;
}

int paracrypt::CudaEcbAES4BPtr::cuda_ecb_aes_decrypt(
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
    	){
	int key_bits = 0;
	switch(rounds) {
	case 10:
		key_bits = 128;
		break;
	case 12:
		key_bits = 192;
		break;
	case 14:
		key_bits = 256;
		break;
	default:
		return -1;
	}
	LOG_TRACE(boost::format("cuda_ecb_aes_8b_decrypt("
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
	cuda_ecb_aes_4b_ptr_decrypt(
			gridSize,
			threadsPerBlock,
			n_blocks,
			this->data,
			key,
			key_bits,
	   		deviceTd0,
	   		deviceTd1,
	   		deviceTd2,
	   		deviceTd3,
	   		deviceTd4
	);
	return 0;
}