#include "CudaEcbAes16B.hpp"

// PARALELIZATION_LEVEL = 1B
//
// AES_BLOCK_SIZE / PARALELIZATION_LEVEL
//  => THREADS_PER_CIPHER_BLOCK = 1
//

int paracrypt::CudaEcbAES16B::getGridSize(int n_blocks)
{
	// gridSize = n_(cipher)_blocks * (THREADS_PER_CIPHER_BLOCK/THREADS_PER_THREAD_BLOCK)
	int gridSize = n_blocks / this->getDevice()->getThreadsPerThreadBlock();
	return gridSize;
}

int paracrypt::CudaEcbAES16B::encrypt(const unsigned char in[],
				      const unsigned char out[],
				      int n_blocks)
{
    int gridSize = getGridSize(n_blocks);
    int threadsPerBlock = this->getDevice()->getThreadsPerThreadBlock();

    unsigned char data[];

	HANDLE_ERROR(cudaMemcpy(this->data, in, keySize,cudaMemcpyHostToDevice)); //TODO change by CUDACipherDevic malloc and memcpy

    // in-place processing, ignore interface out argument
    cuda_ecb_aes_16b_encrypt<<gridSize,threadsPerBlock >>
    		(data,this->getDeviceKey(),n_blocks);

    HANDLE_ERROR(cudaMemcpy(this->data, in, keySize,cudaMemcpyHostToDevice));

    return 0;
}

int paracrypt::CudaEcbAES16B::decrypt(const unsigned char in[],
				      const unsigned char out[],
				      int n_blocks)
{
    int gridSize = getGridSize(n_blocks);


    cuda_ecb_aes_16b_decrypt << gridSize, threadsPerBlock >> (in, key,
							      n_blocks);

    return 0;
}
