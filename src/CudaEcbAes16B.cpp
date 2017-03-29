#include "CudaEcbAes16B.hpp"
#include "CudaEcbAes16B.cuh"

int paracrypt::CudaEcbAES16B::encrypt(const unsigned char in[],
				      const unsigned char out[],
				      int n_blocks)
{
    int gridSize = this->getDevice()->getGridSize(n_blocks,1);
    int threadsPerBlock = this->getDevice()->getThreadsPerThreadBlock();
    int dataSize = n_blocks*AES_BLOCK_SIZE;
    uint32_t* key = this->getDeviceKey()->rd_key;
    int rounds = this->getDeviceKey()->rounds;

	this->getDevice()->memcpyTo((void*)in, this->data, dataSize, this->stream);
	cuda_ecb_aes_16b_encrypt(gridSize,threadsPerBlock,data,n_blocks,key,rounds);
	this->getDevice()->memcpyFrom(this->data, (void*)out, dataSize, this->stream);

    return 0;
}

int paracrypt::CudaEcbAES16B::decrypt(const unsigned char in[],
				      const unsigned char out[],
				      int n_blocks)
{
    int gridSize = this->getDevice()->getGridSize(n_blocks,1);
    int threadsPerBlock = this->getDevice()->getThreadsPerThreadBlock();
    int dataSize = n_blocks*AES_BLOCK_SIZE;
    uint32_t* key = this->getDeviceKey()->rd_key;
    int rounds = this->getDeviceKey()->rounds;

	this->getDevice()->memcpyTo((void*)in, this->data, dataSize, this->stream);
	cuda_ecb_aes_16b_decrypt(gridSize,threadsPerBlock,data,n_blocks,key,rounds); // TODO get decrypt key
	this->getDevice()->memcpyFrom(this->data, (void*)out, dataSize, this->stream);

    return 0;
}