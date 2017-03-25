#include "CudaEcbAes16B.hpp"

int paracrypt::CudaEcbAES16B::encrypt(const unsigned char in[],
				      const unsigned char out[],
				      int n_blocks)
{
    int gridSize = this->device->getGridSize(n_blocks,1);
    int threadsPerBlock = this->getDevice()->getThreadsPerThreadBlock();
    int dataSize = n_blocks*AES_BLOCK_SIZE;

	this->device->memcpyTo(in, this->data, dataSize, this->stream);
	cuda_ecb_aes_16b_encrypt<<gridSize,threadsPerBlock>>(data,n_blocks,this->getDeviceKey());
	this->device->memcpyFrom(this->data, out, dataSize, this->stream);

    return 0;
}

int paracrypt::CudaEcbAES16B::decrypt(const unsigned char in[],
				      const unsigned char out[],
				      int n_blocks)
{
    int gridSize = this->device->getGridSize(n_blocks,1);
    int threadsPerBlock = this->getDevice()->getThreadsPerThreadBlock();
    int dataSize = n_blocks*AES_BLOCK_SIZE;

	this->device->memcpyTo(in, this->data, dataSize, this->stream);
	cuda_ecb_aes_16b_decrypt<<gridSize,threadsPerBlock>>(data,n_blocks,this->getDeviceKey()); // TODO get decrypt key
	this->device->memcpyFrom(this->data, out, dataSize, this->stream);

    return 0;
}
