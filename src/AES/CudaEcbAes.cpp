#include "CudaEcbAes.hpp"

int paracrypt::CudaEcbAES::encrypt(const unsigned char in[],
				      const unsigned char out[],
				      int n_blocks)
{
    int gridSize = this->getDevice()->getGridSize(n_blocks, 1);
    int threadsPerBlock = this->getDevice()->getThreadsPerThreadBlock();
    int dataSize = n_blocks * AES_BLOCK_SIZE;
    uint32_t *key = this->getDeviceKey();
    int rounds = this->getExpandedKey()->rounds;

    this->getDevice()->memcpyTo((void *) in, this->data, dataSize,
				this->stream);
	this->cuda_ecb_aes_encrypt
			(
					gridSize,
					threadsPerBlock,
					this->data,
					n_blocks,
					key,
					rounds,
					this->getDeviceTe0(),
					this->getDeviceTe1(),
					this->getDeviceTe2(),
					this->getDeviceTe3(),
					this->getDeviceTd0(),
					this->getDeviceTd1(),
					this->getDeviceTd2(),
					this->getDeviceTd3(),
					this->getDeviceTd4()
			);
    this->getDevice()->memcpyFrom(this->data, (void *) out, dataSize,
				  this->stream);

    return 0;
}

int paracrypt::CudaEcbAES::decrypt(const unsigned char in[],
				      const unsigned char out[],
				      int n_blocks)
{
    int gridSize = this->getDevice()->getGridSize(n_blocks, 1);
    int threadsPerBlock = this->getDevice()->getThreadsPerThreadBlock();
    int dataSize = n_blocks * AES_BLOCK_SIZE;
    uint32_t *key = this->getDeviceKey();
    int rounds = this->getExpandedKey()->rounds;

    this->getDevice()->memcpyTo((void *) in, this->data, dataSize,
				this->stream);
//    cuda_ecb_aes_16b_decrypt(gridSize, threadsPerBlock, this->data, n_blocks, key, rounds);	// TODO get decrypt key
    this->getDevice()->memcpyFrom(this->data, (void *) out, dataSize,
				  this->stream);

    return 0;
}

// TODO key in big-endian format !! Desde AES.cpp
// para poder directamente operaciones XOR