#include "CudaAES.hpp"

paracrypt::CudaAES::~CudaAES()
{
    cudaFree(this->deviceKey);
    cudaFree(this->data);
}

// must be called after setKey
void paracrypt::CudaAES::setDevice(CUDACipherDevice* device)
{
    this->device = device;

    if (this->deviceKey != NULL) {
	cudaFree(this->deviceKey);
    }
    // copy round keys to device
    int keySize = (4 * (this->roundKeys->rounds + 1)) * sizeof(uint32_t);
    HANDLE_ERROR(cudaMalloc ((void **) &(this->deviceKey),keySize));
    HANDLE_ERROR(cudaMemcpy(this->roundKeys->rd_key, &(this->deviceKey), keySize, cudaMemcpyHostToDevice));
}

CUDACipherDevice* paracrypt::CudaAES::getDevice() {
	       return this->device;
}

paracrypt::CudaAES::malloc(int n_blocks) {
	       int dataSize = AES_BLOCK_SIZE * n_blocks;
	       HANDLE_ERROR(cudaMalloc((void **) &(this->data), dataSize));
}
