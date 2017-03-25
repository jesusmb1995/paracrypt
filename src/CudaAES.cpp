#include "CudaAES.hpp"
#include "CUDACipherDevice.hpp"

paracrypt::CudaAES::~CudaAES()
{
	if (this->deviceKey != NULL) {
		this->getDevice()->free(this->deviceKey);
	}
	if (this->deviceKey != NULL) {
		this->getDevice()->free(this->data);
	}
	if (this->deviceKey != NULL) {
		 this->getDevice()->free(this->stream);
	}
}

// must be called after setKey
void paracrypt::CudaAES::setDevice(CUDACipherDevice* device)
{
	if (this->deviceKey != NULL) {
		this->getDevice()->free(this->deviceKey);
	}
	if (this->deviceKey != NULL) {
		this->getDevice()->free(this->data);
	}
	if (this->deviceKey != NULL) {
		 this->getDevice()->free(this->stream);
	}
    this->device = device;
    this->stream = this->getDevice()->getNewStream();
    // copy round keys to device
    int keySize = (4 * (this->roundKeys->rounds + 1)) * sizeof(uint32_t);
    this->getDevice()->malloc((void **) &(this->deviceKey),keySize);
    this->getDevice()->memcpyTo(this->roundKeys->rd_key, &(this->deviceKey),keySize,this->stream);
}

CUDACipherDevice* paracrypt::CudaAES::getDevice() {
	       return this->device;
}

void paracrypt::CudaAES::malloc(int n_blocks) {
	       int dataSize = AES_BLOCK_SIZE * n_blocks;
	       this->getDevice()->malloc((void **) &(this->data), dataSize);
}
