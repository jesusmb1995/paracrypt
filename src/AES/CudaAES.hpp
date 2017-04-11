#pragma once

#include "AES.hpp"
#include "../device/CUDACipherDevice.hpp"

namespace paracrypt {

    class CudaAES:public AES {
      private:
	CUDACipherDevice * device;
	uint32_t* deviceKey = NULL;
	uint32_t* deviceTe0 = NULL;
	uint32_t* deviceTe1 = NULL;
	uint32_t* deviceTe2 = NULL;
	uint32_t* deviceTe3 = NULL;
	uint32_t* deviceTd0 = NULL;
	uint32_t* deviceTd1 = NULL;
	uint32_t* deviceTd2 = NULL;
	uint32_t* deviceTd3 = NULL;
	uint8_t* deviceTd4 = NULL;
      protected:
	unsigned char *data = NULL;
	uint32_t* getDeviceKey();
	uint32_t* getDeviceTe0();
	uint32_t* getDeviceTe1();
	uint32_t* getDeviceTe2();
	uint32_t* getDeviceTe3();
	uint32_t* getDeviceTd0();
	uint32_t* getDeviceTd1();
	uint32_t* getDeviceTd2();
	uint32_t* getDeviceTd3();
	uint8_t* getDeviceTd4();

	int stream;
      public:
	~CudaAES();
	virtual int encrypt(const unsigned char in[],
			    const unsigned char out[], int n_blocks) = 0;
	virtual int decrypt(const unsigned char in[],
			    const unsigned char out[], int n_blocks) = 0;
	void setDevice(CUDACipherDevice * device);
	void malloc(int n_blocks);	// Must be called to reserve enough space before encrypt/decrypt
	// returns -1 if an error has occurred
	CUDACipherDevice *getDevice();
    };

}