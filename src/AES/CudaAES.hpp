/*
 *  Copyright (C) 2017 Jesus Martin Berlanga. All Rights Reserved.
 *
 *  This file is part of Paracrypt.
 *
 *  Paracrypt is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  Foobar is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with Foobar.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#pragma once

#include "AES.hpp"
#include "../device/CUDACipherDevice.hpp"

namespace paracrypt {

    class CudaAES:public AES {
      private:
	CUDACipherDevice * device;
	uint32_t* deviceEKey = NULL;
	bool deviceEKeyConstant;
	uint32_t* deviceDKey = NULL;
	bool deviceDKeyConstant;
	uint32_t* deviceTe0 = NULL;
	uint32_t* deviceTe1 = NULL;
	uint32_t* deviceTe2 = NULL;
	uint32_t* deviceTe3 = NULL;
	uint32_t* deviceTd0 = NULL;
	uint32_t* deviceTd1 = NULL;
	uint32_t* deviceTd2 = NULL;
	uint32_t* deviceTd3 = NULL;
	uint8_t* deviceTd4 = NULL;
	bool useConstantKey;
	bool useConstantTables;
      protected:
    virtual int getThreadsPerCipherBlock() = 0;
	unsigned char *data = NULL;
	uint32_t* getDeviceEKey();
	uint32_t* getDeviceDKey();
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
	CudaAES();
	~CudaAES();
	virtual int encrypt(const unsigned char in[],
			    const unsigned char out[], int n_blocks) = 0;
	virtual int decrypt(const unsigned char in[],
			    const unsigned char out[], int n_blocks) = 0;
	void setDevice(CUDACipherDevice * device);
	void malloc(int n_blocks);	// Must be called to reserve enough space before encrypt/decrypt
	// returns -1 if an error has occurred
	CUDACipherDevice *getDevice();
	void constantKey(bool val);
	void constantTables(bool val);
	bool constantKey();
	bool constantTables();
    };

}
