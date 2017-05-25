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
 *  Paracrypt is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with Paracrypt.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#pragma once

#include "AES.hpp"
#include "device/CUDACipherDevice.hpp"
#include "cipher/CUDABlockCipher.hpp"
#include "io/CudaPinned.hpp"

namespace paracrypt {

    class CudaAES: public AES, public CUDABlockCipher {
      private:
//    	unsigned int n_blocks;
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
	unsigned char* deviceIV = NULL;
	bool useConstantKey;
	bool useConstantTables;

	bool inPlace;
	unsigned char *data = NULL;
	unsigned char *neighborsDev = NULL;
	unsigned char *neighborsPin = NULL;
	CudaPinned* pin;
	unsigned int nNeighbors;
	unsigned int cipherBlocksPerThreadBlock;
	unsigned int neighSize;

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
	bool enInstantiatedButInOtherDevice;
	bool deInstantiatedButInOtherDevice;
	int stream;

	void transferNeighborsToGPU(
			const unsigned char blocks[],
			std::streamsize n_blocks);

    protected:
	// Each level-of-parallelism version will implement these methods
	virtual int getThreadsPerCipherBlock() = 0;
	virtual std::string getImplementationName() = 0;

	typedef void(*ef)(
			  paracrypt::BlockCipher::Mode, // m
			  int, //gridSize
			  int, //threadsPerBlock
			  cudaStream_t, //stream
			  unsigned int, //n_blocks
			  uint32_t, //offset
			  unsigned char*, //in[]
			  unsigned char*, //out[]
			  unsigned char*, //neigh[]
			  unsigned char*, //iv[]
			  uint32_t*, //expanded_key
			  int, //key_bits
			  uint32_t*, //deviceTe0
			  uint32_t*, //deviceTe1
			  uint32_t*, //deviceTe2
			  uint32_t* //deviceTe3
	);
	typedef void(*df)(
			  paracrypt::BlockCipher::Mode, // m
			  int, //gridSize
			  int, //threadsPerBlock
			  cudaStream_t, //stream
			  unsigned int, //n_blocks
			  unsigned int, //offset
			  unsigned char*, //in[]
			  unsigned char*, //out[]
			  unsigned char*, //neigh[]
			  unsigned char*, //iv[]
			  uint32_t*, //expanded_key
			  int, //key_bits
			  uint32_t*, //deviceTd0
			  uint32_t*, //deviceTd1
			  uint32_t*, //deviceTd2
			  uint32_t*, //deviceTd3
			  uint8_t* //deviceTd4
	);

	virtual ef getEncryptFunction() = 0;
	virtual df getDecryptFunction() = 0;

      public:
	CudaAES();
	CudaAES(CudaAES* aes); // Shallow copy constructor
	virtual ~CudaAES();


	int encrypt(const unsigned char in[], // async
			    const unsigned char out[], std::streamsize n_blocks);
	int decrypt(const unsigned char in[], // async
			    const unsigned char out[], std::streamsize n_blocks);

	void waitFinish();
	bool checkFinish();

	void setDevice(CUDACipherDevice * device);
	void malloc(unsigned int n_blocks, bool isInplace = true);
	// returns -1 if an error has occurred
	CUDACipherDevice *getDevice();
	void constantKey(bool val);
	void constantTables(bool val);
	bool constantKey();
	bool constantTables();
	int setBlockSize(int bits);
	unsigned int getBlockSize();
	int setKey(const unsigned char key[], int bits);
	void setIV(const unsigned char iv[], int bits);
	unsigned char* getIV();
	bool isInplace();
	void setMode(Mode m);

	void initDeviceEKey();
	void initDeviceDKey();
	void initDeviceTe();
	void initDeviceTd();

//	int setOtherDeviceEncryptionKey(AES_KEY * expandedKey);
//	int setOtherDeviceDecryptionKey(AES_KEY * expandedKey);

    };

}
