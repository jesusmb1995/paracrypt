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

#ifndef LAUNCHER_HPP_
#define LAUNCHER_HPP_

#include "device/CUDACipherDevice.hpp"
#include "cipher/CUDABlockCipher.hpp"
#include "io/SimpleIO.hpp"
#include "io/SharedIO.hpp"

namespace paracrypt {

//template < class Device, class Cipher, class IO >
class Launcher {
public:
	Launcher(){};
	virtual ~Launcher();

	typedef enum {
		ENCRYPT = 0,
		DECRYPT = 1,
	} operation_t;

	template < class CudaAES_t >
	static void launchSharedIOCudaAES(
			operation_t op,
			std::string inFileName,
			std::string outFileName,
			const unsigned char key[],
			int key_bits,
			bool constantKey,
			bool constantTables,
			paracrypt::BlockCipher::Mode m,
			const unsigned char iv[],
			int ivBits,
			bool outOfOrder,
			std::streampos begin = NO_RANDOM_ACCESS,
			std::streampos end = NO_RANDOM_ACCESS
	);

	static void limitStagging(rlim_t limit);

//
//	static void encrypt(
//			std::string inFilename,
//			std::string outFilename,
//			Cipher cipher,
//			CUDACipherDevce devices[],
//			SharedIO io);

//	static void decrypt(
//			 std::string inFilename,
//			 std::string outFilename,
//			 Cipher cipher,
//			 Device devices[],
//			 IO io);

	// TODO OpenCL implementations
//
//	static void encrypt(
//			 std::string inFilename,
//			 std::string outFilename,
//			 CLBlockCipher cipher,
//			 CLCipherDevice devices[],
//			 SimpleIO io);
//
//	static void encrypt(
//			 std::string inFilename,
//			 std::string outFilename,
//			 CLBlockCipher cipher,
//			 CLCipherDevice devices[],
//			 SharedIO io);


	// TODO Hybrid CPU-GPU implementations
private:
	static rlim_t staggingLimit;
	// IMPORTANT: Returned CudaAES objects have to be freed
	//  CudaAES_t is a cipher class which has CudaAES as a base.
	template < class CudaAES_t >
	static CudaAES_t** linkAES(
			operation_t op,
			CUDACipherDevice* devices[],
			unsigned int n,
			const unsigned char key[],
			int keyBits,
			bool constantKey,
			bool constantTables,
			paracrypt::BlockCipher::Mode m,
			const unsigned char iv[],
			int ivBits,
			unsigned int *nCiphers);

	template < class Cipher >
	static void freeCiphers(Cipher* ciphers[], unsigned int n);

	// IMPORTANT: SharedIO object has to be freed by the caller
	static SharedIO* newAdjustedSharedIO(
			std::string inFilename,
			std::string outFilename,
			unsigned int blockSize,
			CUDACipherDevice* devices[],
			int n,
			std::streampos begin = NO_RANDOM_ACCESS,
			std::streampos end = NO_RANDOM_ACCESS
	);

	static void operation(
			 operation_t op,
			 CUDABlockCipher* ciphers[],
			 unsigned int n,
			 SharedIO* io,
			 bool outOfOrder
	 );

	inline static void operation(
		operation_t op,
		CUDABlockCipher* cipher,
		paracrypt::BlockIO::chunk c,
		unsigned char* iv
	){
		cipher->setInitialBlockOffset(c.blockOffset);
		switch(op) {
			case paracrypt::Launcher::ENCRYPT:
				cipher->encrypt(c.data,c.data,c.nBlocks);
				break;
			case paracrypt::Launcher::DECRYPT:
				cipher->decrypt(c.data,c.data,c.nBlocks);
				break;
			default:
				ERR("Unknown cipher operation.");
		}
	}

	inline static bool isIVLinkable(CUDABlockCipher* cipher) {
		return
			cipher->getMode() == paracrypt::BlockCipher::CBC ||
			cipher->getMode() == paracrypt::BlockCipher::CFB;
	}

	inline static void cpyLastBlock(
			unsigned char* dest,
			paracrypt::BlockIO::chunk c,
			const unsigned int blockSizeBytes
	){
		std::streamoff lastBlockByteOffset = (c.nBlocks-1)*blockSizeBytes;
#ifdef DEVEL
			if(c.nBlocks <= 66) {
				std::stringstream stream;
				stream << boost::format("copying %ui bytes block from offset %llu (block offset: %llu) of this data to %x ")
				 % blockSizeBytes % lastBlockByteOffset % (c.nBlocks-1) % (void*) dest;
				hexdump(stream.str(), c.data,c.nBlocks*16);
			}
#endif
		assert(lastBlockByteOffset >= 0);
		std::memcpy(dest,c.data+lastBlockByteOffset,blockSizeBytes);
	}

	inline static bool finished(CUDABlockCipher* cipher, bool outOfOrder)
	{
		bool finished;
		if(outOfOrder) {
			finished = cipher->checkFinish();
		} else {
			cipher->waitFinish();
			finished = true;
		}
		return finished;
	}
};

} /* namespace paracrypt */

#include "Launcher.tpp"

#endif /* LAUNCHER_HPP_ */
