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

#include "CudaEcbAes.hpp"
#include "assert.h"
#include "logging.hpp" // TODO TOREMOVE

paracrypt::CudaEcbAES::CudaEcbAES()
{}

paracrypt::CudaEcbAES::CudaEcbAES(CudaEcbAES* aes) : CudaAES(aes)
{}

paracrypt::CudaEcbAES::~CudaEcbAES()
{}

int paracrypt::CudaEcbAES::encrypt(const unsigned char in[],
				      const unsigned char out[],
				      std::streamsize n_blocks)
{
	int threadsPerCipherBlock = this->getThreadsPerCipherBlock();
    int gridSize = this->getDevice()->getGridSize(n_blocks, threadsPerCipherBlock);
    int threadsPerBlock = this->getDevice()->getThreadsPerThreadBlock();
    int dataSize = n_blocks * AES_BLOCK_SIZE_B;
    uint32_t *key = this->getDeviceEKey();
    assert(key != NULL);
    int rounds = this->getEncryptionExpandedKey()->rounds;

    // TODO TOREMOVE
//    if(rounds == 128 && in[0] != 0x32)  {
//    			hexdump("wrong input", in, 16*n_blocks);
//    }
//    if(rounds == 192 && in[1] != 0x11)  {
//        	hexdump("wrong input", in, 16*n_blocks);
//    }
//    if(rounds == 256 && in[1] != 0x11)  {
//    	hexdump("wrong input", in, 16*n_blocks);
//    }
//    LOG_TRACE(boost::format("encryption key: %x") % key);
//    LOG_TRACE(boost::format("encryption data ptr: %x") % (int*) in);
//    LOG_TRACE(boost::format("encryption data size: %i") % dataSize);
//    LOG_TRACE(boost::format("encryption Te0: %x") % this->getDeviceTe0());
//    LOG_TRACE(boost::format("encryption Te1: %x") % this->getDeviceTe1());
//    LOG_TRACE(boost::format("encryption Te2: %x") % this->getDeviceTe2());
//    LOG_TRACE(boost::format("encryption Te3: %x") % this->getDeviceTe3());

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
					this->getDeviceTe3()
			);
    this->getDevice()->memcpyFrom(this->data, (void *) out, dataSize,
				  this->stream);
    return 0;
}

int paracrypt::CudaEcbAES::decrypt(const unsigned char in[],
				      const unsigned char out[],
				      std::streamsize n_blocks)
{
	int threadsPerCipherBlock = this->getThreadsPerCipherBlock();
    int gridSize = this->getDevice()->getGridSize(n_blocks, threadsPerCipherBlock);
    int threadsPerBlock = this->getDevice()->getThreadsPerThreadBlock();
    int dataSize = n_blocks * AES_BLOCK_SIZE_B;
    uint32_t *key = this->getDeviceDKey();
    assert(key != NULL);
    int rounds = this->getDecryptionExpandedKey()->rounds;

    // TODO TOREMOVE
//    if(rounds == 128 && in[0] != 0x39)  {
//    			hexdump("wrong input", in, 16*n_blocks);
//    }
//    if(rounds == 192 && in[1] != 0xa9)  {
//        	hexdump("wrong input", in, 16*n_blocks);
//    }
//    if(rounds == 256 && in[1] != 0xa2)  {
//    	hexdump("wrong input", in, 16*n_blocks);
//    }
//    LOG_TRACE(boost::format("decryption key: %x") % key);
//    LOG_TRACE(boost::format("decryption data ptr: %x") % (int*) in);
//    LOG_TRACE(boost::format("decryption data size: %i") % dataSize);
//    LOG_TRACE(boost::format("decryption Td0: %x") % this->getDeviceTd0());
//    LOG_TRACE(boost::format("decryption Td1: %x") % this->getDeviceTd1());
//    LOG_TRACE(boost::format("decryption Td2: %x") % this->getDeviceTd2());
//    LOG_TRACE(boost::format("decryption Td3: %x") % this->getDeviceTd3());
//    LOG_TRACE(boost::format("decryption Td4: %x") % (int*) this->getDeviceTd4());

    this->getDevice()->memcpyTo((void *) in, this->data, dataSize,
				this->stream);
	this->cuda_ecb_aes_decrypt
			(
					gridSize,
					threadsPerBlock,
					this->data,
					n_blocks,
					key,
					rounds,
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
// TODO -> Posiblemente esta clase se pueda incluir dentro de CudaAES <- y la subclases son los modos de op.

// TODO key in big-endian format !! Desde AES.cpp
// para poder directamente operaciones XOR
