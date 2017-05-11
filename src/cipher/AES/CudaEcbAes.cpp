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

int paracrypt::CudaEcbAES::encrypt(const unsigned char in[],
				      const unsigned char out[],
				      int n_blocks)
{
	int threadsPerCipherBlock = this->getThreadsPerCipherBlock();
    int gridSize = this->getDevice()->getGridSize(n_blocks, threadsPerCipherBlock);
    int threadsPerBlock = this->getDevice()->getThreadsPerThreadBlock();
    int dataSize = n_blocks * AES_BLOCK_SIZE_B;
    uint32_t *key = this->getDeviceEKey();
    assert(key != NULL);
    int rounds = this->getEncryptionExpandedKey()->rounds;

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
				      int n_blocks)
{
	int threadsPerCipherBlock = this->getThreadsPerCipherBlock();
    int gridSize = this->getDevice()->getGridSize(n_blocks, threadsPerCipherBlock);
    int threadsPerBlock = this->getDevice()->getThreadsPerThreadBlock();
    int dataSize = n_blocks * AES_BLOCK_SIZE_B;
    uint32_t *key = this->getDeviceDKey();
    assert(key != NULL);
    int rounds = this->getDecryptionExpandedKey()->rounds;

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
