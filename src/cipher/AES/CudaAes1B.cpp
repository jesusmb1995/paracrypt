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

#include "CudaAes1B.hpp"
#include "CudaAes1B.cuh"

paracrypt::CudaAES1B::CudaAES1B()
{}

paracrypt::CudaAES1B::CudaAES1B(CudaAES1B* aes) : CudaAES(aes)
{}

paracrypt::CudaAES1B::~CudaAES1B()
{}

int paracrypt::CudaAES1B::getThreadsPerCipherBlock() {
	return 16;
}

int paracrypt::CudaAES1B::cuda_aes_encrypt(
   		int gridSize,
   		int threadsPerBlock,
   		unsigned int n_blocks,
   		uint32_t* key,
   		int rounds,
   		uint32_t* deviceTd0,
   		uint32_t* deviceTd1,
   		uint32_t* deviceTd2,
   		uint32_t* deviceTd3,
   		uint8_t* deviceTd4
   		){
	int key_bits = 0;
	switch(rounds) {
	case 10:
		key_bits = 128;
		break;
	case 12:
		key_bits = 192;
		break;
	case 14:
		key_bits = 256;
		break;
	default:
		return -1;
	}
	DEV_TRACE(boost::format("cuda_ecb_aes_1b_encrypt("
			"gridSize=%d"
			", threadsPerBlock=%d"
			", data=%x"
			", n_blocks=%d"
			", expanded_key=%x"
			", rounds=%d)")
		% gridSize
		% threadsPerBlock
		% (void*) (this->data)
		% n_blocks
		% key
		% rounds);
	cuda_ecb_aes_1b_encrypt(
			gridSize,
			threadsPerBlock,
			this->getDevice()->acessStream(this->stream),
			n_blocks,
			this->data,
			key,
			key_bits,
	   		deviceTe0,
	   		deviceTe1,
	   		deviceTe2,
	   		deviceTe3
	);
	return 0;
}

int paracrypt::CudaAES1B::cuda_ecb_aes_decrypt(
   		int gridSize,
   		int threadsPerBlock,
   		unsigned int n_blocks,
   		uint32_t* key,
   		int rounds,
   		uint32_t* deviceTd0,
   		uint32_t* deviceTd1,
   		uint32_t* deviceTd2,
   		uint32_t* deviceTd3,
   		uint8_t* deviceTd4
    	){
	int key_bits = 0;
	switch(rounds) {
	case 10:
		key_bits = 128;
		break;
	case 12:
		key_bits = 192;
		break;
	case 14:
		key_bits = 256;
		break;
	default:
		return -1;
	}
	DEV_TRACE(boost::format("cuda_ecb_aes_1b_decrypt("
			"gridSize=%d"
			", threadsPerBlock=%d"
			", data=%x"
			", n_blocks=%d"
			", expanded_key=%x"
			", rounds=%d)")
		% gridSize
		% threadsPerBlock
		% (void*) (this->data)
		% n_blocks
		% key
		% rounds);
	cuda_ecb_aes_1b_decrypt(
			gridSize,
			threadsPerBlock,
			this->getDevice()->acessStream(this->stream),
			n_blocks,
			this->data,
			key,
			key_bits,
	   		deviceTd0,
	   		deviceTd1,
	   		deviceTd2,
	   		deviceTd3,
	   		deviceTd4
	);
	return 0;
}
