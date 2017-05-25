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

#include "cipher/BlockCipher.hpp"
#include <stdint.h>

void cuda_aes_4b_ptr_encrypt(
			  paracrypt::BlockCipher::Mode m,
			  int gridSize,
			  int threadsPerBlock,
			  cudaStream_t stream,
			  unsigned int n_blocks,
			  unsigned int offset,
			  unsigned char* in,
			  unsigned char* out,
			  unsigned char* neigh,
			  unsigned char* iv,
			  uint32_t* expanded_key,
			  int key_bits,
			  uint32_t* deviceTe0,
			  uint32_t* deviceTe1,
			  uint32_t* deviceTe2,
			  uint32_t* deviceTe3
	      );

void cuda_aes_4b_ptr_decrypt(
			  paracrypt::BlockCipher::Mode m,
			  int gridSize,
			  int threadsPerBlock,
			  cudaStream_t stream,
			  unsigned int n_blocks,
			  unsigned int offset,
			  unsigned char* in,
			  unsigned char* out,
			  unsigned char* neigh,
			  unsigned char* iv,
			  uint32_t* expanded_key,
			  int key_bits,
			  uint32_t* deviceTd0,
			  uint32_t* deviceTd1,
			  uint32_t* deviceTd2,
			  uint32_t* deviceTd3,
			  uint8_t* deviceTd4
	      );
