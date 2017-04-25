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

#include "CudaEcbAes.hpp"

namespace paracrypt {

    class CudaEcbAES16BPtr:public CudaEcbAES {
    protected:
  int getThreadsPerCipherBlock();
  int cuda_ecb_aes_encrypt(
  		int gridSize,
  		int threadsPerBlock,
  		unsigned char * data,
  		int n_blocks,
  		uint32_t* key,
  		int rounds,
  		uint32_t* deviceTe0,
  		uint32_t* deviceTe1,
  		uint32_t* deviceTe2,
  		uint32_t* deviceTe3
  		);
  int cuda_ecb_aes_decrypt(
  		int gridSize,
  		int threadsPerBlock,
  		unsigned char * data,
  		int n_blocks,
  		uint32_t* key,
  		int rounds,
  		uint32_t* deviceTd0,
  		uint32_t* deviceTd1,
  		uint32_t* deviceTd2,
  		uint32_t* deviceTd3,
  		uint8_t* deviceTd4
  		);
    };

}
