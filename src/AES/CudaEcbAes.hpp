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
#include "CudaAES.hpp"

namespace paracrypt {

    class CudaEcbAES:public CudaAES {
    public:
    	CudaEcbAES() {};
    	~CudaEcbAES() {};
    protected:
  virtual int getThreadsPerCipherBlock() = 0;
  virtual int cuda_ecb_aes_encrypt(
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
  		) = 0;
  virtual int cuda_ecb_aes_decrypt(
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
  		) = 0;
    public:
	int encrypt(const unsigned char in[],
		    const unsigned char out[], int n_blocks);
	int decrypt(const unsigned char in[],
		    const unsigned char out[], int n_blocks);
    };

}
