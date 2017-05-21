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

#include "CudaAesVersions.hpp"
#include "cipher/AES/CudaAes16B.cuh"

#define CONSTRUCTORS(className) \
		paracrypt::className::className() {} \
		paracrypt::className::className(className* aes) : CudaAES(aes) {} \
		paracrypt::className::~className() {}

CONSTRUCTORS(CudaAES16B);

int paracrypt::CudaAES16B::getThreadsPerCipherBlock() {
	return 1;
}

std::string paracrypt::CudaAES16B::getImplementationName() {
	return std::string("cuda_ecb_aes_16b");
}

paracrypt::CudaAES::ef paracrypt::CudaAES16B::getEncryptFunction() {
	return &cuda_ecb_aes_16b_encrypt;
}

paracrypt::CudaAES::df paracrypt::CudaAES16B::getDecryptFunction() {
	return &cuda_ecb_aes_16b_decrypt;
}
