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

#define CONSTRUCTORS(className) \
		paracrypt::className::className() {} \
		paracrypt::className::className(className* aes) : CudaAES(aes) {} \
		paracrypt::className::~className() {}

CONSTRUCTORS(CudaAES16B);
CONSTRUCTORS(CudaAES16BPtr);
CONSTRUCTORS(CudaAES8B);
CONSTRUCTORS(CudaAES8BPtr);
CONSTRUCTORS(CudaAES4B);
CONSTRUCTORS(CudaAES4BPtr);
CONSTRUCTORS(CudaAES1B);



// 16B //////////////////////////////////////////////////////////

int paracrypt::CudaAES16B::getThreadsPerCipherBlock() {
	return 1;
}

std::string paracrypt::CudaAES16B::getImplementationName() {
	return std::string("cuda_aes_16b");
}

paracrypt::CudaAES::ef paracrypt::CudaAES16B::getEncryptFunction() {
	return &cuda_aes_16b_encrypt;
}

paracrypt::CudaAES::df paracrypt::CudaAES16B::getDecryptFunction() {
	return &cuda_aes_16b_decrypt;
}



// 16B-PTR //////////////////////////////////////////////////////

int paracrypt::CudaAES16BPtr::getThreadsPerCipherBlock() {
	return 1;
}

std::string paracrypt::CudaAES16BPtr::getImplementationName() {
	return std::string("cuda_aes_16b_ptr");
}

paracrypt::CudaAES::ef paracrypt::CudaAES16BPtr::getEncryptFunction() {
	return &cuda_aes_16b_ptr_encrypt;
}

paracrypt::CudaAES::df paracrypt::CudaAES16BPtr::getDecryptFunction() {
	return &cuda_aes_16b_ptr_decrypt;
}



// 8B ///////////////////////////////////////////////////////////

int paracrypt::CudaAES8B::getThreadsPerCipherBlock() {
	return 2;
}

std::string paracrypt::CudaAES8B::getImplementationName() {
	return std::string("cuda_aes_8b");
}

paracrypt::CudaAES::ef paracrypt::CudaAES8B::getEncryptFunction() {
	return &cuda_aes_8b_encrypt;
}

paracrypt::CudaAES::df paracrypt::CudaAES8B::getDecryptFunction() {
	return &cuda_aes_8b_decrypt;
}



// 8B-PTR ///////////////////////////////////////////////////////

int paracrypt::CudaAES8BPtr::getThreadsPerCipherBlock() {
	return 2;
}

std::string paracrypt::CudaAES8BPtr::getImplementationName() {
	return std::string("cuda_aes_8b_ptr");
}

paracrypt::CudaAES::ef paracrypt::CudaAES8BPtr::getEncryptFunction() {
	return &cuda_aes_8b_ptr_encrypt;
}

paracrypt::CudaAES::df paracrypt::CudaAES8BPtr::getDecryptFunction() {
	return &cuda_aes_8b_ptr_decrypt;
}



// 4B ///////////////////////////////////////////////////////////

int paracrypt::CudaAES4B::getThreadsPerCipherBlock() {
	return 4;
}

std::string paracrypt::CudaAES4B::getImplementationName() {
	return std::string("cuda_aes_4b");
}

paracrypt::CudaAES::ef paracrypt::CudaAES4B::getEncryptFunction() {
	return &cuda_aes_4b_encrypt;
}

paracrypt::CudaAES::df paracrypt::CudaAES4B::getDecryptFunction() {
	return &cuda_aes_4b_decrypt;
}



// 4B-PTR ///////////////////////////////////////////////////////

int paracrypt::CudaAES4BPtr::getThreadsPerCipherBlock() {
	return 4;
}

std::string paracrypt::CudaAES4BPtr::getImplementationName() {
	return std::string("cuda_aes_4b_ptr");
}

paracrypt::CudaAES::ef paracrypt::CudaAES4BPtr::getEncryptFunction() {
	return &cuda_aes_4b_ptr_encrypt;
}

paracrypt::CudaAES::df paracrypt::CudaAES4BPtr::getDecryptFunction() {
	return &cuda_aes_4b_ptr_decrypt;
}



// 1B ///////////////////////////////////////////////////////////

int paracrypt::CudaAES1B::getThreadsPerCipherBlock() {
	return 16;
}

std::string paracrypt::CudaAES1B::getImplementationName() {
	return std::string("cuda_aes_1b");
}

paracrypt::CudaAES::ef paracrypt::CudaAES1B::getEncryptFunction() {
	return &cuda_aes_1b_encrypt;
}

paracrypt::CudaAES::df paracrypt::CudaAES1B::getDecryptFunction() {
	return &cuda_aes_1b_decrypt;
}
