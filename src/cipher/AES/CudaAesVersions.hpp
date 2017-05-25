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

#include "cipher/AES/CudaAES.hpp"
#include "cipher/AES/CudaAes16B.cuh"
#include "cipher/AES/CudaAes16BPtr.cuh"
#include "cipher/AES/CudaAes8B.cuh"
#include "cipher/AES/CudaAes8BPtr.cuh"
#include "cipher/AES/CudaAes4B.cuh"
#include "cipher/AES/CudaAes4BPtr.cuh"
#include "cipher/AES/CudaAes1B.cuh"

namespace paracrypt {

#define VERSION(className) \
    class className:public CudaAES { \
    public: \
    	className(); \
    	className(className* aes); \
    	~className(); \
    protected: \
    	int getThreadsPerCipherBlock(); \
    	std::string getImplementationName(); \
    	CudaAES::ef getEncryptFunction(); \
    	CudaAES::df getDecryptFunction(); \
    }; \

VERSION(CudaAES16B);
VERSION(CudaAES16BPtr);
VERSION(CudaAES8B);
VERSION(CudaAES8BPtr);
VERSION(CudaAES4B);
VERSION(CudaAES4BPtr);
VERSION(CudaAES1B);

}
