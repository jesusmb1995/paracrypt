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

#include "GPUCipherDevice.hpp"
#include "cuda.h"
#include "cuda_runtime_api.h"

namespace paracrypt {

	void HandleError(cudaError_t err,const char *file, int line);
	#ifdef DEBUG
	#define HANDLE_ERROR( err ) (HandleError( err, __FILE__, __LINE__ ))
	#define HANDLE_ERROR_NUMBER( err ) (HandleError( err, __FILE__, __LINE__ ))
	#else
	#define HANDLE_ERROR( err ) (err)
	#define HANDLE_ERROR_NUMBER( err )
	#endif

    class CUDACipherDevice:public GPUCipherDevice < cudaStream_t,
	cudaStreamCallback_t > {
      private:
    void printDeviceInfo();
	int device;
	cudaDeviceProp devProp;
    boost::unordered_map<int,cudaEvent_t> cpyFromEvents;
    boost::unordered_map<int,cudaStreamCallback_t> cpyFromCallbacks;
      public:
	// 0 <= device < cudaGetDeviceCount()
	 CUDACipherDevice(int device);
	const cudaDeviceProp *getDeviceProperties();
	void set();
	void malloc(void **data, int size);
	void free(void *data);
	void memcpyTo(void *host, void *dev, int size, int stream_id);
	void memcpyFrom(void *dev, void *host, int size, int stream_id);
	void waitMemcpyFrom(int stream_id);
	int checkMemcpyFrom(int stream_id);
	void setMemCpyFromCallback(int stream_id,
				   cudaStreamCallback_t func);
	int addStream();	// thread-safe
	void delStream(int stream_id);	// thread-safe
    };
}
