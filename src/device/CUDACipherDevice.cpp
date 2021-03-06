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

#include "CUDACipherDevice.hpp"
#include "utils/logging.hpp"
#include "io/CudaPinned.hpp"

void paracrypt::HandlePrintError(cudaError_t err,
					      const char *file, int line)
{
    if (err != cudaSuccess) {
	LOG_ERR(boost::format("%s in %s at line %d\n")
		% cudaGetErrorString(err) % file % line);
    }
}

void paracrypt::HandleError(cudaError_t err,
					      const char *file, int line)
{
    if (err != cudaSuccess) {
	LOG_ERR(boost::format("%s in %s at line %d\n")
		% cudaGetErrorString(err) % file % line);
	exit(EXIT_FAILURE);
    }
}

paracrypt::CUDACipherDevice::CUDACipherDevice(int device)
{
    this->nConcurrentKernels = 1;
    //this->memCpyFromCallback = NULL;
    this->device = device;

    cudaGetDeviceProperties(&(this->devProp), device);
    this->set();

    //TODO after profiling/performance-tests this does not seem to yield any performance benefits
    // start initializating run-time library as soon as possible - dummy (pinned) malloc
    // https://devtalk.nvidia.com/default/topic/392429/first-cudamalloc-takes-long-time-/
    // https://devtalk.nvidia.com/default/topic/394143/effects-on-performance-with-no-initialization-like-not-putting-cut_device_init-/
    // https://raw.githubusercontent.com/kashif/cuda-workshop/master/cutil/inc/cutil.h
    /*{
		CudaPinned* pin = new CudaPinned();
		void* dummy;
		pin->alloc(&dummy, 1);
		pin->free(dummy);
		delete pin;
    }*/

    // There is no CUDA API function for retrieving blocks per SM.
    // Manually set as described to fit CUDA documentation at table
    // 13 (Maximum number of resident blocks per multiprocessor):
    //  http://docs.nvidia.com/cuda/cuda-c-programming-guide/index.html#features-and-technical-specifications
    //
    int M = this->devProp.major;
    int m = this->devProp.minor;
    if (M <= 2) {
	this->maxBlocksPerSM = 8;
    } else if (M <= 3 && m <= 7) {
	this->maxBlocksPerSM = 16;
    } else {			// cuda capability 5.0
	this->maxBlocksPerSM = 32;
    }

    this->nWarpsPerBlock =
	this->devProp.maxThreadsPerBlock / this->devProp.warpSize;
    this->nThreadsPerThreadBlock =
	this->devProp.warpSize * this->nWarpsPerBlock /
	this->maxBlocksPerSM;

    if (this->devProp.concurrentKernels) {
	// From Table 13. Technical Specifications per Compute Capability
	// Maximum number of resident grids per device (Concurrent Kernel Execution)
	if (M <= 3) {
	    this->nConcurrentKernels = 16;
	} else if (M == 3 && m == 2) {
	    this->nConcurrentKernels = 4;
	} else if (M <= 5 && m <= 2) {
	    this->nConcurrentKernels = 32;
	} else if (M == 5 && m == 3) {
	    this->nConcurrentKernels = 16;
	} else if (M == 6 && m == 0) {
	    this->nConcurrentKernels = 128;
	} else if (M == 6 && m == 1) {
	    this->nConcurrentKernels = 32;
	} else {		//if (M == 6 && m == 2) {
	    this->nConcurrentKernels = 16;
	}
    }

    this->printDeviceInfo();
}

void paracrypt::CUDACipherDevice::printDeviceInfo()
{
	LOG_INF(boost::format(
			"\nCUDA device %d:\n"
			"\t blocks per SM: %d\n"
			"\t warp size: %d\n"
			"\t warps per block: %d\n"
			"\t max. threads per block: %d\n"
			"\t threads per block: %d\n"
			"\t concurrent kernels: %d\n"
		)
		% this->device
		% this->maxBlocksPerSM
		% this->devProp.warpSize
		% this->nWarpsPerBlock
		% this->devProp.maxThreadsPerBlock
		% this->nThreadsPerThreadBlock
		% this->nConcurrentKernels
	);
}

const cudaDeviceProp *paracrypt::CUDACipherDevice::getDeviceProperties()
{
    return &(this->devProp);
}

void paracrypt::CUDACipherDevice::set()
{
    HANDLE_ERROR(cudaSetDevice(this->device));
}

void paracrypt::CUDACipherDevice::malloc(void **data, std::streamsize size)
{
	LOG_DEBUG(boost::format("cudaMalloc(%llu bytes)") % size);
    HANDLE_ERROR(cudaMalloc(data, size));
}

void paracrypt::CUDACipherDevice::free(void *data)
{
    HANDLE_ERROR(cudaFree(data));
}


// copyTo in the default stream
void paracrypt::CUDACipherDevice::memcpyTo(void *host, void *dev, size_t size) {
	HANDLE_ERROR(cudaMemcpyAsync(dev, host, size, cudaMemcpyHostToDevice));
}

void paracrypt::CUDACipherDevice::memcpyTo(void *host, void *dev, size_t size,
					   int stream_id)
{
    cudaStream_t stream = this->acessStream(stream_id);
//    LOG_TRACE(boost::format("CUDACipherDevice(%d).cudaMemcpyAsync("
//    		"dev=%x"
//    		",host=%x"
//    		",size=%d"
//    		",cudaMemcpyHostToDevice,"
//    		"stream=%x)")
//    	% this->device
//    	% host
//    	% dev
//    	% size
//    	% (void*) stream
//    );
    HANDLE_ERROR(cudaMemcpyAsync(dev, host, size, cudaMemcpyHostToDevice, stream));
}

void paracrypt::CUDACipherDevice::memcpyFrom(void *dev, void *host,
		size_t size, int stream_id)
{
    cudaStream_t stream = this->acessStream(stream_id);
    HANDLE_ERROR(cudaMemcpyAsync(host, dev, size, cudaMemcpyDeviceToHost, stream));
//    boost::shared_lock < boost::shared_mutex > lock(this->streams_access);
    HANDLE_ERROR(cudaEventRecord(this->cpyFromEvents[stream_id],stream));
//    HANDLE_ERROR(cudaEventRecord(this->globalCpyFromEvent));

//    boost::unordered_map<int,cudaStreamCallback_t>::const_iterator cb = this->cpyFromCallbacks.find(stream_id);
//    if(cb != this->cpyFromCallbacks.end()) {
//          HANDLE_ERROR(cudaStreamAddCallback(stream,cb->second,host,0));
//    }
}

//void paracrypt::CUDACipherDevice::setMemCpyFromCallback(int stream_id,
//							cudaStreamCallback_t
//							func)
//{
////    boost::unique_lock< boost::shared_mutex > lock(this->streams_access);
//    this->cpyFromCallbacks[stream_id] = func;
//}

namespace paracrypt {
    template <>
	cudaStream_t paracrypt::GPUCipherDevice < cudaStream_t,
	cudaStreamCallback_t >::newStream() {
	cudaStream_t s;
	HANDLE_ERROR(cudaStreamCreate(&s));
	return s;
    } template <>
	void paracrypt::GPUCipherDevice < cudaStream_t,
	cudaStreamCallback_t >::freeStream(cudaStream_t s) {
	HANDLE_ERROR(cudaStreamDestroy(s));
    }
}

int paracrypt::CUDACipherDevice::addStream()
{
	this->set();
    int id = paracrypt::GPUCipherDevice<cudaStream_t,cudaStreamCallback_t>::addStream();

//    boost::unique_lock< boost::shared_mutex > lock(this->streams_access);
    cudaEvent_t ev;
    HANDLE_ERROR(cudaEventCreate(&ev));
    this->cpyFromEvents[id] = ev;

    return id;
}

void paracrypt::CUDACipherDevice::delStream(int stream_id)
{
	this->set();
    paracrypt::GPUCipherDevice<cudaStream_t,cudaStreamCallback_t>::delStream(stream_id);
//    boost::unique_lock< boost::shared_mutex > lock(this->streams_access);
    HANDLE_ERROR(cudaEventDestroy(this->cpyFromEvents[stream_id]));
    this->cpyFromEvents.erase(stream_id);
}

void paracrypt::CUDACipherDevice::waitMemcpyFrom(int stream_id)
{
	this->set();
    cudaEvent_t event = this->cpyFromEvents[stream_id];
    HANDLE_ERROR(cudaEventSynchronize(event));
}

int paracrypt::CUDACipherDevice::checkMemcpyFrom(int stream_id)
{
    cudaEvent_t event = this->cpyFromEvents[stream_id];
    cudaError_t status = cudaEventQuery(event);
      if(status == cudaSuccess)
              return true;
      else if(status == cudaErrorNotReady)
              return false;
      else {
    	  	  HANDLE_ERROR_NUMBER(status);
              return status;
      }
}

//void paracrypt::CUDACipherDevice::waitMemcpyFrom()
//{
//	HANDLE_ERROR(cudaEventSynchronize(this->anyCpyFromEvent));
//}
//
//void paracrypt::CUDACipherDevice::genGlobalMemcpyFromEvent()
//{
//	HANDLE_ERROR(cudaEventCreate(&this->globalCpyFromEvent));
//}
//
//void paracrypt::CUDACipherDevice::setGlobalMemcpyFromEvent(cudaEvent_t e)
//{
//	this->globalCpyFromEvent = e;
//}
//
//cudaEvent_t paracrypt::CUDACipherDevice::getGlobalMemcpyFromEvent(cudaEvent_t e)
//{
//	return this->globalCpyFromEvent;
//}

int paracrypt::CUDACipherDevice::getDevicesCount()
{
	int nDevices;
	HANDLE_ERROR(cudaGetDeviceCount(&nDevices));
	return nDevices;
}

paracrypt::CUDACipherDevice** paracrypt::CUDACipherDevice::instantiateAllDevices()
{
	int count = paracrypt::CUDACipherDevice::getDevicesCount();
	paracrypt::CUDACipherDevice** devices = new paracrypt::CUDACipherDevice*[count];
	for(int d = 0; d < count; d++) {
		devices[d] = new paracrypt::CUDACipherDevice(d);
	}
	return devices;
}

void paracrypt::CUDACipherDevice::freeAllDevices(CUDACipherDevice** devices)
{
	int count = paracrypt::CUDACipherDevice::getDevicesCount();
	for(int d = 0; d < count; d++) {
		delete devices[d];
	}
	delete[] devices;
}


