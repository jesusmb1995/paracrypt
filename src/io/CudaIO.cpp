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

#include "CudaIO.hpp"
#include "../device/CUDACipherDevice.hpp"
#include <cstring>

namespace paracrypt {

CudaIO::CudaIO() {
	this->nBuffers = -1;
	this->initialized = false;
}

CudaIO::~CudaIO() {
	this->freeBuffers();
}

bool CudaIO::initializeBuffers(unsigned long *bufferSizes, int nBuffers) {
	this->freeBuffers();
	this->nBuffers = nBuffers;
	this->buffers = malloc(nBuffers*sizeof(unsigned char*));
	this->bufferSizes = malloc(nBuffers*sizeof(unsigned long));
	memcpy((void*)this->bufferSizes, (void*)bufferSizes, nBuffers*sizeof(unsigned long));
	/*
	 *     TODO If we do not want to use CUDA functions we could use mlock.
	 *
	 *     mlock(), mlock2(), and mlockall() lock part or all of the calling
	 *     process's virtual address space into RAM, preventing that memory from
	 *     being paged to the swap area.
	 */
	for(int i = 0; i < nBuffers; i++) {
		cudaError_t e = cudaHostAlloc(bufferSizes[i]);
		HANDLE_PRINT_ERROR_NUMBER(e);
		if(e != cudaSuccess) {
			this->nBuffers = i+1;
			this->freeBuffers();
			return false;
		}
	}
	this->initialized = true;
	return true;
}

void CudaIO::freeBuffers() {
	if(this->initialized) {
		for(int i = 0; i < nBuffers; i++) {
			HANDLE_ERROR(cudaFreeHost(buffers[i]));
		}
		free(this->buffers);
		free(this->bufferSizes);
		this->initialized = false;
	}
}

unsigned char* CudaIO::getBuffer(int bufferId) {
	return this->buffers[bufferId];
}

unsigned long CudaIO::getBufferSize(int bufferId) {
	return this->bufferSizes[bufferId];
}

int CudaIO::getNBuffers() {
	return this->nBuffers;
}

} /* namespace paracrypt */
