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

#include "SimpleBlockingCudaIO.hpp"
#include "../device/CUDACipherDevice.hpp"
#include <algorithm>
#include "../logging.hpp"

namespace paracrypt {

SimpleBlockingCudaIO::SimpleBlockingCudaIO(
		std::string inFilename,
		std::string outFilename,
		unsigned int blockSize,
		unsigned int nBuffers,
		unsigned int buffersWeights[] = {1},
		std::streampos buffersSizeLimit = AUTO_IO_BUFFERS_LIMIT,
		std::streampos begin = 0,
		std::streampos end = 0
) : SharedIO(inFilename, outFilename, blockSize, nBuffers, buffersWeights, buffersSizeLimit, begin, end)
{
	for(int i = 1; i < nBuffers; i++) {
		this->bufferBlocksSize = std::max(this->getBufferSize(i-1),this->getBufferSize(i));
	}
	unsigned long bytesAllocated = this->bufferBlocksSize*this->getBlockSize();
	HANDLE_ERROR(cudaMallocHost(&(this->buffer),bytesAllocated));
	LOG_INF(boost::format("SimpleBlockingCudaIO has allocated %ul bytes (%d blocks) of pinned memory for his buffer.") % bytesAllocated % this->bufferBlocksSize);
	this->currentBufferIndex = nBuffers+1;
}

SimpleBlockingCudaIO::~SimpleBlockingCudaIO() {
	HANDLE_ERROR(cudaFreeHost(this->buffer));
}

unsigned int paracrypt::SimpleBlockingCudaIO::read(unsigned int bufferIndex, char* data[], std::streampos* blockOffset, readStatus *status)
{
	this->currentBufferIndex = bufferIndex;
	unsigned int nBlocks = this->getNBuffers();
	unsigned int nBRead = this->inFileRead(this->buffer,nBlocks,blockOffset,status);
	return nBRead;
}

void paracrypt::SimpleBlockingCudaIO::dump(unsigned int bufferIndex, std::streampos blockOffset)
{
	if(bufferIndex != this->getNBuffers()+1 && bufferIndex != this->currentBufferIndex) {
		unsigned int nBlocks = this->getBufferSize(bufferIndex);
		this->outFileWrite(this->buffer,nBlocks,blockOffset);
	} else {
		LOG_WAR("Trying to dump wrong buffer. You have to read from the buffer before dumping it.");
	}
}

} /* namespace paracrypt */
