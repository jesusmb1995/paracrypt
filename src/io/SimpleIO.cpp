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

#include "SimpleIO.hpp"
#include "logging.hpp"

paracrypt::SimpleIO::SimpleIO(
		std::string inFilename,
		std::string outFilename,
		unsigned int blockSize,
		std::streampos begin,
		std::streampos end
		)
: paracrypt::BlockIO::BlockIO(inFilename, outFilename, blockSize, begin, end)
{
//	this->buffer = NULL;
//	this->bufferSize = 0;
}

paracrypt::SimpleIO::~SimpleIO() {}

void paracrypt::SimpleIO::construct(rlim_t bufferSizeLimit) {
    // allocate buffer chunks
    rlim_t buffersTotalSize = this->getPinned()->getReasonablyBigChunkOfRam(bufferSizeLimit);
    bool allocSuccess = false;
    std::streamsize bufferSizeBytes;
    do {
    	this->bufferSize = buffersTotalSize / this->getBlockSize();
		if(this->bufferSize == 0) {
			// exit with error
			ERR("Couldn't allocate SharedIO internal buffer.\n");
		}
    	// bufferSize aligned to chunk size
        bufferSizeBytes = this->getBufferSize()*this->getBlockSize();
    	allocSuccess = this->getPinned()->alloc((void**) &buffer.data,bufferSizeBytes);
    	if(!allocSuccess) {
    		if(this->bufferSize != 0) {
    			LOG_WAR(boost::format("Coudn't allocate %llu bytes for SharedIO internal buffer."
    					" Trying with a smaller buffer...\n") % bufferSizeBytes);
    		}
    		buffersTotalSize -= this->getBlockSize();
    	}
    }
    while(!allocSuccess);

    LOG_INF(boost::format(
    		"A new SharedIO object uses %llu bytes"
    		" (%u blocks of %u bytes) "
    		" of pinned memory for its internal buffer."
    		"\n")
    % bufferSizeBytes
    % this->getBufferSize()
    % this->getBlockSize()
    );
}
void paracrypt::SimpleIO::destruct() {
	this->getPinned()->free((void*)this->buffer.data);
}

const std::streamsize paracrypt::SimpleIO::getBufferSize() {
	return this->bufferSize;
}

paracrypt::BlockIO::chunk paracrypt::SimpleIO::read()
{
	this->buffer.nBlocks = this->inFileRead(this->buffer.data,this->getBufferSize(),&this->buffer.status,&this->buffer.blockOffset);
	return this->buffer;
}
void paracrypt::SimpleIO::dump(chunk c)
{
	this->outFileWrite(
			c.data,
			c.nBlocks,
			c.blockOffset);
}
