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

#include "SharedIO.hpp"
#include "../logging.hpp"
#include <sys/resource.h>
#include <sys/sysinfo.h>
#include <algorithm>
#include <stdint.h>

paracrypt::SharedIO::SharedIO(
		std::string inFilename,
		std::string outFilename,
		unsigned int blockSize,
		unsigned int chunkSize,
		std::streampos buffersSizeLimit = AUTO_IO_BUFFERS_LIMIT,
		std::streampos begin = 0,
		std::streampos end = 0
		)
{
	this->inFile.open(inFilename);
	this->inFileReadStatus = OK;
	this->inFile.seekg(begin);
	this->outFile.open(outFilename);
	this->blockSize = blockSize;
	this->chunkSize = chunkSize;
	this->alreadyReadBlocks = 0;
	if (end > begin) {
		LOG_WARNING("Swapping begin-end random access positions.\n");
		std::swap(begin,end);
	}
	unsigned long maxBytesRead = end-begin;
	if(maxBytesRead != 0) {
		this->maxBlocksRead = maxBytesRead / blockSize;
		int halfBlock = maxBytesRead % blockSize;
		if(halfBlock != 0) {
			this->maxBlocksRead++;
			LOG_WAR(boost::format(
					"Aligning random access section to block size: "
					" Using %d bytes instead of %d bytes.\n")
				% this->maxBlocksRead * blockSize
				% maxBytesRead
			);
		}
	}

//	this->nBuffers = nBuffers;
//    this->bufferSizes = new unsigned int[nBuffers]();

    // calculate amount of available memory for buffers
#define BUFFERS_RAM_USAGE_FACTOR 0.67 // we do not want to use all ram only for IO buffers
    rlim_t avaliableRam = getAvaliablePinneableRAM();
    rlim_t usableRAM = BUFFERS_RAM_USAGE_FACTOR*avaliableRam;
    rlim_t buffersTotalSize = buffersSizeLimit == 0 ?
    		usableRAM :
    		min(usableRAM, buffersSizeLimit);

    // bufferSize aligned to chunk size
    std::streampos bytesPerChunk = this->getBlockSize()*this->getBufferSize();
    this->bufferSize = buffersTotalSize/bytesPerChunk;

    // allocate buffer chunks
    bool allocSuccess = false;
    std::streampos bufferSizeBytes;
    do {
        bufferSizeBytes = this->bufferSize*bytesPerChunk;
    	allocSuccess = this->pinnedAlloc(&this->chunks,bufferSizeBytes);
    	if(!allocSucess) {
    		this->bufferSize--;
    		if(this->bufferSize == 0) {
    			// exit with error
    			LOG_ERR("Couldn't allocate SharedIO internal buffer.\n");
    		} else {
    			LOG_WAR(boost::format("Coudn't allocate %llu bytes for SharedIO internal buffer."
    					" Trying with a smaller buffer...\n") % bufferSizeBytes);
    		}
    	}
    }
    while(!allocSuccess);

    LOG_INF(boost::format(
    		"A new SharedIO object uses %llu bytes"
    		" (%u chunks of %u bytes blocks) "
    		" of pinned memory for its internal buffers."
    		" Available RAM: %llu bytes."
    		" Limit set by user: %llu bytes."
    		"\n")
    % bufferSizeBytes
    % this->getBufferSize()
    % this->getBlockSize()
    % avaliableRam
    % buffersSizeLimit
    );
}

paracrypt::SharedIO::~SharedIO() {
	if(this->inFile.is_open())
		this->inFile.close();
	this->outFile.close();
//	delete[] this->bufferSizes;
	this->freePinnedAlloc(this->chunks);
}

const rlim_t paracrypt::SharedIO::getBufferSize() {
	return this->bufferSize;
}

//const unsigned int paracrypt::SharedIO::getNBuffers() {
//	return this->nBuffers;
//}

const unsigned int paracrypt::SharedIO::getBlockSize() {
	return this->blockSize;
}

const unsigned int paracrypt::SharedIO::getChunkSize() {
	return this->chunkSize;
}

void paracrypt::SharedIO::setPadding(paddingScheme p) {
	this->paddingType = p;
}

unsigned int paracrypt::SharedIO::inFileRead(unsigned char* store, std::streampos nBlocks, readStatus *status, std::streampos* blockOffset)
{
	unsigned int nread = 0;
	if(this->inFileReadStatus == OK) {
		if(this->alreadReadBlocks >= this->maxBLocksRead) {
			this->inFile.read(store, nBlocks*this->blockSize);
			if(this->inFile.fail()){
				if(this->inFile.eof()) {
					unsigned long readBytes = this->inFile.gcount();
					nread = (readBytes/this->blockSize);
					applyPadding(store, nread, nread+1);
					nread++;
					this->inFile.close();
					this->inFileReadStatus = END;
				} else {
					LOG_FATAL(boost::format("Error reading input file: %s\n") % strerror(errno));
				}
			} else {
				nread = nBlocks;
			}
			(*blockOffset) = this->alreadyReadBlocks;
			this->alreadyReadBlocks++;
		} else {
			this->inFile.close();
			this->inFileReadStatus = END;
		}
	}
	(*status) = this->inFileReadStatus;
	return nread;
}

void paracrypt::SharedIO::outFileWrite(unsigned char* data, std::streampos nBlocks, std::streampos blockOffset)
{
	unsigned long size = nBlocks*this->blockSize;
	this->outFile.seekp(blockOffset*this->blockSize);
	this->outFile.write(data,size);
}

void paracrypt::SharedIO::applyPadding(unsigned char* data, rlim_t dataSize, rlim_t desiredSize)
{
	rlim_t paddingSize = desiredSize-dataSize;
	char* padding = data+dataSize;
	switch(this->paddingType) {
		case APPEND_ZEROS:
			memset(padding, 0, paddingSize);
			break;
		case PKCS7:
			uint8_t n = (uint8_t) paddingSize;
			for(int i = 0; i < paddingSize; i++) {
				padding[i] = n;
			}
			break;
	}
}

const rlim_t paracrypt::SharedIO::getAvaliablePinneableRAM()
{
	/*
	 *        http://man7.org/linux/man-pages/man2/setrlimit.2.html
	 *
	 *        int getrlimit(int resource, struct rlimit *rlim);
	 *
	 *        RLIMIT_MEMLOCK
	 *            This is the maximum number of bytes of memory that may be
	 *            locked into RAM.  This limit is in effect rounded down to the
	 *            nearest multiple of the system page size.  This limit affects
	 *            mlock(2), mlockall(2), and the mmap(2) MAP_LOCKED operation.
	 *
	 *            In Linux kernels before 2.6.9, this limit controlled the
	 *            amount of memory that could be locked by a privileged process.
	 *            Since Linux 2.6.9, no limits are placed on the amount of
	 *            memory that a privileged process may lock, and this limit
	 *            instead governs the amount of memory that an unprivileged
	 *            process may lock.
	 */
	struct rlimit limit;
	struct sysinfo info;
	getrlimit(RLIMIT_MEMLOCK,&limit);
	sysinfo(&info);
	rlim_t lock_limit = limit.rlim_cur;
	rlim_t ram_limit = info.freeram;
	rlim_t pinneable_limit = std::min(lock_limit, ram_limit);
	return pinneable_limit;
}

// TODO versiones del planificador que accedan con buffer dividido
// y sin dividir. hacer que se pueda registrar un lock para esperar
// que se llama cuando el thread lector lee suficiente
void paracrypt::SharedIO::divideBuffer(
		unsigned int chunkSizedDivisions[],
		unsigned int nWeightedDivisions,
		unsigned int weights[],
		unsigned int nFixedSizeDivisions = 0,
		unsigned int fixedSizes[] = {}
) {
	unsigned int nDivisions = nWeightedDivisions + nFixedSizeDivisions;
	rlim_t nChunks = this->getBufferSize();
	int d = 0;
	for(int i = 0; i < nFixedSizeDivisions; i++) {
		chunkSizedDivisions[d] = fixedSizes[i];
		nChunks -= fixedSizes[i];
		d++;
	}
	unsigned int totalWeight;
	for(int i = 0; i < nWeightedDivisions; i++) {
		totalWeight += buffersWeights[i];
	}
//	unsigned int remainingWeightParts = 0;
//	unsigned int remainingChunks = 0;
	for(int i = 0; i < nWeightedDivisions; i++) {
		unsigned int weightPart = totalWeight/weights[i];
//		remainingWeightParts += totalWeight%weights[i];
		unsigned int chunksPart = nChunks / weightPart;
//		remainingChunks += nChunks % weightPart;
		chunkSizedDivisions[d] = chunksPart;
		d++;
	}

	// ensure the entire buffer is used
	unsigned int alreadyDistributedChunks = 0;
	for(int i = 0; i < nDivisions; i++) {
		alreadyDistributedChunks += chunkSizedDivisions[i];
	}
	unsigned int remainingChunks = this->getBufferSize() - alreadyDistributedChunks;
	d = 0;
	while(remainingChunks > 0) {
		chunkSizedDivisions[d]++;
		remainingChunks--;
		d = d+1 % nDivisions;
	}

	// if assert is enabled ensure the entire buffer is used
#if !defined(NDEBUG)
	unsigned int assertTotalDistributedChunks = 0;
	for(int i = 0; i < nDivisions; i++) {
		assertTotalDistributedChunks += chunkSizedDivisions[i];
	}
	assert(assertTotalDistributedChunks == this->getBufferSize());
#endif

//	// calculate buffer sizes
//    unsigned int totalWeight;
//    for(int i = 0; i < nBuffers; i++) {
//    	totalWeight += buffersWeights[i];
//    }
//    for(int i = 0; i < nBuffers; i++) {
//    	float sizeFraction = buffersWeights[i]/totalWeight;
//    	// divide by the block size and discard decimals
//    	// to align buffer size with block size
//    	unsigned int nBlocks = (sizeFraction * buffersTotalSize)/blockSize;
//    	this->bufferSizes[i] = nBlocks;
//    }

}
