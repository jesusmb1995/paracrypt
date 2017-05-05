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
#include <boost/thread/locks.hpp>

// Reader thread
void paracrypt::SharedIO::reading() {
	chunk c;
	c.status = OK;
	while(c.status != END && !(*finishThreading)) {
		boost::unique_lock<boost::mutex> lock(chunk_access);
			if(this->emptyChunks->size() <= 0) {
				LOG_TRACE("SharedIO reader: Waiting for a chunk of"
						" free memory to read from the input file.");
				this->thereAreEmptyChunks.wait(lock);
				if(*finishThreading)
					break;
				LOG_TRACE("SharedIO reader: Waking up... now there is"
						" a chunk free memory and I can read from the"
						" input file.");
			}
			chunk c = this->emptyChunks->dequeue();
		lock.unlock();

		c.nBlocks = this->inFileRead((unsigned char*)c.data,this->getChunkSize(),&c.status,&c.blockOffset);

		lock.lock();
			readyToReadChunks->enqueue(c);
			if(this->readyToReadChunks->size() == 1) {
				this->thereAreChunksToRead.notify_one();
			}
		lock.unlock();
	}
}

// Main thread
paracrypt::SharedIO::chunk paracrypt::SharedIO::read(readStatus *status)
{
	boost::unique_lock<boost::mutex> lock(chunk_access);
		if(this->readyToReadChunks->size() <= 0) {
			this->thereAreChunksToRead.wait(lock);
		}
		chunk c = this->emptyChunks->dequeue();
		return c;
}
void paracrypt::SharedIO::dump(chunk c)
{
	boost::unique_lock<boost::mutex> lock(chunk_access);
		outputChunks->enqueue(c);
		if(this->outputChunks->size() == 1) {
			this->thereAreChunksToWrite.notify_one();
		}
}

// Writter thread
void paracrypt::SharedIO::writing() {
	chunk c;
	c.status = OK;
	while(c.status != END && !(*finishThreading)) {
		boost::unique_lock<boost::mutex> lock(chunk_access);
			if(this->outputChunks->size() <= 0) {
				LOG_TRACE("SharedIO writer: Waiting for a chunk in the output queue.");
				this->thereAreChunksToWrite.wait(lock);
				if(*finishThreading)
					break;
				LOG_TRACE("SharedIO writer: waking up... now I have a chunk in the output"
						" queue that I can dump in the output file.");
			}
			chunk c = this->outputChunks->dequeue();
		lock.unlock();

		this->outFileWrite((unsigned char*)c.data,this->getChunkSize(),c.blockOffset);

		lock.lock();
			emptyChunks->enqueue(c);
			if(this->readyToReadChunks->size() == 1) {
				this->thereAreEmptyChunks.notify_one();
			}
		lock.unlock();
	}
}

paracrypt::SharedIO::SharedIO(
		std::string inFilename,
		std::string outFilename,
		unsigned int blockSize,
		std::streampos begin,
		std::streampos end
		)
: paracrypt::BlockIO::BlockIO(inFilename, outFilename, blockSize, begin, end)
{
//	this->finishThreading = NULL;
}

paracrypt::SharedIO::~SharedIO() {}

void paracrypt::SharedIO::construct(unsigned int nChunks, rlim_t bufferSizeLimit) {
    // allocate buffer chunks
	this->bufferSize = nChunks;
    rlim_t buffersTotalSize = this->getPinned()->getReasonablyBigChunkOfRam(bufferSizeLimit);
    bool allocSuccess = false;
    std::streamsize bufferSizeBytes;
    do {
    	this->chunkSize = (buffersTotalSize / this->getBlockSize() / nChunks);
    	// bufferSize aligned to chunk size
        bufferSizeBytes = this->getBufferSize()*this->getChunkSize()*this->getBlockSize();
    	allocSuccess = this->getPinned()->alloc((void**)&this->chunksData,bufferSizeBytes);
    	if(!allocSuccess) {
    		buffersTotalSize -= this->getChunkSize();
    		// minimum 1 block per chunk
    		if(buffersTotalSize <= this->getBlockSize()*nChunks) {
    			// exit with error
    			ERR("Couldn't allocate SharedIO internal buffer.\n");
    		} else {
    			LOG_WAR(boost::format("Coudn't allocate %llu bytes for SharedIO internal buffer."
    					" Trying with a smaller buffer...\n") % bufferSizeBytes);
    		}
    	}
    }
    while(!allocSuccess);

    // initialize chunks
    this->chunks = new chunk[nChunks];
    this->emptyChunks = new LimitedQueue<chunk>(this->getBufferSize());
    for(unsigned int i = 0; i < nChunks; i++) {
    	unsigned char* chunkData = this->chunksData + this->getChunkSize()*i;
    	this->chunks[i].data = chunkData;
    	this->emptyChunks->enqueue(this->chunks[i]);
    }


    LOG_INF(boost::format(
    		"A new SharedIO object uses %llu bytes"
    		" (%u chunks of %u bytes blocks) "
    		" of pinned memory for its internal buffers."
    		"\n")
    % bufferSizeBytes
    % this->getBufferSize()
    % this->getBlockSize()
    );

    // launch reader and writer threads
    this->readyToReadChunks = new LimitedQueue<chunk>(this->getBufferSize());
    this->outputChunks = new LimitedQueue<chunk>(this->getBufferSize());
    finishThreading = new bool();
    *finishThreading = false;
    this->reader = new boost::thread(boost::bind(&paracrypt::SharedIO::reading, this));
    this->writer = new boost::thread(boost::bind(&paracrypt::SharedIO::writing, this));
}
void paracrypt::SharedIO::destruct() {
	*finishThreading = true;
	this->thereAreEmptyChunks.notify_all();
	this->thereAreChunksToWrite.notify_all();
	this->reader->join();
	this->writer->join();
	delete finishThreading;
	delete emptyChunks;
	delete readyToReadChunks;
	delete outputChunks;
	delete[] this->chunks;
	this->getPinned()->free((void*)this->chunksData);
}

const std::streamsize paracrypt::SharedIO::getBufferSize() {
	return this->bufferSize;
}

const std::streamsize paracrypt::SharedIO::getChunkSize() {
	return this->chunkSize;
}
