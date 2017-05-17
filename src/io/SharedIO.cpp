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
#include "logging.hpp"
#include <boost/thread/locks.hpp>

// Reader thread
void paracrypt::SharedIO::reading() {
	chunk c;
	c.status = OK;
	while(c.status != END && !(*finishThreading)) {
		boost::unique_lock<boost::mutex> lock(chunk_access);
			if(this->emptyChunks->size() <= 0) {
				DEV_TRACE("SharedIO reader: Not enough free memory for"
						" buffering. Waiting for a chunk of"
						" free memory before attempting to read from the input file.");
				this->thereAreEmptyChunks.wait(lock);
				if(*finishThreading)
					break;
				DEV_TRACE("SharedIO reader: Waking up... now there is"
						" a chunk of free memory and I can read from the"
						" input file.");
			}
			c = this->emptyChunks->dequeue();
		lock.unlock();

		c.nBlocks = this->inFileRead(c.data,this->getChunkSize(),&c.status,&c.blockOffset);

		lock.lock();
			readyToReadChunks->enqueue(c);
			DEV_TRACE(boost::format("SharedIO reader: %llu block chunk beginning at block "
					"%llu has been enqueued (read queue size: %llu)- its ready to be read by the user.")
			% c.nBlocks
			% c.blockOffset
			% readyToReadChunks->size());
			if(this->readyToReadChunks->size() == 1) {
				DEV_TRACE("SharedIO reader: Notifying the user.");
				this->thereAreChunksToRead.notify_one();
			}
		lock.unlock();
	}
	LOG_TRACE("SharedIO reader exits.");
}

// Main thread
paracrypt::BlockIO::chunk paracrypt::SharedIO::read()
{
	boost::unique_lock<boost::mutex> lock(chunk_access);
		if(this->readyToReadChunks->size() <= 0) {
			this->thereAreChunksToRead.wait(lock);
		}
		chunk c = this->readyToReadChunks->dequeue();
		return c;
}
void paracrypt::SharedIO::dump(chunk c)
{
	boost::unique_lock<boost::mutex> lock(chunk_access);
		outputChunks->enqueue(c);
		DEV_TRACE(boost::format("SharedIO user: %llu block chunk beginning at block "
				"%llu has been placed in the output queue (size: %llu).")
			% c.nBlocks
			% c.blockOffset
			% outputChunks->size());
		if(this->outputChunks->size() == 1) {
			DEV_TRACE("SharedIO user: Notifying the writer.");
			this->thereAreChunksToWrite.notify_one();
		}
}

// Writter thread
void paracrypt::SharedIO::writing() {
	chunk c;
	c.status = OK;
	while(!(*finishThreading) || this->outputChunks->size() > 0) {
		boost::unique_lock<boost::mutex> lock(chunk_access);
			if(this->outputChunks->size() <= 0) {
				if(*finishThreading) {
					// only exit if there are no more chunks to
					//  dump and the finish order has been received
					DEV_TRACE("SharedIO writer: I received a order to stop and there are"
							" no more chunks in the output queue so I can finish now"
							" knowing that I do not leave any write order behind.");
					break;
				}
				DEV_TRACE("SharedIO writer: Waiting for a chunk in the output queue.");
				this->thereAreChunksToWrite.wait(lock);
				if(this->outputChunks->size() == 0 && *finishThreading) {
					DEV_TRACE("SharedIO writer: I received a order to stop.");
					break;
				}
				DEV_TRACE("SharedIO writer: waking up... now I have a chunk in the output"
						" queue that I can dump in the output file.");
			}
			c = this->outputChunks->dequeue();
		lock.unlock();

		this->outFileWrite(c.data,c.nBlocks,c.blockOffset);
		DEV_TRACE(boost::format("SharedIO writer: %llu block chunk beginning at block"
				" %llu has been written to the output file.") % c.nBlocks % c.blockOffset);

		lock.lock();
			emptyChunks->enqueue(c);
			DEV_TRACE(boost::format("SharedIO writer: %llu free chunks.") % this->emptyChunks->size());
			if(this->emptyChunks->size() == 1) {
				DEV_TRACE("SharedIO writer: Notifying the reader.");
				this->thereAreEmptyChunks.notify_one();
			}
		lock.unlock();
	}
	LOG_TRACE("SharedIO writer exits.");
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

    if(this->getEnd() != NO_RANDOM_ACCESS) {
    	rlim_t maxRead = this->getMaxBlocksRead()*this->getBlockSize();
    	// do not allocate memory we will not use
    	buffersTotalSize = std::min(buffersTotalSize, maxRead);
    }

    // Align to block/nchunks size in excess
    //  in this way we assure that we reserve
    //  enough memory to process an entire file
    //  delimited by bufferSizeLimit at once.
    {
		rlim_t remaining = buffersTotalSize % this->getBlockSize();
		buffersTotalSize += remaining;
		remaining = (buffersTotalSize/this->getBlockSize()) % nChunks;
		buffersTotalSize += remaining*nChunks;
    }

    // at least one block per chunk
    buffersTotalSize = std::max(buffersTotalSize, ((rlim_t)this->getBlockSize())*nChunks);

    bool allocSuccess = false;
    std::streamsize bufferSizeBytes;
    do {
		if(buffersTotalSize < this->getBlockSize()*nChunks) {
			// exit with error
			ERR("Couldn't allocate SharedIO internal buffer.\n");
		}
    	this->chunkSize = (buffersTotalSize / this->getBlockSize() / nChunks);
    	// bufferSize aligned to chunk size
        bufferSizeBytes = this->getBufferSize()*this->getChunkSize()*this->getBlockSize();
    	allocSuccess = this->getPinned()->alloc((void**)&this->chunksData,bufferSizeBytes);
    	if(!allocSuccess) {
    		buffersTotalSize -= this->chunkSize;
    		// minimum 1 block per chunk
    		if(buffersTotalSize >= this->getBlockSize()*nChunks) {
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
    	unsigned char* chunkData = this->chunksData + this->getChunkSize()*this->getBlockSize()*i;
    	this->chunks[i].data = chunkData;
    	this->emptyChunks->enqueue(this->chunks[i]);
    }


    LOG_INF(boost::format(
    		"A new SharedIO object uses %llu bytes"
    		" (%llu chunks - each one with %llu blocks of %u bytes) "
    		" of pinned memory for its internal buffers."
    		"\n")
    % bufferSizeBytes
    % this->getBufferSize()
    % this->getChunkSize()
    % this->getBlockSize()
    );

    // launch reader and writer threads
    this->readyToReadChunks = new LimitedQueue<chunk>(this->getBufferSize());
    this->outputChunks = new LimitedQueue<chunk>(this->getBufferSize());
    this->finishThreading = new bool();
    *finishThreading = false;
    this->reader = new boost::thread(boost::bind(&paracrypt::SharedIO::reading, this));
    this->writer = new boost::thread(boost::bind(&paracrypt::SharedIO::writing, this));
}
void paracrypt::SharedIO::destruct() {

	LOG_TRACE("SharedIO user: Ordering threads to finish... \n");
	boost::unique_lock<boost::mutex> lock(chunk_access);
		*finishThreading = true;
		this->thereAreEmptyChunks.notify_all();
		this->thereAreChunksToWrite.notify_all();
	lock.unlock();
	this->reader->join();
	this->writer->join();

	delete this->reader;
	delete this->writer;
	delete this->finishThreading;
	delete this->emptyChunks;
	delete this->readyToReadChunks;
	delete this->outputChunks;
	delete[] this->chunks;
	this->getPinned()->free((void*)this->chunksData);
}

const std::streamsize paracrypt::SharedIO::getBufferSize() {
	return this->bufferSize;
}

const std::streamsize paracrypt::SharedIO::getChunkSize() {
	return this->chunkSize;
}
