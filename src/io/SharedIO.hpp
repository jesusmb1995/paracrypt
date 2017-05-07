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

#include <fstream>
#include <string>
#include <boost/thread/thread.hpp>
#include <boost/thread/shared_mutex.hpp>
#include "BlockIO.hpp"
#include "LimitedQueue.hpp"
#include "Pinned.hpp"

#ifndef IO_H_
#define IO_H_

namespace paracrypt {

/*
 * IO operations are done in background with two threads: one to
 *  read and another to write. This means write operations can be performed
 *  asynchronously and reads are performed in O(1) time if the read thread
 *  has already stored some chunks of data in the input queue.
 *
 *  Warning: Do not call inherited IO methods because those are not
 *  thread-safe. Use read() and dump() instead.
 */
class SharedIO: public BlockIO {
public:
	// Initialize size(bufferWeights) buffers
	 // Reads the whole file
	SharedIO(
			std::string inFilename,
			std::string outFilename,
			unsigned int blockSize,
			std::streampos begin = NO_RANDOM_ACCESS, // file begin byte
			std::streampos end = NO_RANDOM_ACCESS    // file end byte
	);
	virtual ~SharedIO();
	const std::streamsize getBufferSize(); // get total number of chunks in the buffer
	const std::streamsize getChunkSize(); // returns nBlocks per chunk
	chunk read();
	void dump(chunk c);

protected:
    virtual Pinned* getPinned() = 0;

    // cannot directly use virtual
    //  methods in the constructor/destructor
	#define AUTO_IO_BUFFER_LIMIT 0
    void construct(unsigned int nChunks, // number of chunks in which the buffer is divided
            // TODO support chunks of different size?
    		rlim_t bufferSizeLimit = AUTO_IO_BUFFER_LIMIT);
    void destruct();

private:
	chunk *chunks;
	unsigned char* chunksData;
	rlim_t chunkSize;
	std::streamsize bufferSize; // nChunks
	static const rlim_t getAvaliablePinneableRAM();
	LimitedQueue<chunk> *emptyChunks;
	LimitedQueue<chunk> *readyToReadChunks; // chunks with new data read by the reader thread
	LimitedQueue<chunk> *outputChunks; // chunks waiting to be written by the writer thread
	                                   //  before being empty and being added to emptyChunks
	boost::mutex chunk_access;
	boost::condition_variable thereAreEmptyChunks;
	boost::condition_variable thereAreChunksToRead;
	boost::condition_variable thereAreChunksToWrite;
	boost::thread *reader, *writer;
	bool *finishThreading;
	void reading();
	void writing();
};

} /* namespace paracrypt */

#endif /* IO_LIMITS_H_ */
