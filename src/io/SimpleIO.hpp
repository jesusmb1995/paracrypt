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
#include "BlockIO.hpp"
#include "LimitedQueue.hpp"
#include "Pinned.hpp"

#ifndef SIMPLEIO_H_
#define SIMPLEIO_H_

namespace paracrypt {

class SimpleIO: public BlockIO {
public:
	SimpleIO(
			std::string inFilename,
			std::string outFilename,
			unsigned int blockSize,
			std::streampos begin = NO_RANDOM_ACCESS, // file begin byte
			std::streampos end = NO_RANDOM_ACCESS    // file end byte
	);
	virtual ~SimpleIO();
	const std::streamsize getBufferSize(); // get number of blocks

	// read a chunk, return the number of blocks read, the offset, and the status
	std::streamsize read(readStatus *status, std::streampos* blockOffset);
    void dump(std::streampos blockOffset); // writes buffer contents
    const unsigned char* getBufferPtr();

protected:
    virtual Pinned* getPinned() = 0;

    // cannot directly use virtual
    //  methods in the constructor/destructor
	#define AUTO_IO_BUFFER_LIMIT 0
    void construct(rlim_t bufferSizeLimit = AUTO_IO_BUFFER_LIMIT);
    void destruct();

private:
    std::streamsize nLastRead;
    const unsigned char* buffer;
    std::streampos blockOffset;
    std::streamsize bufferSize; // nBlocks
};

} /* namespace paracrypt */

#endif /* SIMPLEIO_H_ */
