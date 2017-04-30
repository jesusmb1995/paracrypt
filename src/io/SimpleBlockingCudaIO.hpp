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

#ifndef SIMPLEBLOCKINGCUDAIO_HPP_
#define SIMPLEBLOCKINGCUDAIO_HPP_

#include "SharedIO.hpp"

namespace paracrypt {

class SimpleBlockingCudaIO: public SharedIO {
private:
	unsigned char* buffer;
	unsigned int bufferBlocksSize;
	unsigned int currentBufferIndex;
public:
	SimpleBlockingCudaIO(
			std::string inFilename,
			std::string outFilename,
			unsigned int blockSize,
			unsigned int nBuffers,
			unsigned int buffersWeights[] = {1},
			std::streampos buffersSizeLimit = AUTO_IO_BUFFERS_LIMIT,
			std::streampos begin = 0,
			std::streampos end = 0
	);
	~SimpleBlockingCudaIO();
	unsigned int read(unsigned int bufferIndex, char* data[], std::streampos* blockOffset, readStatus *status);
	void dump(unsigned int bufferIndex, std::streampos blockOffset);
};

} /* namespace paracrypt */

#endif /* SIMPLEBLOCKINGCUDAIO_HPP_ */
