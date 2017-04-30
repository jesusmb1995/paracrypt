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

#ifndef IO_H_
#define IO_H_

namespace paracrypt {

/*
 * Shared file IO - multiple buffers permit to multiple readers/writers
 *  to share input/output block operations.
 */
class SharedIO {
public:
	typedef enum {
		OK = 0,
		EMPTY = 1, // ASYNC implementations: We have to wait until the buffer is filled
		END = 2,
	} readStatus;
private:
	const std::ifstream inFile;
	readStatus inFileReadStatus;
	const std::ofstream outFile;
	const unsigned int blockSize;
	const std::streampos maxBlocksRead;
	std::streampos alreadyReadBlocks;
	static const rlim_t getAvaliablePinneableRAM();
    const rlim_t bufferSizes[];
    const unsigned int nBuffers;
    void applyPadding(unsigned char* data, rlim_t dataSize, rlim_t desiredSize);

protected:
	// return number of blocks read, blockOffset and Status
    unsigned int inFileRead(unsigned char* store, std::streampos nBlocks, readStatus *status, std::streampos* blockOffset);
	void outFileWrite(unsigned char* data, std::streampos nBlocks, std::streampos blockOffset);

public:
	typedef enum {
		APPEND_ZEROS = 0,
		PKCS7 = 1,
	} paddingScheme;
	paddingScheme paddingType;
	// Initialize size(bufferWeights) buffers
	 // Reads the whole file
	SharedIO(
			std::string inFilename,
			std::string outFilename,
			unsigned int blockSize,
			unsigned int nBuffers,
			unsigned int buffersWeights[] = {1}, //TODO another array for constant size buffers...
			#define AUTO_IO_BUFFERS_LIMIT 0
			std::streampos buffersSizeLimit = AUTO_IO_BUFFERS_LIMIT,
			std::streampos begin = 0,
			std::streampos end = 0
	);
	virtual ~SharedIO();
	void setPadding(paddingScheme p);
	const rlim_t getBufferSize(unsigned int bufferIndex);
	const unsigned int getNBuffers();
	const unsigned int getBlockSize();
	// return number of blocks read, blockOffset and Status
	virtual unsigned int read(unsigned int bufferIndex, char* data[], std::streampos* blockOffset, readStatus *status) = 0;
	virtual void dump(unsigned int bufferIndex, std::streampos blockOffset) = 0;
};

} /* namespace paracrypt */

#endif /* IO_LIMITS_H_ */
