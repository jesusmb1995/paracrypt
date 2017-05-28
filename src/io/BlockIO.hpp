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

#ifndef BLOCKIO_HPP_
#define BLOCKIO_HPP_

#include <sys/resource.h>
#include <fstream>
#include <string>

namespace paracrypt {

class BlockIO {
public:
	typedef enum {
		OK = 0,
		END = 1,
	} readStatus;
	typedef struct chunk {
		std::streamsize nBlocks; //number of blocks
		std::streamsize padding; //number of padded bytes
		std::streampos blockOffset;
		unsigned char* data;
		readStatus status;
	} chunk;
	virtual chunk read() = 0;
	virtual void dump(chunk c) = 0;

	typedef enum {
		UNPADDED = 0, // Append zeros when reading and remove number padding bytes at writing
		PKCS7 = 1,
	} paddingScheme;
	BlockIO(
			std::string inFilename,
			std::string outFilename,
			unsigned int blockSize,
			#define NO_RANDOM_ACCESS -1
			std::streampos begin = NO_RANDOM_ACCESS,
			std::streampos end = NO_RANDOM_ACCESS
	);
	virtual ~BlockIO();

	std::streamsize inFileRead(unsigned char* store, std::streamsize nBlocks, readStatus *status, std::streampos* blockOffset,  std::streamsize* paddingSize);
	void outFileWrite(unsigned char* data, std::streampos nBlocks, std::streampos blockOffset, std::streamsize cutBytes = 0);
	void outFileWriteBytes(unsigned char* data, std::streampos nBytes, std::streampos byteOffset);
	void setPadding(paddingScheme p);
	paddingScheme getPadding();
	const unsigned int getBlockSize();
	std::string getInFileName();
	std::streamsize getInFileSize();
	std::streamsize getInNBlocks();
	std::string getOutFileName();
	std::streampos getBegin();
	std::streampos getBeginBlock();
	std::streampos getEnd();
	std::streampos getEndBlock();
	std::streamsize getMaxBlocksRead();

	std::streamoff getRandomAccessBeginOffset();
	std::streamsize getRandomAccessNBytes();

private:
	std::ifstream inFile;
	std::string inFileName;
	std::streamsize inFileSize; // in number of blocks
	std::streamsize inNBlocks;
	readStatus inFileReadStatus;
	std::ofstream outFile;
	std::string outFileName;
	const unsigned int blockSize;
	std::streamsize maxBlocksRead;
	std::streamsize alreadyReadBlocks;
	paddingScheme paddingType;
	// return the padding size (only the number of bytes added to the original data size "dataSize")
	std::streamsize applyPadding(unsigned char* data, std::streamsize dataSize, std::streamsize desiredSize);
	// return the unpadded size, total data size without padding
	std::streamsize removePadding(unsigned char* data, std::streamsize dataSize, std::streamsize cutBytes = 0);
	std::streampos begin;
	std::streampos beginBlock;
	std::streampos end;
	std::streampos endBlock;

	std::streamsize randomAccessNBytes;
	std::streamoff randomAccessBeginOffset;
};

} /* namespace paracrypt */

#endif /* BLOCKIO_HPP_ */
