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
	typedef enum {
		APPEND_ZEROS = 0,
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
	std::streamsize inFileRead(unsigned char* store, std::streamsize nBlocks, readStatus *status, std::streampos* blockOffset);
	void outFileWrite(unsigned char* data, std::streampos nBlocks, std::streampos blockOffset);
	void outFileWriteBytes(unsigned char* data, std::streampos nBytes, std::streampos byteOffset);
	void setPadding(paddingScheme p);
	paddingScheme getPadding();
	const unsigned int getBlockSize();
	std::string getInFileName();
	std::string getOutFileName();
	std::streampos getBegin();
	std::streampos getEnd();
	std::streamsize getMaxBlocksRead();

private:
	std::ifstream inFile;
	std::string inFileName;
	readStatus inFileReadStatus;
	std::ofstream outFile;
	std::string outFileName;
	const unsigned int blockSize;
	std::streamsize maxBlocksRead;
	std::streamsize alreadyReadBlocks;
	paddingScheme paddingType;
	void applyPadding(unsigned char* data, std::streamsize dataSize, std::streamsize desiredSize);
	std::streampos begin;
	std::streampos beginBlock;
	std::streampos end;
};

} /* namespace paracrypt */

#endif /* BLOCKIO_HPP_ */
