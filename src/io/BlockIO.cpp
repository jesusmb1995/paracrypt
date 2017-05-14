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

#include "BlockIO.hpp"
#include "logging.hpp"
#include <algorithm>
#include "IO.hpp"

namespace paracrypt {

BlockIO::BlockIO(
		std::string inFilename,
		std::string outFilename,
		unsigned int blockSize,
		std::streampos begin,
		std::streampos end
) : blockSize(blockSize)
{
	this->inFileName = inFilename;
	this->outFileName = outFilename;
	this->inFile.open(inFilename.c_str(),std::ifstream::binary);
	if(!inFile) {
		ERR(boost::format("cannot open %s: %s") % inFilename % strerror(errno));
	}
	this->inFileReadStatus = OK;
	this->inFileSize = IO::fileSize(&inFile);
	this->inNBlocks = inFileSize / blockSize;
	unsigned int remBytesFileSize = inFileSize % blockSize;
	if(remBytesFileSize > 0) {
		this->inNBlocks++;
	}

	if(begin != NO_RANDOM_ACCESS) {
		this->beginBlock = begin/blockSize;
		this->begin = this->beginBlock*this->blockSize; // aligned to block
		this->inFile.seekg(begin);
		// TODO extra read blocks
	}
	else {
		this->beginBlock = 0;
		this->begin = 0;
	}
	this->outFile.open(outFilename.c_str(),std::ifstream::binary | std::ifstream::trunc);
	if(!outFile) {
		ERR(boost::format("cannot open %s: %s") % outFilename % strerror(errno));
	}
	this->alreadyReadBlocks = 0;
	std::streamsize maxBytesRead;
	if(end == NO_RANDOM_ACCESS) {
		this->maxBlocksRead = NO_RANDOM_ACCESS;
	} else {
		if (begin > end) {
			LOG_WAR("Swapping begin-end random access positions.\n");
			std::swap(begin,end);
		}
		maxBytesRead = end-begin;
		this->maxBlocksRead = maxBytesRead / blockSize;
		int halfBlock = maxBytesRead % blockSize;
		if(halfBlock != 0) {
			this->maxBlocksRead += 1;
//			LOG_WAR(boost::format(
//					"Aligning random access section to block size: "
//					" Using %llu bytes instead of %llu bytes.\n")
//				% (this->maxBlocksRead * blockSize)
//				% maxBytesRead
//			);
			// TODO extra read end blocks
		}
	}
	this->begin = begin;
	this->end = end;
	this->paddingType = APPEND_ZEROS_TO_INPUT; // default padding
}

BlockIO::~BlockIO() {
	if(this->inFile.is_open())
		this->inFile.close();
	this->outFile.flush();
	this->outFile.close();
}

const unsigned int paracrypt::BlockIO::getBlockSize() {
	return this->blockSize;
}

void paracrypt::BlockIO::setPadding(paddingScheme p) {
	this->paddingType = p;
}

paracrypt::BlockIO::paddingScheme paracrypt::BlockIO::getPadding() {
	return this->paddingType;
}

std::streamsize paracrypt::BlockIO::inFileRead(unsigned char* store, std::streamsize nBlocks, readStatus *status, std::streampos* blockOffset)
{
	std::streamsize nread = 0;
	if(this->inFileReadStatus == OK) {
		std::streamsize blocksToRead;
		if(this->maxBlocksRead == NO_RANDOM_ACCESS || this->alreadyReadBlocks < this->maxBlocksRead) {
			blocksToRead = this->maxBlocksRead == NO_RANDOM_ACCESS ?
					                                                         nBlocks
					: std::min((this->maxBlocksRead-this->alreadyReadBlocks),nBlocks);
			this->inFile.read((char*)store, blocksToRead*this->getBlockSize());
			if(this->inFile.fail()){
				if(this->inFile.eof()) {
					std::streamsize readBytes = this->inFile.gcount();
					nread = (readBytes/(std::streamsize)this->blockSize); // entire blocks read
					if(readBytes%this->blockSize != 0) {
						applyPadding(store, readBytes, (nread+1)*this->getBlockSize());
						nread++; // padding block
					}
					this->inFile.close();
					this->inFileReadStatus = END;
				} else {
					FATAL(boost::format("Error reading input file: %s\n") % strerror(errno));
				}
			} else {
				nread = blocksToRead;
			}
			(*blockOffset) = this->beginBlock + this->alreadyReadBlocks;
			this->alreadyReadBlocks += nread;
			if(this->maxBlocksRead != NO_RANDOM_ACCESS && this->alreadyReadBlocks >= this->maxBlocksRead) {
				this->inFile.close();
				this->inFileReadStatus = END;
			}
		}
	}
	(*status) = this->inFileReadStatus;
	return nread;
}

void paracrypt::BlockIO::outFileWriteBytes(unsigned char* data, std::streampos nBytes, std::streampos byteOffset)
{
	this->outFile.seekp(byteOffset);
	this->outFile.write((const char*)data,nBytes);
	if(!outFile) {
		FATAL(boost::format("Error writing to output file: %s\n") % strerror(errno));
	}
}

void paracrypt::BlockIO::outFileWrite(unsigned char* data, std::streampos nBlocks, std::streampos blockOffset)
{
	std::streamsize size = nBlocks*this->blockSize;
	if(blockOffset+nBlocks >= this->inNBlocks) {
		size = this->removePadding(data, size);
	}
	std::streampos byteOffset = blockOffset*this->blockSize;
	this->outFileWriteBytes(data, size, byteOffset);
}

void paracrypt::BlockIO::applyPadding(unsigned char* data, std::streamsize dataSize, std::streamsize desiredSize)
{
	std::streamsize paddingSize = desiredSize-dataSize;
	unsigned char* padding = data+dataSize;
	switch(this->paddingType) {
		case APPEND_ZEROS_TO_INPUT:
			memset(padding, 0, paddingSize);
			break;
		case PKCS7:
			uint8_t n = (uint8_t) paddingSize;
			memset(padding, n, paddingSize); // About memset:
			// The value is passed as an int, but the
			// function fills the block of memory using
			// the unsigned char conversion of this value.
			break;
	}
}

std::streamsize paracrypt::BlockIO::removePadding(unsigned char* data, std::streamsize dataSize)
{
	std::streamsize unpaddedSize = dataSize;
	if(dataSize > 0) {
		unsigned char* ptr = data+(dataSize-1);
		switch(this->paddingType) {
			case APPEND_ZEROS_TO_INPUT:
	// case APPEND_ZEROS:
	//			while(*ptr == 0) {
	//				unpaddedSize--;
	//				ptr--;
	//			}
				break;
			case PKCS7:
				unsigned char n = *ptr;
				bool hasPadding = true;
				for(int i = 0; i < n; i++) {
					if(*ptr != n) {
						hasPadding = false;
						break;
					}
					ptr--;
				}
				if(hasPadding) {
					unpaddedSize = unpaddedSize - n;
				}
				break;
		}
	}
	return unpaddedSize;
}

std::string paracrypt::BlockIO::getInFileName()
{
	return this->inFileName;
}

std::string paracrypt::BlockIO::getOutFileName()
{
	return this->outFileName;
}

std::streampos paracrypt::BlockIO::getBegin()
{
	return this->begin;
}

std::streampos paracrypt::BlockIO::getEnd()
{
	return this->end;
}

std::streamsize paracrypt::BlockIO::getMaxBlocksRead()
{
	return this->maxBlocksRead;
}

std::streamsize paracrypt::BlockIO::getInFileSize()
{
	return this->inFileSize;
}

std::streamsize paracrypt::BlockIO::getInNBlocks()
{
	return this->inNBlocks;
}

} /* namespace paracrypt */
