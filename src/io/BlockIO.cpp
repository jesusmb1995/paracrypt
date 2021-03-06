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
#include "utils/logging.hpp"
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
		this->randomAccessBeginOffset = begin%blockSize;
		this->begin = this->beginBlock*this->blockSize; // aligned to block
		this->inFile.seekg(this->begin);
	}
	else {
		this->beginBlock = 0;
		this->begin = 0;
		this->randomAccessBeginOffset = 0;
	}
	this->end = end == NO_RANDOM_ACCESS ? end : std::min(end,(std::streampos)(inFileSize-1));
	this->outFile.open(outFilename.c_str(),std::ifstream::binary | std::ifstream::trunc);
	if(!outFile) {
		ERR(boost::format("cannot open %s: %s") % outFilename % strerror(errno));
	}
	this->alreadyReadBlocks = 0;
	std::streamsize maxBytesRead;
	if(this->end == NO_RANDOM_ACCESS) {
		this->maxBlocksRead = NO_RANDOM_ACCESS;
		this->randomAccessNBytes = NO_RANDOM_ACCESS;
	} else {
		if (this->begin > this->end) {
			LOG_WAR("Swapping begin-end random access positions.\n");
			std::swap(this->begin,this->end);
		}
		maxBytesRead = this->end-this->begin+1; // +1 (end byte is read too)
		this->maxBlocksRead = maxBytesRead / blockSize;
		unsigned int halfBlock = maxBytesRead % blockSize;
		if(halfBlock != 0) {
			this->maxBlocksRead += 1;
			LOG_WAR(boost::format(
					"Aligning random access section to block size: "
					" Using %llu bytes instead of %llu bytes.\n")
				% (this->maxBlocksRead * blockSize)
				% maxBytesRead
			);
		}
		this->randomAccessNBytes = (this->end - this->begin) + 1;
	}
	this->endBlock = this->end/blockSize;
	this->paddingType = UNPADDED; // unpadded data by default: the read and wrote messages have the same length
}

BlockIO::~BlockIO() {
	if(this->inFile.is_open())
		this->inFile.close();
	this->outFile.flush();
	if(!outFile) {
		FATAL(boost::format("Error flushing output file: %s\n") % strerror(errno));
	}
	this->outFile.close();
	LOG_TRACE("Output file flushed and closed.");
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

std::streamsize paracrypt::BlockIO::inFileRead(unsigned char* store, std::streamsize nBlocks, readStatus *status, std::streampos* blockOffset, std::streamsize* paddingSize)
{
	std::streamsize nread = 0;
	(*paddingSize) = 0;
	if(this->inFileReadStatus == OK) {
		std::streamsize blocksToRead;
		if(this->maxBlocksRead != NO_RANDOM_ACCESS && this->alreadyReadBlocks >= this->maxBlocksRead) {
			// Enter here if for example we do random access to the end of the file
			this->inFile.close();
			this->inFileReadStatus = END;
		}
		else if(this->maxBlocksRead == NO_RANDOM_ACCESS || this->alreadyReadBlocks < this->maxBlocksRead) {
			blocksToRead = this->maxBlocksRead == NO_RANDOM_ACCESS ?
					                                                         nBlocks
					: std::min((this->maxBlocksRead-this->alreadyReadBlocks),nBlocks);
			this->inFile.read((char*)store, blocksToRead*this->getBlockSize());
			if(this->inFile.fail()){
				if(this->inFile.eof()) {
					std::streamsize readBytes = this->inFile.gcount();
					nread = (readBytes/(std::streamsize)this->blockSize); // entire blocks read
					if(readBytes%this->blockSize != 0) {
						(*paddingSize) = applyPadding(store, readBytes, (nread+1)*this->getBlockSize());
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

void paracrypt::BlockIO::outFileWrite(unsigned char* data, std::streampos nBlocks, std::streampos blockOffset, std::streamsize cutBytes)
{
	std::streamsize size = nBlocks*this->blockSize;
	std::streampos reach = blockOffset+nBlocks-((std::streampos)1);
	if(reach >= this->inNBlocks-1) {
		// this is the last block write (at the end of the file)
		size = this->removePadding(data, size, cutBytes);
		if(this->randomAccessNBytes != NO_RANDOM_ACCESS) {
			// Only write selected random access bytes
			size = this->randomAccessNBytes-((blockOffset-this->beginBlock)*this->blockSize);
		}
	} else if(reach >= this->getEndBlock()) {
		// this is the last block write (limited by random access this->end)
		if(this->randomAccessNBytes != NO_RANDOM_ACCESS) {
			size = this->randomAccessNBytes-((blockOffset-this->beginBlock)*this->blockSize);
			DEV_TRACE(boost::format("outFileWrite size reach random access endblock = %llu-((%llu-%llu)*%llu) = %llu")
					% this->randomAccessNBytes % blockOffset % this->beginBlock % this->blockSize
					% size);
		}
	}
	std::streampos byteOffset = blockOffset*this->blockSize;
	if(this->begin != 0) {
		// When random access we satart writing at
		//  the begining of the output file.
		byteOffset -= this->begin;
		assert(byteOffset >= 0);

		if(blockOffset <= this->getBeginBlock()) {
			assert(blockOffset == this->getBeginBlock());
			// Only write selected random access bytes
			data += this->randomAccessBeginOffset;
			size -= this->randomAccessBeginOffset;
		} else  {
			byteOffset -= this->randomAccessBeginOffset;
			assert(byteOffset >= 0);
		}
	}
#ifdef DEVEL
	std::stringstream stream;
	stream << boost::format("outFileWriteBytes data (size: %llu, byteOffset: %llu)") % size % byteOffset;
	hexdump(stream.str(),data,size);
#endif
	this->outFileWriteBytes(data, size, byteOffset);
}

std::streamsize paracrypt::BlockIO::applyPadding(unsigned char* data, std::streamsize dataSize, std::streamsize desiredSize)
{
	std::streamsize paddingSize = desiredSize-dataSize;
	unsigned char* padding = data+dataSize;
	switch(this->paddingType) {
		case UNPADDED:
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
	return paddingSize;
}

std::streamsize paracrypt::BlockIO::removePadding(unsigned char* data, std::streamsize dataSize, std::streamsize cutBytes)
{
	std::streamsize unpaddedSize = dataSize;
	if(dataSize > 0) {
		unsigned char* ptr = data+(dataSize-1);
		switch(this->paddingType) {
			case UNPADDED:
				unpaddedSize -= cutBytes;
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

std::streampos paracrypt::BlockIO::getBeginBlock()
{
	return this->beginBlock;
}

std::streampos paracrypt::BlockIO::getEnd()
{
	return this->end;
}

std::streampos paracrypt::BlockIO::getEndBlock()
{
	return this->endBlock;
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

std::streamoff paracrypt::BlockIO::getRandomAccessBeginOffset()
{
	return this->randomAccessBeginOffset;
}

std::streamsize paracrypt::BlockIO::getRandomAccessNBytes()
{
	return this->randomAccessNBytes;
}

} /* namespace paracrypt */
