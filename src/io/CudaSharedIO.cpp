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

#include "CudaSharedIO.hpp"
#include "CudaPinned.hpp"

namespace paracrypt {

CudaSharedIO::CudaSharedIO(
		std::string inFilename,
		std::string outFilename,
		unsigned int blockSize,
		unsigned int nChunks,
		rlim_t bufferSizeLimit,
		std::streampos begin,
		std::streampos end
) : paracrypt::SharedIO::SharedIO(inFilename, outFilename, blockSize, begin, end)
{
	this->pin = new CudaPinned();
	this->construct(nChunks, bufferSizeLimit);
}

CudaSharedIO::~CudaSharedIO()
{
	DEV_TRACE("Deleting CudaSharedIO.\n");
	this->destruct();
	delete this->pin;
}

Pinned* paracrypt::CudaSharedIO::getPinned()
{
	return this->pin;
}

} /* namespace paracrypt */
