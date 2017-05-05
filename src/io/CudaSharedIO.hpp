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

#ifndef CUDASHAREDIO_HPP_
#define CUDASHAREDIO_HPP_

#include "SharedIO.hpp"

namespace paracrypt {

class CudaSharedIO: public SharedIO {
private:
	Pinned* pin;
protected:
	Pinned* getPinned();
public:
	CudaSharedIO(
			std::string inFilename,
			std::string outFilename,
			unsigned int blockSize,
			unsigned int nChunks,
			rlim_t bufferSizeLimit = AUTO_IO_BUFFER_LIMIT,
			std::streampos begin = NO_RANDOM_ACCESS,
			std::streampos end = NO_RANDOM_ACCESS
	);
	~CudaSharedIO();
};

} /* namespace paracrypt */

#endif /* CUDASHAREDIO_HPP_ */
