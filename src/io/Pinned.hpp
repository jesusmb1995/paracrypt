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

#ifndef PINNED_H_
#define PINNED_H_

#include <fstream>
#include <sys/resource.h>

#define BUFFERS_RAM_USAGE_FACTOR 0.67 // we do not want to use all ram only for IO buffers

namespace paracrypt {

class Pinned {
public:
	virtual ~Pinned(){};
	virtual bool alloc(void** ptr, std::streampos size) = 0;
	virtual void free(void* ptr) = 0;
	static const rlim_t getAvaliablePinneableRAM();
	static const rlim_t getReasonablyBigChunkOfRam(rlim_t lim);
};

} /* namespace paracrypt */

#endif /* PINNED_H_ */
