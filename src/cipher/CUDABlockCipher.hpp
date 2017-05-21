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

#pragma once

#include "device/CUDACipherDevice.hpp"
#include "cipher/BlockCipher.hpp"

namespace paracrypt {

    class CUDABlockCipher: public BlockCipher {
      public:
    	CUDABlockCipher();
		virtual ~CUDABlockCipher() {}
		virtual void setDevice(CUDACipherDevice * device) = 0;
		virtual void malloc(unsigned int n_blocks, bool isInplace = true) = 0;	// Must be called to reserve enough space before encrypt/decrypt
		// returns -1 if an error has occurred
		virtual CUDACipherDevice *getDevice() = 0;
		virtual void waitFinish() = 0; // Wait for an async operation to finish
		virtual bool checkFinish() = 0; // The cipher has finished an async operation
    };

}
