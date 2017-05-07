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

#ifndef LAUNCHER_HPP_
#define LAUNCHER_HPP_

#include "../device/GPUCipherDevice.hpp"
#include "../BlockCipher.hpp"

namespace paracrypt {

class launcher {
public:
	virtual launcher(std::string inFilename, std::string outFilename, BlockCipher cipher, GPUCipherDevice devices[]);
	virtual ~launcher();
	virtual int encrypt(const unsigned char in[], const unsigned char out[], int n_blocks) = 0;
	virtual int decrypt(const unsigned char in[], const unsigned char out[], int n_blocks) = 0;
};

} /* namespace paracrypt */

#endif /* LAUNCHER_HPP_ */
