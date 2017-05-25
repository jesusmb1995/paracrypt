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

#include "BlockCipher.hpp"

paracrypt::BlockCipher::BlockCipher()
{
	this->mode = ECB;
	this->enBlockOffset = 0;
	this->deBlockOffset = 0;
}

paracrypt::BlockCipher::BlockCipher(BlockCipher* cipher)
{
	this->mode = cipher->mode;
}

paracrypt::BlockCipher::~BlockCipher()
{}

int paracrypt::BlockCipher::encrypt(const unsigned char in[],
			      const unsigned char out[], std::streamsize n_blocks)
{
	this->enBlockOffset += n_blocks;
	this->lastOp = ENCRYPT;
	return 0;
}

int paracrypt::BlockCipher::decrypt(const unsigned char in[],
			    const unsigned char out[], std::streamsize n_blocks)
{
	this->deBlockOffset += n_blocks;
	this->lastOp = DECRYPT;
	return 0;
}

void paracrypt::BlockCipher::setMode(Mode m)
{
	this->mode = m;
}

paracrypt::BlockCipher::Mode paracrypt::BlockCipher::getMode()
{
	return this->mode;
}

std::streamoff paracrypt::BlockCipher::getCurrentBlockOffset()
{
	std::streamoff lastOff;
	switch(this->lastOp) {
	case ENCRYPT:
		lastOff = this->enBlockOffset;
		break;
	case DECRYPT:
		lastOff = this->deBlockOffset;
		break;
	}
	return lastOff;
}

std::streamoff paracrypt::BlockCipher::getEncryptBlockOffset()
{
	return this->enBlockOffset;
}

std::streamoff paracrypt::BlockCipher::getDecryptBlockOffset()
{
	return this->deBlockOffset;
}

void paracrypt::BlockCipher::setInitialBlockOffset(std::streamoff offset)
{
	this->enBlockOffset = offset;
	this->deBlockOffset = offset;
}
