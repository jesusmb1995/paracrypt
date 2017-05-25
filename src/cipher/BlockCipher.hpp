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

#include <fstream>

namespace paracrypt {

    class BlockCipher {
      public:
    BlockCipher();
    BlockCipher(BlockCipher* cipher);
	virtual ~BlockCipher();
	virtual int encrypt(const unsigned char in[],
			      const unsigned char out[], std::streamsize n_blocks);
	virtual int decrypt(const unsigned char in[],
			    const unsigned char out[], std::streamsize n_blocks);
	virtual int setKey(const unsigned char key[], int bits) = 0;
	virtual int setBlockSize(int bits) = 0;
	virtual unsigned int getBlockSize() = 0;

	virtual void setIV(const unsigned char iv[], int bits) = 0;
	virtual unsigned char* getIV() = 0;

	typedef enum Mode {
		ECB = 0,
		CBC = 1,
		CFB = 2,
		CTR = 3,
		GCM = 4,
    } Mode;
	void setMode(Mode m);
	Mode getMode();

	std::streamoff getCurrentBlockOffset();
	std::streamoff getEncryptBlockOffset();
	std::streamoff getDecryptBlockOffset();
	void setInitialBlockOffset(std::streamoff offset);

	private:
		Mode mode;
		typedef enum LastOperation {
			ENCRYPT = 0,
			DECRYPT = 1,
		} LastOperation;
		LastOperation lastOp;
		std::streamoff enBlockOffset;
		std::streamoff deBlockOffset;

    };
}
