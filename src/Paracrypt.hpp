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

#ifndef PARACRYPT_HPP_
#define PARACRYPT_HPP_

#include "Launcher.hpp"
#include "cipher/BlockCipher.hpp"
#include <fstream>
#include <string>

namespace paracrypt {

	typedef enum cipher {
		AES128,
		AES192,
		AES256,
	} cipher_t;

	typedef struct config {
		cipher_t c,
		paracrypt::Launcher::operation_t op,
		std::string inFile,
		std::string outFile,
		const unsigned char key[],
		int key_bits,
		bool constantKey,
		bool constantTables,
		paracrypt::BlockCipher::Mode m,
		const unsigned char iv[],
		int ivBits,
		bool outOfOrder,
		std::streampos begin,
		std::streampos end

		node(){};
		node(
				cipher_t c,
				paracrypt::Launcher::operation_t op,
				std::string inFile,
				std::string outFile,
				const unsigned char key[],
				int key_bits,
				paracrypt::BlockCipher::Mode m,
			){
			this->c = c;
			this-> op = op;
			this->inFile = inFile;
			this->outFile = outFile;
			this->key = key;
			this->key_bits = key_bits;
			this->m = m;
			this->constantKey = true;
			this->constantTables = true;
			this->outOfOrder = false;
			this->begin = NO_RANDOM_ACCESS;
			this->end = NO_RANDOM_ACCESS;
		};

		void setIV(const unsigned char iv[], int ivBits) {
			this->iv = iv;
			this->ivBits = ivBits;
		}

		void enableOutOfOrder() {
			this->outOfOrder = true;
		}

		void randomAccess(std::streampos begin) {
			this->outOfOrder = true;
		}

	} config_t;

	void paracrypt(config c);
}

#endif /* PARACRYPT_HPP_ */
