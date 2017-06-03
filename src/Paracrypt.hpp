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

#include <fstream>
#include <string>

// Paracrypt API for the paracrypt.so library

namespace paracrypt {

	typedef enum cipher {
		// AES /////////////
		AES16B,
		AES8B,
		AES4B,
		AES1B,

		// TODO implement other ciphers
	} cipher_t;

	// TODO support OpenCL versions

	typedef enum mode {
		ECB = 0,
		CBC = 1,
		CFB = 2,
		CTR = 3,
		//GCM = 4, // TODO this mode has yet to be implemented
    } mode_t;

	typedef enum operation {
		ENCRYPT = 0,
		DECRYPT = 1,
	} operation_t;

	typedef enum verbosity {
		QUIET = 0,
		WARNING = 1,
		INFO = 2,
		DBG = 3,
		TRACE = 4
    } verbosity_t;

	// TODO support SimpleIO and not only async IO

	// TODO permit to set the desired logging level (info, waring, err, fatal, etc.)

	// TODO in the library version do not write err message directly and end, throw
	//  an exception instead.

	typedef std::streampos random_access_pos_t;

#ifndef NO_RANDOM_ACCESS
	#define NO_RANDOM_ACCESS -1
#endif

	typedef struct config {
		cipher_t c;
		operation_t op;
		std::string inFile;
		std::string outFile;
		unsigned char* key;
		int key_bits;
		bool constantKey;
		bool constantTables;
		mode_t m;
		unsigned char* iv;
		int ivBits;
		bool outOfOrder;
		random_access_pos_t begin;
		random_access_pos_t end;
		verbosity_t verbosity;

		config(
				cipher_t c,
				operation_t op,
				std::string inFile,
				std::string outFile,
				unsigned char* key,
				int key_bits,
				mode_t m
			){
			this->c = c;
			this-> op = op;
			this->inFile = inFile;
			this->outFile = outFile;
			this->key = key;
			this->key_bits = key_bits;
			this->m = m;
			this->iv = NULL;
			this->ivBits = 0;
			this->constantKey = true;
			this->constantTables = true;
			this->outOfOrder = false;
			this->begin = NO_RANDOM_ACCESS;
			this->end = NO_RANDOM_ACCESS;
			this->verbosity = WARNING;
		};

		void setIV(unsigned char* iv, int ivBits) {
			this->iv = iv;
			this->ivBits = ivBits;
		}

		void enableOutOfOrder() {
			this->outOfOrder = true;
		}

		void disableConstantKey() {
			this->constantKey = false;
		}

		void disableConstantTables() {
			this->constantTables = false;
		}

		// begin and end bytes are included
		void setRandomAccess(random_access_pos_t begin, random_access_pos_t end) {
			this->begin = begin;
			this->end = end;
		}

		void setBeginByte(random_access_pos_t begin) {
			this->begin = begin;
		}

		void setEndByte(random_access_pos_t end) {
			this->end = end;
		}

		void setVerbosity(verbosity_t verbosity) {
			this->verbosity = verbosity;
		}

	} config_t;

	void exec(config_t c);
}

#endif /* PARACRYPT_HPP_ */
