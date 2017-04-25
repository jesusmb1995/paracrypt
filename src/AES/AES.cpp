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

#include "AES.hpp"
#include <cstddef>
#include <stdlib.h>
#include "../logging.hpp"
#include "../endianess.h"

paracrypt::AES::AES()
{
	this->key = NULL;
	this->keyBits = -1;
    this->enRoundKeys = NULL;
    this->deRoundKeys = NULL;
    this->enKeyPropietary = false;
    this->deKeyPropietary = false;
}

paracrypt::AES::~AES()
{
    if(this->enKeyPropietary && this->enRoundKeys != NULL) {
    	free(this->enRoundKeys);
    }
    if(this->deKeyPropietary && this->deRoundKeys != NULL) {
    	free(this->deRoundKeys);
    }
    free(this->key);
}

int paracrypt::AES::setKey(const unsigned char key[], int bits)
{
    if (this->key == NULL) {
    	this->keyBits = bits;
    	int bytes = bits/8;
    	this->key = (unsigned char*) malloc(bytes);
    	memcpy(this->key,key,bytes);
    }
    return 0;
}

// Warning: If we destruct the object who owns the key 
//  we will point to nowhere
int paracrypt::AES::setEncryptionKey(AES_KEY * expandedKey)
{
    if (this->enKeyPropietary && this->enRoundKeys != NULL) {
    	free(this->enRoundKeys);
    	this->enKeyPropietary = false;
    }
    this->enRoundKeys = expandedKey;
    return 0;
}

int paracrypt::AES::setDecryptionKey(AES_KEY * expandedKey)
{
    if (this->deKeyPropietary && this->deRoundKeys != NULL) {
    	free(this->deRoundKeys);
    	this->deKeyPropietary = false;
    }
    this->deRoundKeys = expandedKey;
    return 0;
}

AES_KEY *paracrypt::AES::getEncryptionExpandedKey()
{
	if(this->enRoundKeys == NULL) {
		this->enRoundKeys = (AES_KEY *) malloc(sizeof(AES_KEY));
		this->enKeyPropietary = true;
		AES_set_encrypt_key(key, this->keyBits, this->enRoundKeys);
		big(this->enRoundKeys->rd_key,this->enRoundKeys->rd_key,(this->enRoundKeys->rounds+1)*4);
	}
	return this->enRoundKeys;
}

AES_KEY *paracrypt::AES::getDecryptionExpandedKey()
{
	if(this->deRoundKeys == NULL) {
		this->deRoundKeys = (AES_KEY *) malloc(sizeof(AES_KEY));
		this->deKeyPropietary = true;
		AES_set_decrypt_key(key, this->keyBits, this->deRoundKeys);
		big(this->deRoundKeys->rd_key,this->deRoundKeys->rd_key,(this->deRoundKeys->rounds+1)*4);
	}
	return this->deRoundKeys;
}

int paracrypt::AES::setBlockSize(int bits)
{
    return 0;
}
