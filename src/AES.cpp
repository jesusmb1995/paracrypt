#include "AES.hpp"
#include <cstddef>
#include <stdlib.h>

paracrypt::AES::AES()
{
	this->roundKeys = NULL;
	this->keyPropietary = false;
}

paracrypt::AES::~AES()
{
	if(this->keyPropietary && this->roundKeys != NULL)
		free(this->roundKeys);
}

int paracrypt::AES::setKey(const unsigned char key[], int bits)
{
	if(this->roundKeys == NULL) {
		this->roundKeys = (AES_KEY*) malloc(sizeof(AES_KEY));
		this->keyPropietary = true;
	}
    AES_set_encrypt_key(key, bits, this->roundKeys);
    return 0;
}

// Warning: If we destruct the object who owns the key 
//  we will point to nowhere
int paracrypt::AES::setKey(AES_KEY * expandedKey)
{
	if(this->keyPropietary && this->roundKeys != NULL)  {
		free(this->roundKeys);
		this->keyPropietary = false;
	}
    this->roundKeys = expandedKey;
    return 0;
}

AES_KEY *paracrypt::AES::getExpandedKey()
{
    return this->roundKeys;
}

int paracrypt::AES::setBlockSize(int bits)
{
    return 0;
}
