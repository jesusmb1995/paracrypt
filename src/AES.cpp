#include "AES.hpp"

paracrypt::AES::AES()
{
    this->roundKeys = malloc(sizeof(AES_KEY));
}

paracrypt::AES::~AES()
{
    free(this->roundKeys);
}

int paracrypt::AES::setKey(const unsigned char key[], int bits)
{
    AES_set_encrypt_key(key, bits, this->roundKeys);
    return 0;
}

// Warning: If we destruct the object who owns the key 
//  we will point to nowhere
int paracrypt::AES::setKey(AES_KEY * expandedKey)
{
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
