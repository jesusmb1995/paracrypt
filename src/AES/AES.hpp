#pragma once

#include "../BlockCipher.hpp"
#include "../openssl/AES_key_schedule.h"

namespace paracrypt {

    class AES:public BlockCipher {
#define AES_STATE_SIZE 128
#define AES_BLOCK_SIZE AES_STATE_SIZE

      private:
	AES_KEY * roundKeys;
	bool keyPropietary;
      public:
	 AES();
	~AES();
	virtual int encrypt(const unsigned char in[],
			    const unsigned char out[], int n_blocks)
	    = 0;
	virtual int decrypt(const unsigned char in[],
			    const unsigned char out[], int n_blocks)
	    = 0;
	int setKey(const unsigned char key[], int bits);
	int setKey(AES_KEY * expandedKey);
	AES_KEY *getExpandedKey();
	int setBlockSize(int bits);
    };

}