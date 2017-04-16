#pragma once

#include "../BlockCipher.hpp"
#include "../openssl/AES_key_schedule.h"

namespace paracrypt {

    class AES:public BlockCipher {
#define AES_STATE_SIZE 128
#define AES_BLOCK_SIZE AES_STATE_SIZE
#define AES_STATE_SIZE_B 16
#define AES_BLOCK_SIZE_B AES_STATE_SIZE_B

      private:
    unsigned char* key;
    int keyBits;
	AES_KEY * enRoundKeys;
	AES_KEY * deRoundKeys;
	bool enKeyPropietary;
	bool deKeyPropietary;
      protected:
    virtual int getThreadsPerCipherBlock() = 0;
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
	int setEncryptionKey(AES_KEY * expandedKey);
	int setDecryptionKey(AES_KEY * expandedKey);
	AES_KEY *getEncryptionExpandedKey();
	AES_KEY *getDecryptionExpandedKey();
	int setBlockSize(int bits);
    };

}
