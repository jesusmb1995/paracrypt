#pragma once

namespace paracrypt {

    class BlockCipher {
      public:
	virtual ~ BlockCipher() {
	} virtual int encrypt(const unsigned char in[],
			      const unsigned char out[], int n_blocks) = 0;
	virtual int decrypt(const unsigned char in[],
			    const unsigned char out[], int n_blocks) = 0;
	virtual int setKey(const unsigned char key[], int bits) = 0;
	virtual int setBlockSize(int bits) = 0;
    };

}
