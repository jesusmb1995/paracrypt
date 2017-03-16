#include "BlockCipher.hpp"

namespace paracrypt {

    class AES:public BlockCipher {
#define AES_STATE_SIZE 128
#define AES_ROUND_KEY_SIZE AES_STATE_SIZE
#define AES_BLOCK_SIZE AES_STATE_SIZE

      private:
	int roundKeys[][AES_ROUND_KEY_SIZE];
      public:
	 virtual int encrypt(char in[], char out[], int n_blocks)
	    = 0;
	virtual int decrypt(char in[], char out[], int n_blocks)
	    = 0;
	int setKey(char key[], int bits);
	int setBlockSize(int bits);
    };

}
