#include "AES.hpp"

namespace paracrypt {

    class CudaAES:public AES {
      public:
	int encrypt(char in[], char out[], int n_blocks);
	int decrypt(char in[], char out[], int n_blocks);
    };

}
