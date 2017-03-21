#include "AES.hpp"

namespace paracrypt {

    class AES16B:public AES {
      public:
	encrypt(char in[], char out[], int n_blocks);
	 decrypt(char in[], char out[], int n_blocks);
    };

}
