#pragma once

#include "AES.hpp"
#include "CudaAES.hpp"

namespace paracrypt {

    class CudaEcbAES16B:public CudaAES {
      public:
	int encrypt(const unsigned char in[],
		    const unsigned char out[], int n_blocks);
	int decrypt(const unsigned char in[],
		    const unsigned char out[], int n_blocks);
    };

}
