#include "endianess.h"
//#include "logging.hpp"
//#include <stdio.h>

 void big(uint32_t* little, uint32_t* store, int n) {
	int i;
	for(i=0;i<n;i++) {

	    //unsigned char *ptr = (unsigned char *)(little+i);
	    //store[i] = (ptr[0] << 24) | (ptr[1] << 16) | (ptr[2] << 8) | ptr[3];
		//store[i] = SWAP_ENDIAN(little+i);
		//PUTU32(store+i,little[i]);

		//LOG_DEBUG(boost::format("host: %x") % little[i]);
		//printf("host: %x\n", little[i]);
		store[i] = htobe32(little[i]);
		//printf("big-endian: %x\n", store[i]);
		//LOG_DEBUG(boost::format("big-endian: %x") % store[i]);
	}
}