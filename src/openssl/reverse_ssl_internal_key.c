#include "reverse_ssl_internal_key.h"
#include "aes_locl.h"

int AES_get_key(uint32_t* store, AES_KEY* internal_key) {
	for(int i = 0; i < internal_key->rounds + 1; i++)
		PUTU32(store+i,internal_key->rd_key[i]);
	return 0;
}
