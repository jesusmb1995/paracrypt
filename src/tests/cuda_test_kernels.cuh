#include <stdint.h>

typedef struct{
	uint32_t w1, w2, w3, w4;
} _16B;

__global__ void aes_add_16B_round_key_kernel
(
	uint32_t* data1,
	uint32_t* data2,
	uint32_t* data3,
	uint32_t* data4,
	uint32_t key1,
	uint32_t key2,
	uint32_t key3,
	uint32_t key4
);

_16B aes_add_16B_round_key_call(
		uint32_t data1,
		uint32_t data2,
		uint32_t data3,
		uint32_t data4,
		uint32_t key1,
		uint32_t key2,
		uint32_t key3,
		uint32_t key4
);
