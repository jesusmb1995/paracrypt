#include <stdint.h>

#define BLOCK_SIZE 128

__device__ void cuda_ecb_aes_16b__add_round_key(unsigned char data[],
						int n_blocks,
						unsigned char expanded_key[]);
__device__ void cuda_ecb_aes_16b__sub_bytes(unsigned char data[],
						int n_blocks,
						unsigned char expanded_key[]);
__device__ void cuda_ecb_aes_16b__shift_rows(unsigned char data[],
						int n_blocks,
						unsigned char expanded_key[]);
__global__ void cuda_ecb_aes_16b_encrypt_kernel(unsigned char data[],
						int n_blocks,
						unsigned char expanded_key[],
						int rounds);
__global__ void cuda_ecb_aes_16b_decrypt_kernel(unsigned char data[],
						int n_blocks,
						unsigned char expanded_key[],
						int rounds);
void cuda_ecb_aes_16b_encrypt(int gridSize, int threadsPerBlock,
			      unsigned char data[], int n_blocks,
			      unsigned char expanded_key[], int rounds);
void cuda_ecb_aes_16b_decrypt(int gridSize, int threadsPerBlock,
			      unsigned char data[], int n_blocks,
			      unsigned char expanded_key[], int rounds);
