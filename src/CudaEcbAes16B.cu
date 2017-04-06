#include "CudaEcbAes16B.cuh"

// TODO inline y no guardar/acceder a memoria
// recibir directamente los w1,w2,w3,w4 de la
// clave y del state
//
// Ver codigo objeto tras compilar
//
// http://docs.nvidia.com/cuda/cuda-binary-utilities/#cuobjdump
// cuobjdumo extrae codigo objeto
__device__ inline void cuda_ecb_aes_16b__add_round_key(unsigned char data[],
						int n_blocks,
						unsigned char expanded_key[])
{
	int iBlock = blockIdx.x * blockDim.x;

	#pragma unroll
	for(int w = 0; w < 4; w++) {
		uint32_t* data_word_ptr = ((uint32_t*)data)+iBlock+w;
		uint32_t data_word = (*data_word_ptr);
	    uint32_t key_word = ((uint32_t*)expanded_key)[iBlock+w];
	    (*data_word_ptr) = key_word ^ data_word;
	}
}

__global__ void cuda_ecb_aes_16b_encrypt_kernel(unsigned char data[],
						int n_blocks,
						unsigned char expanded_key[])
{


}


__global__ void cuda_ecb_aes_16b_decrypt_kernel(unsigned char data[],
						int n_blocks,
						unsigned char expanded_key[])
{


}

void cuda_ecb_aes_16b_encrypt(int gridSize, int threadsPerBlock,
			      unsigned char data[], int n_blocks,
			      unsigned char expanded_key[], int rounds)
{
    cuda_ecb_aes_16b_encrypt_kernel <<< gridSize,
	threadsPerBlock >>> (data, n_blocks, expanded_key, rounds);
}


void cuda_ecb_aes_16b_decrypt(int gridSize, int threadsPerBlock,
			      unsigned char data[], int n_blocks,
			      unsigned char expanded_key[], int rounds)
{
    cuda_ecb_aes_16b_decrypt_kernel <<< gridSize,
	threadsPerBlock >>> (data, n_blocks, expanded_key, rounds);
}
