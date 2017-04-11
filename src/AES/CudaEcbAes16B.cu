#include "CudaEcbAes16B.cuh"

//#define aes_add_16B_round_key \
//( \
//		data_u32_w1, data_u32_w2, data_u32_w3, data_u32_w4 \
//		key_u32_w1, key_u32_w1, key_u32_w1, key_u32_w1 \
//) \
//{ \
//	(data_u32_w1) = (data_u32_w1) ^ (key_u32_w1); \
//	(data_u32_w2) = (data_u32_w2) ^ (key_u32_w2); \
//	(data_u32_w3) = (data_u32_w3) ^ (key_u32_w3); \
//	(data_u32_w4) = (data_u32_w4) ^ (key_u32_w4); \
//}

//__device__ cuda_aes_ttable

//// TODO inline y no guardar/acceder a memoria
//// recibir directamente los w1,w2,w3,w4 de la
//// clave y del state
////
//// Ver codigo objeto tras compilar
////
//// http://docs.nvidia.com/cuda/cuda-binary-utilities/#cuobjdump
//// cuobjdumo extrae codigo objeto
//__device__ inline void cuda_ecb_aes_16b__add_round_key(
//						uint32_t data_w1,
//						uint32_t data_w2,
//						uint32_t data_w3,
//						uint32_t data_w4,
//						uint32_t key_w1,
//						uint32_t key_w2,
//						uint32_t key_w3,
//						uint32_t key_w4
//						)
//{
//	data_w1 =
//
//	int iBlock = blockIdx.x * blockDim.x;
//
//	#pragma unroll
//	for(int w = 0; w < 4; w++) {
//		uint32_t* data_word_ptr = ((uint32_t*)data)+iBlock+w;
//		uint32_t data_word = (*data_word_ptr);
//	    uint32_t key_word = ((uint32_t*)expanded_key)[iBlock+w];
//	    (*data_word_ptr) = key_word ^ data_word;
//	}
//}

__global__ void cuda_ecb_aes_16b_encrypt_kernel(
						unsigned char data[],
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
//    cuda_ecb_aes_16b_encrypt_kernel <<< gridSize,
//	threadsPerBlock >>> (data, n_blocks, expanded_key, rounds);
}


void cuda_ecb_aes_16b_decrypt(int gridSize, int threadsPerBlock,
			      unsigned char data[], int n_blocks,
			      unsigned char expanded_key[], int rounds)
{
//    cuda_ecb_aes_16b_decrypt_kernel <<< gridSize,
//	threadsPerBlock >>> (data, n_blocks, expanded_key, rounds);
}

__global__ void __cuda_ecb_aes128_16b_encrypt__(
		  uint32_t* d,
	  	  uint32_t* k,
	  	  uint32_t* T0,
	  	  uint32_t* T1,
	  	  uint32_t* T2,
	  	  uint32_t* T3
    )
{
	int p = ((blockIdx.x * blockDim.x) + threadIdx.x)*4;
	uint32_t s0,s1,s2,s3,t0,t1,t2,t3;

    /*
     * map byte array block to cipher state
     * and add initial round key:
     */
	s0 = d[p]   ^ k[0];
	s1 = d[p+1] ^ k[1];
	s2 = d[p+2] ^ k[2];
	s3 = d[p+3] ^ k[3];

	// 8 rounds - in each loop we do two rounds
	#pragma unroll
	for(int r2 = 0; r2 < 4; r2++) {
	    t0 =
	        T0[(s0      ) & 0xff] ^
	        T1[(s1 >>  8) & 0xff] ^
	        T2[(s2 >> 16) & 0xff] ^
	        T3[(s3 >> 24)       ] ^
	        k[(r2*8)  ];
	    t1 =
	        T0[(s1      ) & 0xff] ^
	        T1[(s2 >>  8) & 0xff] ^
	        T2[(s3 >> 16) & 0xff] ^
	        T3[(s0 >> 24)       ] ^
	        k[(r2*8)+1];
	    t2 =
	        T0[(s2      ) & 0xff] ^
	        T1[(s3 >>  8) & 0xff] ^
	        T2[(s0 >> 16) & 0xff] ^
	        T3[(s1 >> 24)       ] ^
	        k[(r2*8)+2];
	    t3 =
	        T0[(s3      ) & 0xff] ^
	        T1[(s0 >>  8) & 0xff] ^
	        T2[(s1 >> 16) & 0xff] ^
	        T3[(s2 >> 24)       ] ^
	        k[(r2*8)+3];

	    s0 =
	        T0[(t0      ) & 0xff] ^
	        T1[(t1 >>  8) & 0xff] ^
	        T2[(t2 >> 16) & 0xff] ^
	        T3[(t3 >> 24)       ] ^
	        k[(r2*8)+4];
	    s1 =
	        T0[(t1      ) & 0xff] ^
	        T1[(t2 >>  8) & 0xff] ^
	        T2[(t3 >> 16) & 0xff] ^
	        T3[(t0 >> 24)       ] ^
	        k[(r2*8)+5];
	    s2 =
	        T0[(t2      ) & 0xff] ^
	        T1[(t3 >>  8) & 0xff] ^
	        T2[(t0 >> 16) & 0xff] ^
	        T3[(t1 >> 24)       ] ^
	        k[(r2*8)+6];
	    s3 =
	        T0[(t3      ) & 0xff] ^
	        T1[(t0 >>  8) & 0xff] ^
	        T2[(t1 >> 16) & 0xff] ^
	        T3[(t2 >> 24)       ] ^
	        k[(r2*8)+7];
	}

    t0 =
        T0[(s0      ) & 0xff] ^
        T1[(s1 >>  8) & 0xff] ^
        T2[(s2 >> 16) & 0xff] ^
        T3[(s3 >> 24)       ] ^
        k[36];
    t1 =
        T0[(s1      ) & 0xff] ^
        T1[(s2 >>  8) & 0xff] ^
        T2[(s3 >> 16) & 0xff] ^
        T3[(s0 >> 24)       ] ^
        k[37];
    t2 =
        T0[(s2      ) & 0xff] ^
        T1[(s3 >>  8) & 0xff] ^
        T2[(s0 >> 16) & 0xff] ^
        T3[(s1 >> 24)       ] ^
        k[38];
    t3 =
        T0[(s3      ) & 0xff] ^
        T1[(s0 >>  8) & 0xff] ^
        T2[(s1 >> 16) & 0xff] ^
        T3[(s2 >> 24)       ] ^
        k[39];

    // last round - save result
    s0 =
        (T0[(t0      ) & 0xff] & 0x000000ff) ^
        (T1[(t1 >>  8) & 0xff] & 0x0000ff00) ^
        (T2[(t2 >> 16) & 0xff] & 0x00ff0000) ^
        (T3[(t3 >> 24)       ] & 0xff000000) ^
        k[40];
    d[p] = s0;
    s1 =
        (T0[(t1      ) & 0xff] & 0x000000ff) ^
        (T1[(t2 >>  8) & 0xff] & 0x0000ff00) ^
        (T2[(t3 >> 16) & 0xff] & 0x00ff0000) ^
        (T3[(t0 >> 24)       ] & 0xff000000) ^
        k[41];
    d[p+1] = s1;
    s2 =
        (T0[(t2      ) & 0xff] & 0x000000ff) ^
        (T1[(t3 >>  8) & 0xff] & 0x0000ff00) ^
        (T2[(t0 >> 16) & 0xff] & 0x00ff0000) ^
        (T3[(t1 >> 24)       ] & 0xff000000) ^
        k[42];
    d[p+2] = s2;
    s3 =
        (T0[(t3      ) & 0xff] & 0x000000ff) ^
        (T1[(t0 >>  8) & 0xff] & 0x0000ff00) ^
        (T2[(t1 >> 16) & 0xff] & 0x00ff0000) ^
        (T3[(t2 >> 24)       ] & 0xff000000) ^
        k[43];
    d[p+3] = s3;
}

void cuda_ecb_aes128_16b_encrypt(
		  	  int gridSize,
		  	  int threadsPerBlock,
		  	  unsigned char data[],
		  	  uint32_t* expanded_key,
		  	  uint32_t* deviceTe0,
		  	  uint32_t* deviceTe1,
		  	  uint32_t* deviceTe2,
		  	  uint32_t* deviceTe3
	      )
{
	__cuda_ecb_aes128_16b_encrypt__<<<gridSize,threadsPerBlock>>>(
			gridSize,
			threadsPerBlock,
			(uint32_t*)data,
			key,
	   		deviceTe0,
	   		deviceTe1,
	   		deviceTe2,
	   		deviceTe3
	);
}