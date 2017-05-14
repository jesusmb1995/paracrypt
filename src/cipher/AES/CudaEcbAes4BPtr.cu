/*
 *  Copyright (C) 2017 Jesus Martin Berlanga. All Rights Reserved.
 *
 *  This file is part of Paracrypt.
 *
 *  Paracrypt is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  Paracrypt is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with Paracrypt.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "CudaEcbAes4BPtr.cuh"

__global__ void __cuda_ecb_aes_4b_ptr_encrypt__(
		  int n,
		  uint32_t* d,
	  	  uint32_t* k,
	  	  int key_bits,
	  	  uint32_t* T0,
	  	  uint32_t* T1,
	  	  uint32_t* T2,
	  	  uint32_t* T3
    )
{
	// Each block has its own shared memory
	// We have an state for each two threads
	extern __shared__ uint32_t state[];

	int bi = ((blockIdx.x * blockDim.x) + threadIdx.x); // section index
	const int s_size = blockDim.x/4;
	//__LOG_TRACE__("s_size => %d", s_size);
	uint32_t* s0 = state           ;
	uint32_t* s1 = state+(  s_size);
	uint32_t* s2 = state+(2*s_size);
	uint32_t* s3 = state+(3*s_size);
	uint32_t* t0 = state+(4*s_size);
	uint32_t* t1 = state+(5*s_size);
	uint32_t* t2 = state+(6*s_size);
	uint32_t* t3 = state+(7*s_size);

	int p = bi;
	int sti = threadIdx.x/4; //state index
	int ti = threadIdx.x%4; // block-thread index: 0, 1, 2 or 3 (4 threads per cipher-block)
	int valid_thread = bi < n*4;
	int key_index_sum = 0;

	uint8_t* s0p = (uint8_t*) &s0[sti];
	uint8_t* s1p = (uint8_t*) &s1[sti];
	uint8_t* s2p = (uint8_t*) &s2[sti];
	uint8_t* s3p = (uint8_t*) &s3[sti];
	uint8_t* t0p = (uint8_t*) &t0[sti];
	uint8_t* t1p = (uint8_t*) &t1[sti];
	uint8_t* t2p = (uint8_t*) &t2[sti];
	uint8_t* t3p = (uint8_t*) &t3[sti];

#if defined(DEBUG) && defined(DEVEL)
	if(valid_thread) {
    	__LOG_TRACE__("p %d: threadIx.x => %d",p,threadIdx.x);
    	__LOG_TRACE__("p %d: ti => %d",p,ti);
    }
#endif

	/*
	 * map byte array block to cipher state
	 * and add initial round key:
	 */
	if(valid_thread && ti == 0) {
		__LOG_TRACE__("p %d: d[0] => 0x%04x",p,d[p]);
		__LOG_TRACE__("p %d: k[0] => 0x%04x",p,k[0]);
		s0[sti] = d[p] ^ k[0];
		__LOG_TRACE__("p %d: s0 => 0x%04x",p,s0[sti]);
	}
	else if(valid_thread && ti == 1) {
		__LOG_TRACE__("p %d: d[1] => 0x%04x",p,d[p]);
		__LOG_TRACE__("p %d: k[1] => 0x%04x",p,k[1]);
		s1[sti] = d[p] ^ k[1];
		__LOG_TRACE__("p %d: s1 => 0x%04x",p,s1[sti]);
	}
	else if(valid_thread && ti == 2) {
		__LOG_TRACE__("p %d: d[2] => 0x%04x",p,d[p]);
		__LOG_TRACE__("p %d: k[2] => 0x%04x",p,k[2]);
		s2[sti] = d[p] ^ k[2];
		__LOG_TRACE__("p %d: s2 => 0x%04x",p,s2[sti]);
	}
	else if(valid_thread && ti == 3) {
		__LOG_TRACE__("p %d: d[3] => 0x%04x",p,d[p]);
		__LOG_TRACE__("p %d: k[3] => 0x%04x",p,k[3]);
		s3[sti] = d[p] ^ k[3];
		__LOG_TRACE__("p %d: s3 => 0x%04x",p,s3[sti]);
	}

	// 8 rounds - in each loop we do two rounds
	#pragma unroll
	for(int r2 = 1; r2 <= 4; r2++) {
		__syncthreads();
		if(valid_thread && ti == 0) {
			t0[sti] = T0[s0p[0]] ^ T1[s1p[1]] ^ T2[s2p[2]] ^ T3[s3p[3]] ^ k[(r2*8)-4];
			__LOG_TRACE__("p %d: t0 => 0x%04x",p,t0[sti]);

		}
		else if(valid_thread && ti == 1) {
		t1[sti] = T0[s1p[0]] ^ T1[s2p[1]] ^ T2[s3p[2]] ^ T3[s0p[3]] ^ k[(r2*8)-3];
		__LOG_TRACE__("p %d: t1 => 0x%04x",p,t1[sti]);
		}
		else if(valid_thread && ti == 2) {
			__LOG_TRACE__("p %d: (s0      ) & 0xff => 0x%04x",p,s0p[0]);
			__LOG_TRACE__("p %d: (s1 >>  8) & 0xff => 0x%04x",p,s1p[1]);
			__LOG_TRACE__("p %d: (s2 >> 16) & 0xff => 0x%04x",p,s2p[2]);
			__LOG_TRACE__("p %d: (s3 >> 24)        => 0x%04x",p,(s3[sti] >> 24));
			__LOG_TRACE__("p %d: T0[(s0      ) & 0xff] => 0x%04x",p,T0[s0p[0]]);
			__LOG_TRACE__("p %d: T1[(s1 >>  8) & 0xff] => 0x%04x",p,T1[s1p[1]]);
			__LOG_TRACE__("p %d: T2[(s2 >> 16) & 0xff] => 0x%04x",p,T2[s2p[2]]);
			__LOG_TRACE__("p %d: T3[(s3 >> 24)       ] => 0x%04x",p,T3[s3p[3]]);
			__LOG_TRACE__("p %d: k[%d] => 0x%04x",p,(r2*8)-2 , k[(r2*8)-2]);
			t2[sti] = T0[s2p[0]] ^ T1[s3p[1]] ^ T2[s0p[2]] ^ T3[s1p[3]] ^ k[(r2*8)-2];
			__LOG_TRACE__("p %d: t2 => 0x%04x",p,t2[sti]);
		}
		else if(valid_thread && ti == 3) {
			t3[sti] = T0[s3p[0]] ^ T1[s0p[1]] ^ T2[s1p[2]] ^ T3[s2p[3]] ^ k[(r2*8)-1];
			__LOG_TRACE__("p %d: t3 => 0x%04x",p,t3[sti]);
		}
		__syncthreads();
		if(valid_thread && ti == 0) {
			s0[sti] = T0[t0p[0]] ^ T1[t1p[1]] ^ T2[t2p[2]] ^ T3[t3p[3]] ^ k[(r2*8)  ];
			__LOG_TRACE__("p %d: s0 => 0x%04x",p,s0[sti]);

		}
		else if(valid_thread && ti == 1) {
			s1[sti] = T0[t1p[0]] ^ T1[t2p[1]] ^ T2[t3p[2]] ^ T3[t0p[3]] ^ k[(r2*8)+1];
			__LOG_TRACE__("p %d: s1 => 0x%04x",p,s1[sti]);
		}
		if(valid_thread && ti == 2) {
			s2[sti] = T0[t2p[0]] ^ T1[t3p[1]] ^ T2[t0p[2]] ^ T3[t1p[3]] ^ k[(r2*8)+2];
			__LOG_TRACE__("p %d: s2 => 0x%04x",p,s2[sti]);
		}
		if(valid_thread && ti == 3) {
			s3[sti] = T0[t3p[0]] ^ T1[t0p[1]] ^ T2[t1p[2]] ^ T3[t2p[3]] ^ k[(r2*8)+3];
			__LOG_TRACE__("p %d: s3 => 0x%04x",p,s3[sti]);
		}
	}

	if(key_bits >= 192) {
		key_index_sum = 8;
		__syncthreads();
		if(valid_thread && ti == 0) {
			t0[sti] = T0[s0p[0]] ^ T1[s1p[1]] ^ T2[s2p[2]] ^ T3[s3p[3]] ^ k[36];
			__LOG_TRACE__("p %d: t0 => 0x%04x",p,t0[sti]);
		}
		else if(valid_thread && ti == 1) {
			t1[sti] = T0[s1p[0]] ^ T1[s2p[1]] ^ T2[s3p[2]] ^ T3[s0p[3]] ^ k[37];
			__LOG_TRACE__("p %d: t1 => 0x%04x",p,t1[sti]);
		}
		else if(valid_thread && ti == 2) {
			t2[sti] = T0[s2p[0]] ^ T1[s3p[1]] ^ T2[s0p[2]] ^ T3[s1p[3]] ^ k[38];
			__LOG_TRACE__("p %d: t2 => 0x%04x",p,t2[sti]);
		}
		else if(valid_thread && ti == 3) {
			t3[sti] = T0[s3p[0]] ^ T1[s0p[1]] ^ T2[s1p[2]] ^ T3[s2p[3]] ^ k[39];
			__LOG_TRACE__("p %d: t3 => 0x%04x",p,t3[sti]);
		}

		__syncthreads();
		if(valid_thread && ti == 0) {
			s0[sti] = T0[t0p[0]] ^ T1[t1p[1]] ^ T2[t2p[2]] ^ T3[t3p[3]] ^ k[40];
			__LOG_TRACE__("p %d: s0 => 0x%04x",p,s0[sti]);
		}
		else if(valid_thread && ti == 1) {
			s1[sti] = T0[t1p[0]] ^ T1[t2p[1]] ^ T2[t3p[2]] ^ T3[t0p[3]] ^ k[41];
			__LOG_TRACE__("p %d: s1 => 0x%04x",p,s1[sti]);
		}
		else if(valid_thread && ti == 2) {
			s2[sti] = T0[t2p[0]] ^ T1[t3p[1]] ^ T2[t0p[2]] ^ T3[t1p[3]] ^ k[42];
			__LOG_TRACE__("p %d: s2 => 0x%04x",p,s2[sti]);
		}
		else if(valid_thread && ti == 3) {
			s3[sti] = T0[t3p[0]] ^ T1[t0p[1]] ^ T2[t1p[2]] ^ T3[t2p[3]] ^ k[43];
			__LOG_TRACE__("p %d: s3 => 0x%04x",p,s3[sti]);
		}

		if(key_bits == 256) {
			key_index_sum = 16;
			__syncthreads();
			if(valid_thread && ti == 0) {
				t0[sti] = T0[s0p[0]] ^ T1[s1p[1]] ^ T2[s2p[2]] ^ T3[s3p[3]] ^ k[44];
				__LOG_TRACE__("p %d: t0 => 0x%04x",p,t0[sti]);
			}
			else if(valid_thread && ti == 1) {
				t1[sti] = T0[s1p[0]] ^ T1[s2p[1]] ^ T2[s3p[2]] ^ T3[s0p[3]] ^ k[45];
				__LOG_TRACE__("p %d: t1 => 0x%04x",p,t1[sti]);
			}
			if(valid_thread && ti == 2) {
				t2[sti] = T0[s2p[0]] ^ T1[s3p[1]] ^ T2[s0p[2]] ^ T3[s1p[3]] ^ k[46];
				__LOG_TRACE__("p %d: t2 => 0x%04x",p,t2[sti]);
			}
			if(valid_thread && ti == 3) {
				t3[sti] = T0[s3p[0]] ^ T1[s0p[1]] ^ T2[s1p[2]] ^ T3[s2p[3]] ^ k[47];
				__LOG_TRACE__("p %d: t3 => 0x%04x",p,t3[sti]);
			}
			__syncthreads();
			if(valid_thread && ti == 0) {
				s0[sti] = T0[t0p[0]] ^ T1[t1p[1]] ^ T2[t2p[2]] ^ T3[t3p[3]] ^ k[48];
				__LOG_TRACE__("p %d: s0 => 0x%04x",p,s0[sti]);
			}
			else if(valid_thread && ti == 1) {
				s1[sti] = T0[t1p[0]] ^ T1[t2p[1]] ^ T2[t3p[2]] ^ T3[t0p[3]] ^ k[49];
				__LOG_TRACE__("p %d: s1 => 0x%04x",p,s1[sti]);
			}
			if(valid_thread && ti == 2) {
				s2[sti] = T0[t2p[0]] ^ T1[t3p[1]] ^ T2[t0p[2]] ^ T3[t1p[3]] ^ k[50];
				__LOG_TRACE__("p %d: s2 => 0x%04x",p,s2[sti]);
			}
			if(valid_thread && ti == 3) {
				s3[sti] =  T0[t3p[0]] ^ T1[t0p[1]] ^ T2[t1p[2]] ^ T3[t2p[3]] ^ k[51];
				__LOG_TRACE__("p %d: s3 => 0x%04x",p,s3[sti]);
			}
		}
	}

	__syncthreads();
	if(valid_thread && ti == 0) {
		t0[sti] = T0[s0p[0]] ^ T1[s1p[1]] ^ T2[s2p[2]] ^ T3[s3p[3]] ^ k[36+key_index_sum];
		__LOG_TRACE__("p %d: t0 => 0x%04x",p,t0[sti]);
	}
	if(valid_thread && ti == 1) {
		t1[sti] = T0[s1p[0]] ^ T1[s2p[1]] ^ T2[s3p[2]] ^ T3[s0p[3]] ^ k[37+key_index_sum];
		__LOG_TRACE__("p %d: t1 => 0x%04x",p,t1[sti]);
	}
	if(valid_thread && ti == 2) {
		t2[sti] = T0[s2p[0]] ^ T1[s3p[1]] ^ T2[s0p[2]] ^ T3[s1p[3]] ^ k[38+key_index_sum];
		__LOG_TRACE__("p %d: t2 => 0x%04x",p,t2[sti]);
	}
	if(valid_thread && ti == 3) {
		t3[sti] = T0[s3p[0]] ^ T1[s0p[1]] ^ T2[s1p[2]] ^ T3[s2p[3]] ^ k[39+key_index_sum];
		__LOG_TRACE__("p %d: t3 => 0x%04x",p,t3[sti]);
	}

	// last round - save result
	__syncthreads();
	if(valid_thread && ti == 0) {
		s0[sti] =
			(T2[t0p[0]] & 0x000000ff) ^
			(T3[t1p[1]] & 0x0000ff00) ^
			(T0[t2p[2]] & 0x00ff0000) ^
			(T1[t3p[3]] & 0xff000000) ^
			k[40+key_index_sum];
		__LOG_TRACE__("p %d: s0 => 0x%04x",p,s0[sti]);
		d[p] = s0[sti];
	}
	else if(valid_thread && ti == 1){
		s1[sti] =
			(T2[t1p[0]] & 0x000000ff) ^
			(T3[t2p[1]] & 0x0000ff00) ^
			(T0[t3p[2]] & 0x00ff0000) ^
			(T1[t0p[3]] & 0xff000000) ^
			k[41+key_index_sum];
		__LOG_TRACE__("p %d: s1 => 0x%04x",p,s1);
		d[p] = s1[sti];
	}
	if(valid_thread && ti == 2) {
		s2[sti] =
			(T2[t2p[0]] & 0x000000ff) ^
			(T3[t3p[1]] & 0x0000ff00) ^
			(T0[t0p[2]] & 0x00ff0000) ^
			(T1[t1p[3]] & 0xff000000) ^
			k[42+key_index_sum];
		__LOG_TRACE__("p %d: s2 => 0x%04x",p,s2[sti]);
		d[p] = s2[sti];
	}
	if(valid_thread && ti == 3) {
		s3[sti] =
			(T2[t3p[0]] & 0x000000ff) ^
			(T3[t0p[1]] & 0x0000ff00) ^
			(T0[t1p[2]] & 0x00ff0000) ^
			(T2[t2p[3]] & 0xff000000) ^
			k[43+key_index_sum];
		__LOG_TRACE__("p %d: s3 => 0x%04x",p,s3[sti]);
		d[p] = s3[sti];
	}
}

__global__ void __cuda_ecb_aes_4b_ptr_decrypt__(
		  int n,
		  uint32_t* d,
	  	  uint32_t* k,
	  	  int key_bits,
	  	  uint32_t* T0,
	  	  uint32_t* T1,
	  	  uint32_t* T2,
	  	  uint32_t* T3,
	  	  uint8_t* T4
    )
{
	// Each block has its own shared memory
	// We have an state for each two threads
	extern __shared__ uint32_t state[];

	int bi = ((blockIdx.x * blockDim.x) + threadIdx.x); // section index
	const int s_size = blockDim.x/4;
	//__LOG_TRACE__("s_size => %d", s_size);
	uint32_t* s0 = state           ;
	uint32_t* s1 = state+(  s_size);
	uint32_t* s2 = state+(2*s_size);
	uint32_t* s3 = state+(3*s_size);
	uint32_t* t0 = state+(4*s_size);
	uint32_t* t1 = state+(5*s_size);
	uint32_t* t2 = state+(6*s_size);
	uint32_t* t3 = state+(7*s_size);

	int p = bi;
	int sti = threadIdx.x/4; //state index
	int ti = threadIdx.x%4; // block-thread index: 0, 1, 2 or 3 (4 threads per cipher-block)
	int valid_thread = bi < n*4;
	int key_index_sum = 0;

	uint8_t* s0p = (uint8_t*) &s0[sti];
	uint8_t* s1p = (uint8_t*) &s1[sti];
	uint8_t* s2p = (uint8_t*) &s2[sti];
	uint8_t* s3p = (uint8_t*) &s3[sti];
	uint8_t* t0p = (uint8_t*) &t0[sti];
	uint8_t* t1p = (uint8_t*) &t1[sti];
	uint8_t* t2p = (uint8_t*) &t2[sti];
	uint8_t* t3p = (uint8_t*) &t3[sti];

#if defined(DEBUG) && defined(DEVEL)
	if(valid_thread) {
    	__LOG_TRACE__("p %d: threadIx.x => %d",p,threadIdx.x);
    	__LOG_TRACE__("p %d: ti => %d",p,ti);
    }
#endif

	/*
	 * map byte array block to cipher state
	 * and add initial round key:
	 */
	if(valid_thread && ti == 0) {
		__LOG_TRACE__("p %d: d[0] => 0x%04x",p,d[p]);
		__LOG_TRACE__("p %d: k[0] => 0x%04x",p,k[0]);
		s0[sti] = d[p] ^ k[0];
		__LOG_TRACE__("p %d: s0 => 0x%04x",p,s0[sti]);
	}
	else if(valid_thread && ti == 1) {
		__LOG_TRACE__("p %d: d[1] => 0x%04x",p,d[p]);
		__LOG_TRACE__("p %d: k[1] => 0x%04x",p,k[1]);
		s1[sti] = d[p] ^ k[1];
		__LOG_TRACE__("p %d: s1 => 0x%04x",p,s1[sti]);
	}
	else if(valid_thread && ti == 2) {
		__LOG_TRACE__("p %d: d[2] => 0x%04x",p,d[p]);
		__LOG_TRACE__("p %d: k[2] => 0x%04x",p,k[2]);
		s2[sti] = d[p] ^ k[2];
		__LOG_TRACE__("p %d: s2 => 0x%04x",p,s2[sti]);
	}
	else if(valid_thread && ti == 3) {
		__LOG_TRACE__("p %d: d[3] => 0x%04x",p,d[p]);
		__LOG_TRACE__("p %d: k[3] => 0x%04x",p,k[3]);
		s3[sti] = d[p] ^ k[3];
		__LOG_TRACE__("p %d: s3 => 0x%04x",p,s3[sti]);
	}

	// 8 rounds - in each loop we do two rounds
	#pragma unroll
	for(int r2 = 1; r2 <= 4; r2++) {
		__syncthreads();
		if(valid_thread && ti == 0) {
			t0[sti] = T0[s0p[0]] ^ T1[s3p[1]] ^ T2[s2p[2]] ^ T3[s1p[3]] ^ k[(r2*8)-4];
			__LOG_TRACE__("p %d: t0 => 0x%04x",p,t0[sti]);

		}
		else if(valid_thread && ti == 1) {
		t1[sti] = T0[s1p[0]] ^ T1[s0p[1]] ^ T2[s3p[2]] ^ T3[s2p[3]] ^ k[(r2*8)-3];
		__LOG_TRACE__("p %d: t1 => 0x%04x",p,t1[sti]);
		}
		else if(valid_thread && ti == 2) {
			__LOG_TRACE__("p %d: (s0      ) & 0xff => 0x%04x",p,s0p[0]);
			__LOG_TRACE__("p %d: (s1 >>  8) & 0xff => 0x%04x",p,s1p[1]);
			__LOG_TRACE__("p %d: (s2 >> 16) & 0xff => 0x%04x",p,s2p[2]);
			__LOG_TRACE__("p %d: (s3 >> 24)        => 0x%04x",p,(s3[sti] >> 24));
			__LOG_TRACE__("p %d: T0[(s0      ) & 0xff] => 0x%04x",p,T0[s0p[0]]);
			__LOG_TRACE__("p %d: T1[(s1 >>  8) & 0xff] => 0x%04x",p,T1[s1p[1]]);
			__LOG_TRACE__("p %d: T2[(s2 >> 16) & 0xff] => 0x%04x",p,T2[s2p[2]]);
			__LOG_TRACE__("p %d: T3[(s3 >> 24)       ] => 0x%04x",p,T3[s3p[3]]);
			__LOG_TRACE__("p %d: k[%d] => 0x%04x",p,(r2*8)-2 , k[(r2*8)-2]);
			t2[sti] = T0[s2p[0]] ^ T1[s1p[1]] ^ T2[s0p[2]] ^ T3[s3p[3]] ^ k[(r2*8)-2];
			__LOG_TRACE__("p %d: t2 => 0x%04x",p,t2[sti]);
		}
		else if(valid_thread && ti == 3) {
			t3[sti] = T0[s3p[0]] ^ T1[s2p[1]] ^ T2[s1p[2]] ^ T3[s0p[3]] ^ k[(r2*8)-1];
			__LOG_TRACE__("p %d: t3 => 0x%04x",p,t3[sti]);
		}
		__syncthreads();
		if(valid_thread && ti == 0) {
			s0[sti] = T0[t0p[0]] ^ T1[t3p[1]] ^ T2[t2p[2]] ^ T3[t1p[3]] ^
				k[(r2*8)  ];
			__LOG_TRACE__("p %d: s0 => 0x%04x",p,s0[sti]);

		}
		else if(valid_thread && ti == 1) {
			s1[sti] = T0[t1p[0]] ^ T1[t0p[1]] ^ T2[t3p[2]] ^ T3[t2p[3]] ^ k[(r2*8)+1];
			__LOG_TRACE__("p %d: s1 => 0x%04x",p,s1[sti]);
		}
		if(valid_thread && ti == 2) {
			s2[sti] = T0[t2p[0]] ^ T1[t1p[1]] ^ T2[t0p[2]] ^ T3[t3p[3]] ^ k[(r2*8)+2];
			__LOG_TRACE__("p %d: s2 => 0x%04x",p,s2[sti]);
		}
		if(valid_thread && ti == 3) {
			s3[sti] = T0[t3p[0]] ^ T1[t2p[1]] ^ T2[t1p[2]] ^ T3[t0p[3]] ^ k[(r2*8)+3];
			__LOG_TRACE__("p %d: s3 => 0x%04x",p,s3[sti]);
		}
	}

	if(key_bits >= 192) {
		key_index_sum = 8;
		__syncthreads();
		if(valid_thread && ti == 0) {
			t0[sti] = T0[s0p[0]] ^ T1[s3p[1]] ^ T2[s2p[2]] ^ T3[s1p[3]] ^ k[36];
			__LOG_TRACE__("p %d: t0 => 0x%04x",p,t0[sti]);
		}
		else if(valid_thread && ti == 1) {
			t1[sti] = T0[s1p[0]] ^ T1[s0p[1]] ^ T2[s3p[2]] ^ T3[s2p[3]] ^ k[37];
			__LOG_TRACE__("p %d: t1 => 0x%04x",p,t1[sti]);
		}
		else if(valid_thread && ti == 2) {
			t2[sti] = T0[s2p[0]] ^ T1[s1p[1]] ^ T2[s0p[2]] ^ T3[s3p[3]] ^ k[38];
			__LOG_TRACE__("p %d: t2 => 0x%04x",p,t2[sti]);
		}
		else if(valid_thread && ti == 3) {
			t3[sti] = T0[s3p[0]] ^ T1[s2p[1]] ^ T2[s1p[2]] ^ T3[s0p[3]] ^ k[39];
			__LOG_TRACE__("p %d: t3 => 0x%04x",p,t3[sti]);
		}

		__syncthreads();
		if(valid_thread && ti == 0) {
			s0[sti] = T0[t0p[0]] ^ T1[t3p[1]] ^ T2[t2p[2]] ^ T3[t1p[3]] ^ k[40];
			__LOG_TRACE__("p %d: s0 => 0x%04x",p,s0[sti]);
		}
		else if(valid_thread && ti == 1) {
			s1[sti] = T0[t1p[0]] ^ T1[t0p[1]] ^ T2[t3p[2]] ^ T3[t2p[3]] ^ k[41];
			__LOG_TRACE__("p %d: s1 => 0x%04x",p,s1[sti]);
		}
		else if(valid_thread && ti == 2) {
			s2[sti] = T0[t2p[0]] ^ T1[t1p[1]] ^ T2[t0p[2]] ^ T3[t3p[3]] ^ k[42];
			__LOG_TRACE__("p %d: s2 => 0x%04x",p,s2[sti]);
		}
		else if(valid_thread && ti == 3) {
			s3[sti] = T0[t3p[0]] ^ T1[t2p[1]] ^ T2[t1p[2]] ^ T3[t0p[3]] ^ k[43];
			__LOG_TRACE__("p %d: s3 => 0x%04x",p,s3[sti]);
		}

		if(key_bits == 256) {
			key_index_sum = 16;
			__syncthreads();
			if(valid_thread && ti == 0) {
				t0[sti] = T0[s0p[0]] ^ T1[s3p[1]] ^ T2[s2p[2]] ^ T3[s1p[3]] ^ k[44];
				__LOG_TRACE__("p %d: t0 => 0x%04x",p,t0[sti]);
			}
			else if(valid_thread && ti == 1) {
				t1[sti] = T0[s1p[0]] ^ T1[s0p[1]] ^ T2[s3p[2]] ^ T3[s2p[3]] ^ k[45];
				__LOG_TRACE__("p %d: t1 => 0x%04x",p,t1[sti]);
			}
			if(valid_thread && ti == 2) {
				t2[sti] = T0[s2p[0]] ^ T1[s1p[1]] ^ T2[s0p[2]] ^ T3[s3p[3]] ^ k[46];
				__LOG_TRACE__("p %d: t2 => 0x%04x",p,t2[sti]);
			}
			if(valid_thread && ti == 3) {
				t3[sti] = T0[s3p[0]] ^ T1[s2p[1]] ^ T2[s1p[2]] ^ T3[s0p[3]] ^ k[47];
				__LOG_TRACE__("p %d: t3 => 0x%04x",p,t3[sti]);
			}
			__syncthreads();
			if(valid_thread && ti == 0) {
				s0[sti] =T0[t0p[0]] ^ T1[t3p[1]] ^ T2[t2p[2]] ^ T3[t1p[3]] ^ k[48];
				__LOG_TRACE__("p %d: s0 => 0x%04x",p,s0[sti]);
			}
			else if(valid_thread && ti == 1) {
				s1[sti] = T0[t1p[0]] ^ T1[t0p[1]] ^ T2[t3p[2]] ^ T3[t2p[3]] ^ k[49];
				__LOG_TRACE__("p %d: s1 => 0x%04x",p,s1[sti]);
			}
			if(valid_thread && ti == 2) {
				s2[sti] = T0[t2p[0]] ^ T1[t1p[1]] ^ T2[t0p[2]] ^ T3[t3p[3]] ^ k[50];
				__LOG_TRACE__("p %d: s2 => 0x%04x",p,s2[sti]);
			}
			if(valid_thread && ti == 3) {
				s3[sti] = T0[t3p[0]] ^ T1[t2p[1]] ^ T2[t1p[2]] ^ T3[t0p[3]] ^ k[51];
				__LOG_TRACE__("p %d: s3 => 0x%04x",p,s3[sti]);
			}
		}
	}

	__syncthreads();
	if(valid_thread && ti == 0) {
		t0[sti] = T0[s0p[0]] ^ T1[s3p[1]] ^ T2[s2p[2]] ^ T3[s1p[3]] ^ k[36+key_index_sum];
		__LOG_TRACE__("p %d: t0 => 0x%04x",p,t0[sti]);
	}
	if(valid_thread && ti == 1) {
		t1[sti] = T0[s1p[0]] ^ T1[s0p[1]] ^ T2[s3p[2]] ^ T3[s2p[3]] ^ k[37+key_index_sum];
		__LOG_TRACE__("p %d: t1 => 0x%04x",p,t1[sti]);
	}
	if(valid_thread && ti == 2) {
		t2[sti] = T0[s2p[0]] ^ T1[s1p[1]] ^ T2[s0p[2]] ^ T3[s3p[3]] ^ k[38+key_index_sum];
		__LOG_TRACE__("p %d: t2 => 0x%04x",p,t2[sti]);
	}
	if(valid_thread && ti == 3) {
		t3[sti] = T0[s3p[0]] ^ T1[s2p[1]] ^ T2[s1p[2]] ^ T3[s0p[3]] ^ k[39+key_index_sum];
		__LOG_TRACE__("p %d: t3 => 0x%04x",p,t3[sti]);
	}

	// last round - save result
	__syncthreads();
	if(valid_thread && ti == 0) {
		s0[sti] =
			((uint32_t)T4[t0p[0]]      ) ^
			((uint32_t)T4[t3p[1]] <<  8) ^
			((uint32_t)T4[t2p[2]] << 16) ^
			((uint32_t)T4[t1p[3]] << 24) ^
			k[40+key_index_sum];
		__LOG_TRACE__("p %d: s0 => 0x%04x",p,s0[sti]);
		d[p] = s0[sti];
	}
	else if(valid_thread && ti == 1){
		s1[sti] =
			((uint32_t)T4[t1p[0]]      ) ^
			((uint32_t)T4[t0p[1]] <<  8) ^
			((uint32_t)T4[t3p[2]] << 16) ^
			((uint32_t)T4[t2p[3]] << 24) ^
			k[41+key_index_sum];
		__LOG_TRACE__("p %d: s1 => 0x%04x",p,s1);
		d[p] = s1[sti];
	}
	if(valid_thread && ti == 2) {
		s2[sti] =
			((uint32_t)T4[t2p[0]]      ) ^
			((uint32_t)T4[t1p[1]] <<  8) ^
			((uint32_t)T4[t0p[2]] << 16) ^
			((uint32_t)T4[t3p[3]] << 24) ^
			k[42+key_index_sum];
		__LOG_TRACE__("p %d: s2 => 0x%04x",p,s2[sti]);
		d[p] = s2[sti];
	}
	if(valid_thread && ti == 3) {
		s3[sti] =
			((uint32_t)T4[t3p[0]]      ) ^
			((uint32_t)T4[t2p[1]] <<  8) ^
			((uint32_t)T4[t1p[2]] << 16) ^
			((uint32_t)T4[t0p[3]] << 24) ^
			k[43+key_index_sum];
		__LOG_TRACE__("p %d: s3 => 0x%04x",p,s3[sti]);
		d[p] = s3[sti];
	}
}

void cuda_ecb_aes_4b_ptr_encrypt(
		  	  int gridSize,
		  	  int threadsPerBlock,
		  	  cudaStream_t stream,
		  	  int n_blocks,
		  	  unsigned char data[],
		  	  uint32_t* expanded_key,
		  	  int key_bits,
		  	  uint32_t* deviceTe0,
		  	  uint32_t* deviceTe1,
		  	  uint32_t* deviceTe2,
		  	  uint32_t* deviceTe3
	      )
{
	int shared_memory = threadsPerBlock*2*sizeof(uint32_t);
	__cuda_ecb_aes_4b_ptr_encrypt__<<<gridSize,threadsPerBlock,shared_memory,stream>>>(//*2>>>(
			n_blocks,
			(uint32_t*)data,
			expanded_key,
			key_bits,
	   		deviceTe0,
	   		deviceTe1,
	   		deviceTe2,
	   		deviceTe3
	);
}

void cuda_ecb_aes_4b_ptr_decrypt(
		  	  int gridSize,
		  	  int threadsPerBlock,
		  	  cudaStream_t stream,
		  	  int n_blocks,
		  	  unsigned char data[],
		  	  uint32_t* expanded_key,
		  	  int key_bits,
		  	  uint32_t* deviceTd0,
		  	  uint32_t* deviceTd1,
		  	  uint32_t* deviceTd2,
		  	  uint32_t* deviceTd3,
		  	  uint8_t* deviceTd4
	      )
{
	int shared_memory = threadsPerBlock*2*sizeof(uint32_t);
	__cuda_ecb_aes_4b_ptr_decrypt__<<<gridSize,threadsPerBlock,shared_memory,stream>>>(
			n_blocks,
			(uint32_t*)data,
			expanded_key,
			key_bits,
	   		deviceTd0,
	   		deviceTd1,
	   		deviceTd2,
	   		deviceTd3,
	   		deviceTd4
	);
}
