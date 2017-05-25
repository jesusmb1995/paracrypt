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

#include "CudaAes1B.cuh"
#include "cuda_logging.cuh"

#define AES_1B_ROUND_KEY(state_pointer, n_state) \
{ \
	if(valid_thread && ti == (n_state)*4+0) { \
		__LOG_TRACE__("p %d: d[%d].0 => 0x%02x",p,d[p]); \
		__LOG_TRACE__("p %d: k[%d].0 => 0x%02x",p,k[4*(n_state)+0]); \
		(state_pointer)[0] = d[p] ^ k[4*(n_state)+0]; \
		__LOG_TRACE__("p %d: state%d.0 => 0x%02x",p,(n_state),(state_pointer)[0]); \
	} \
	else if(valid_thread && ti == 4*(n_state)+1) { \
		__LOG_TRACE__("p %d: d[%d].1 => 0x%02x",p,n_state,d[p]); \
		__LOG_TRACE__("p %d: k[%d].1 => 0x%02x",p,n_state,k[4*(n_state)+1]); \
		(state_pointer)[1] = d[p] ^ k[4*(n_state)+1]; \
		__LOG_TRACE__("p %d: state%d.1 => 0x%02x",p,(n_state),(state_pointer)[1]); \
	} \
	else if(valid_thread && ti == 4*(n_state)+2) { \
		__LOG_TRACE__("p %d: d[%d].2 => 0x%02x",p,n_state,d[p]); \
		__LOG_TRACE__("p %d: k[%d].2 => 0x%02x",p,n_state,k[4*(n_state)+2]); \
		(state_pointer)[2] = d[p] ^ k[4*(n_state)+2]; \
		__LOG_TRACE__("p %d: state%d.2 => 0x%02x",p,(n_state),(state_pointer)[2]); \
	} \
	else if(valid_thread && ti == 4*(n_state)+3) { \
		__LOG_TRACE__("p %d: d[%d].3 => 0x%02x",p,n_state,d[p]); \
		__LOG_TRACE__("p %d: k[%d].3 => 0x%02x",p,n_state,k[4*(n_state)+3]); \
		(state_pointer)[3] = d[p] ^ k[4*(n_state)+3]; \
		__LOG_TRACE__("p %d: state%d.3 => 0x%02x",p,(n_state),(state_pointer)[3]); \
	} \
}

#define AES_1B_PTR_ROUND_KEY(state_pointer, n_state, global_bi_pointer) \
{ \
	if(valid_thread && ti == (n_state)*4+0) { \
		__LOG_TRACE__("p %d: global_bi.0 => 0x%02x",p,(global_bi_pointer)[0]); \
		__LOG_TRACE__("p %d: iv[%d].0 => 0x%02x",p,iv[4*(n_state)+0]); \
		__LOG_TRACE__("p %d: k[%d].0 => 0x%02x",p,k[4*(n_state)+0]); \
		(state_pointer)[0] = (global_bi_pointer)[0] ^ iv[4*(n_state)+0] ^ k[4*(n_state)+0]; \
		__LOG_TRACE__("p %d: state%d.0 => 0x%02x",p,(n_state),(state_pointer)[0]); \
	} \
	else if(valid_thread && ti == 4*(n_state)+1) { \
		__LOG_TRACE__("p %d: global_bi.1 => 0x%02x",p,(global_bi_pointer)[1]); \
		__LOG_TRACE__("p %d: iv[%d].1 => 0x%02x",p,iv[4*(n_state)+1]); \
		__LOG_TRACE__("p %d: k[%d].1 => 0x%02x",p,k[4*(n_state)+1]); \
		(state_pointer)[1] = (global_bi_pointer)[1] ^ iv[4*(n_state)+1] ^ k[4*(n_state)+1]; \
		__LOG_TRACE__("p %d: state%d.1 => 0x%02x",p,(n_state),(state_pointer)[1]); \
	} \
	else if(valid_thread && ti == 4*(n_state)+2) { \
		__LOG_TRACE__("p %d: global_bi.2 => 0x%02x",p,(global_bi_pointer)[2]); \
		__LOG_TRACE__("p %d: iv[%d].2 => 0x%02x",p,iv[4*(n_state)+2]); \
		__LOG_TRACE__("p %d: k[%d].2 => 0x%02x",p,k[4*(n_state)+2]); \
		(state_pointer)[2] = (global_bi_pointer)[2] ^ iv[4*(n_state)+2] ^ k[4*(n_state)+2]; \
		__LOG_TRACE__("p %d: state%d.2 => 0x%02x",p,(n_state),(state_pointer)[2]); \
	} \
	else if(valid_thread && ti == 4*(n_state)+3) { \
		__LOG_TRACE__("p %d: global_bi.3 => 0x%02x",p,(global_bi_pointer)[3]); \
		__LOG_TRACE__("p %d: iv[%d].3 => 0x%02x",p,iv[4*(n_state)+3]); \
		__LOG_TRACE__("p %d: k[%d].3 => 0x%02x",p,k[4*(n_state)+3]); \
		(state_pointer)[3] = (global_bi_pointer)[3] ^ iv[4*(n_state)+3] ^ k[4*(n_state)+3]; \
		__LOG_TRACE__("p %d: state%d.3 => 0x%02x",p,(n_state),(state_pointer)[3]); \
	} \
}

#define AES_1B_CFB_ROUND_KEY(state_pointer, n_state) \
{ \
	if(valid_thread && ti == 4*(n_state)+0) { \
			if(bi == (n_state)*4+0) { \
				__LOG_TRACE__("p %d: iv[%d].0 => 0x%04x",p,iv[4*(n_state)+0]); \
				(state_pointer)[0] = iv[4*(n_state)+0] ^ k[4*(n_state)+0]; \
			} \
			else { \
				if(sti == 0) { \
					int np = (blockIdx.x*16)-16; \
					(state_pointer)[0] = neigh[np+(n_state*4+0)] ^ k[4*(n_state)+0]; \
					__LOG_TRACE__("p %d (bi %d): accessing neighbor at byte %d.",p,bi,np+(n_state*4+0)); \
				} \
				else { \
					(state_pointer)[0] = d[p-16] ^ k[4*(n_state)+0]; \
					__LOG_TRACE__("p %d (bi %d): accessing prev. block.",p,bi); \
				} \
			} \
	} \
	else if(valid_thread && ti == 4*(n_state)+1) { \
			if(bi == (n_state)*4+1) { \
				__LOG_TRACE__("p %d: iv[%d].1 => 0x%04x",p,iv[4*(n_state)+1]); \
				(state_pointer)[1] = iv[4*(n_state)+1] ^ k[4*(n_state)+1]; \
			} \
			else { \
				if(sti == 0) { \
					int np = (blockIdx.x*16)-16; \
					(state_pointer)[1] = neigh[np+(n_state*4+1)] ^ k[4*(n_state)+1]; \
					__LOG_TRACE__("p %d (bi %d): accessing neighbor at byte %d.",p,bi,np+(n_state*4+1)); \
				} \
				else { \
					(state_pointer)[1] = d[p-16] ^ k[4*(n_state)+1]; \
					__LOG_TRACE__("p %d (bi %d): accessing prev. block.",p,bi); \
				} \
			} \
	} \
	else if(valid_thread && ti == 4*(n_state)+2) { \
			if(bi == (n_state)*4+2) { \
				__LOG_TRACE__("p %d: iv[%d].2 => 0x%04x",p,iv[4*(n_state)+2]); \
				(state_pointer)[2] = iv[4*(n_state)+2] ^ k[4*(n_state)+2]; \
			} \
			else { \
				if(sti == 0) { \
					int np = (blockIdx.x*16)-16; \
					(state_pointer)[2] = neigh[np+(n_state*4+2)] ^ k[4*(n_state)+2]; \
					__LOG_TRACE__("p %d (bi %d): accessing neighbor at byte %d.",p,bi,np+(n_state*4+2)); \
				} \
				else { \
					(state_pointer)[2] = d[p-16] ^ k[4*(n_state)+2]; \
					__LOG_TRACE__("p %d (bi %d): accessing prev. block.",p,bi); \
				} \
			} \
	} \
	else if(valid_thread && ti == 4*(n_state)+3) { \
			if(bi == (n_state)*4+3) { \
				__LOG_TRACE__("p %d: iv[%d].3 => 0x%04x",p,iv[4*(n_state)+3]); \
				(state_pointer)[3] = iv[4*(n_state)+3] ^ k[4*(n_state)+3]; \
			} \
			else { \
				if(sti == 0) { \
					int np = (blockIdx.x*16)-16; \
					(state_pointer)[3] = neigh[np+(n_state*4+3)] ^ k[4*(n_state)+3]; \
					__LOG_TRACE__("p %d (bi %d): accessing neighbor at byte %d.",p,bi,np+(n_state*4+3)); \
				} \
				else { \
					(state_pointer)[3] = d[p-16] ^ k[4*(n_state)+3]; \
					__LOG_TRACE__("p %d (bi %d): accessing prev. block.",p,bi); \
				} \
			} \
	} \
}

#define AES_1B_CBC_ROUND(state_pointer, n_state) \
{ \
	if(valid_thread && ti == 4*(n_state)+0) { \
			uint8_t cb0; \
			if(bi == (n_state)*4+0) { \
				__LOG_TRACE__("p %d: iv[%d].0 => 0x%04x",p,iv[4*(n_state)+0]); \
				cb0 = iv[4*(n_state)+0] ^ k[4*(n_state)+0]; \
			} \
			else { \
				if(sti == 0) { \
					int np = (blockIdx.x*16)-16; \
					cb0 = neigh[np+(n_state*4+0)]; \
					__LOG_TRACE__("p %d (bi %d): accessing neighbor at byte %d.",p,bi,np+(n_state*4+0)); \
				} \
				else { \
					cb0 = d[p-16]; \
					__LOG_TRACE__("p %d (bi %d): accessing prev. block.",p,bi); \
				} \
			} \
			(state_pointer)[0] = cb0; \
	} \
	else if(valid_thread && ti == 4*(n_state)+1) { \
		uint8_t cb1; \
		if(bi == (n_state)*4+1) { \
			__LOG_TRACE__("p %d: iv[%d].1=> 0x%04x",p,iv[4*(n_state)+1]); \
			cb1 = iv[4*(n_state)+1] ^ k[4*(n_state)+1]; \
		} \
		else { \
			if(sti == 0) { \
				int np = (blockIdx.x*16)-16; \
				cb1 = neigh[np+(n_state*4+1)]; \
				__LOG_TRACE__("p %d (bi %d): accessing neighbor at byte %d.",p,bi,np+(n_state*4+1)); \
			} \
			else { \
				cb1 = d[p-16]; \
				__LOG_TRACE__("p %d (bi %d): accessing prev. block.",p,bi); \
			} \
		} \
		(state_pointer)[1] = cb1; \
	} \
	else if(valid_thread && ti == 4*(n_state)+2) { \
		uint8_t cb2; \
		if(bi == (n_state)*4+2) { \
			__LOG_TRACE__("p %d: iv[%d].2 => 0x%04x",p,iv[4*(n_state)+2]); \
			cb2 = iv[4*(n_state)+2] ^ k[4*(n_state)+2]; \
		} \
		else { \
			if(sti == 0) { \
				int np = (blockIdx.x*16)-16; \
				cb2 = neigh[np+(n_state*4+2)]; \
				__LOG_TRACE__("p %d (bi %d): accessing neighbor at byte %d.",p,bi,np+(n_state*4+2)); \
			} \
			else { \
				cb2 = d[p-16]; \
				__LOG_TRACE__("p %d (bi %d): accessing prev. block.",p,bi); \
			} \
		} \
		(state_pointer)[2] = cb2; \
	} \
	else if(valid_thread && ti == 4*(n_state)+3) { \
		uint8_t cb3; \
		if(bi == (n_state)*4+3) { \
			__LOG_TRACE__("p %d: iv[%d].3 => 0x%04x",p,iv[4*(n_state)+3]); \
			cb3 = iv[4*(n_state)+3] ^ k[4*(n_state)+3]; \
		} \
		else { \
			if(sti == 0) { \
				int np = (blockIdx.x*16)-16; \
				cb3 = neigh[np+(n_state*4+3)]; \
				__LOG_TRACE__("p %d (bi %d): accessing neighbor at byte %d.",p,bi,np+(n_state*4+3)); \
			} \
			else { \
				cb3 = d[p-16]; \
				__LOG_TRACE__("p %d (bi %d): accessing prev. block.",p,bi); \
			} \
		} \
		(state_pointer)[3] = cb3; \
	} \
}

#define AES_1B_STATE_XOR_INPUT(state_pointer, n_state) \
		if(valid_thread && ti == 4*(n_state)+0) { \
			(state_pointer)[0] ^= d[p]; \
		} \
		else if(valid_thread && ti == 4*(n_state)+1) { \
			(state_pointer)[1] ^= d[p]; \
		} \
		else if(valid_thread && ti == 4*(n_state)+2) { \
			(state_pointer)[2] ^= d[p]; \
		} \
		else if(valid_thread && ti == 4*(n_state)+3) { \
			(state_pointer)[3] ^= d[p]; \
		} \

#define AES_1B_EXPORT_STATE(state_pointer, n_state) \
	if(valid_thread && ti == 4*(n_state)+0) { \
		out[p] = (state_pointer)[0]; \
	} \
	else if(valid_thread && ti == 4*(n_state)+1) { \
		out[p] = (state_pointer)[1]; \
	} \
	else if(valid_thread && ti == 4*(n_state)+2) { \
		out[p] = (state_pointer)[2]; \
	} \
	else if(valid_thread && ti == 4*(n_state)+3) { \
		out[p] = (state_pointer)[3]; \
	} \

#define AES_1B_ENCRYPT_ROUND(store0_ptr,store1_ptr,store2_ptr,store3_ptr,s0_ptr, s1_ptr, s2_ptr, s3_ptr, round_number) \
{ \
	/* S0 = ... */ \
	if(valid_thread && ti == 0) { \
		(store0_ptr)[0] = T0[(s0_ptr)[0]*4+0] ^ T1[(s1_ptr)[1]*4+0] ^ T2[(s2_ptr)[2]*4+0] ^ T3[(s3_ptr)[3]*4+0] ^ k[4*((round_number)*4)+0]; \
		__LOG_TRACE__("p %d: state0.0 => 0x%02x",p,(store0_ptr)[0]); \
	} \
	else if(valid_thread && ti == 1) { \
		(store0_ptr)[1] = T0[(s0_ptr)[0]*4+1] ^ T1[(s1_ptr)[1]*4+1] ^ T2[(s2_ptr)[2]*4+1] ^ T3[(s3_ptr)[3]*4+1] ^ k[4*((round_number)*4)+1]; \
		__LOG_TRACE__("p %d: state0.1 => 0x%02x",p,(store0_ptr)[1]); \
	} \
	else if(valid_thread && ti == 2) { \
		(store0_ptr)[2] = T0[(s0_ptr)[0]*4+2] ^ T1[(s1_ptr)[1]*4+2] ^ T2[(s2_ptr)[2]*4+2] ^ T3[(s3_ptr)[3]*4+2] ^ k[4*((round_number)*4)+2]; \
		__LOG_TRACE__("p %d: state0.3 => 0x%02x",p,(store0_ptr)[2]); \
	} \
	else if(valid_thread && ti == 3) { \
		(store0_ptr)[3] = T0[(s0_ptr)[0]*4+3] ^ T1[(s1_ptr)[1]*4+3] ^ T2[(s2_ptr)[2]*4+3] ^ T3[(s3_ptr)[3]*4+3] ^ k[4*((round_number)*4)+3]; \
		__LOG_TRACE__("p %d: state0.3 => 0x%02x",p,(store0_ptr)[3]); \
	} \
	\
	/* S1 = ... */ \
	else if(valid_thread && ti == 4) { \
		(store1_ptr)[0] = T0[(s1_ptr)[0]*4+0] ^ T1[(s2_ptr)[1]*4+0] ^ T2[(s3_ptr)[2]*4+0] ^ T3[(s0_ptr)[3]*4+0] ^ k[4*((round_number)*4)+4]; \
		__LOG_TRACE__("p %d: state0.0 => 0x%02x",p,(store1_ptr)[0]); \
	} \
	else if(valid_thread && ti == 5) { \
		(store1_ptr)[1] = T0[(s1_ptr)[0]*4+1] ^ T1[(s2_ptr)[1]*4+1] ^ T2[(s3_ptr)[2]*4+1] ^ T3[(s0_ptr)[3]*4+1] ^ k[4*((round_number)*4)+5]; \
		__LOG_TRACE__("p %d: state0.1 => 0x%02x",p,(store1_ptr)[1]); \
	} \
	else if(valid_thread && ti == 6) { \
		(store1_ptr)[2] = T0[(s1_ptr)[0]*4+2] ^ T1[(s2_ptr)[1]*4+2] ^ T2[(s3_ptr)[2]*4+2] ^ T3[(s0_ptr)[3]*4+2] ^ k[4*((round_number)*4)+6]; \
		__LOG_TRACE__("p %d: state0.3 => 0x%02x",p,(store1_ptr)[2]); \
	} \
	else if(valid_thread && ti == 7) { \
		(store1_ptr)[3] = T0[(s1_ptr)[0]*4+3] ^ T1[(s2_ptr)[1]*4+3] ^ T2[(s3_ptr)[2]*4+3] ^ T3[(s0_ptr)[3]*4+3] ^ k[4*((round_number)*4)+7]; \
		__LOG_TRACE__("p %d: state0.3 => 0x%02x",p,(store1_ptr)[3]); \
	} \
	\
	/* S2 = ... */ \
	else if(valid_thread && ti == 8) { \
		(store2_ptr)[0] = T0[(s2_ptr)[0]*4+0] ^ T1[(s3_ptr)[1]*4+0] ^ T2[(s0_ptr)[2]*4+0] ^ T3[(s1_ptr)[3]*4+0] ^ k[4*((round_number)*4)+8]; \
		__LOG_TRACE__("p %d: state0.0 => 0x%02x",p,(store2_ptr)[0]); \
	} \
	else if(valid_thread && ti == 9) { \
		(store2_ptr)[1] = T0[(s2_ptr)[0]*4+1] ^ T1[(s3_ptr)[1]*4+1] ^ T2[(s0_ptr)[2]*4+1] ^ T3[(s1_ptr)[3]*4+1] ^ k[4*((round_number)*4)+9]; \
		__LOG_TRACE__("p %d: state0.1 => 0x%02x",p,(store2_ptr)[1]); \
	} \
	else if(valid_thread && ti == 10) { \
		(store2_ptr)[2] = T0[(s2_ptr)[0]*4+2] ^ T1[(s3_ptr)[1]*4+2] ^ T2[(s0_ptr)[2]*4+2] ^ T3[(s1_ptr)[3]*4+2] ^ k[4*((round_number)*4)+10]; \
		__LOG_TRACE__("p %d: state0.3 => 0x%02x",p,(store2_ptr)[2]); \
	} \
	else if(valid_thread && ti == 11) { \
		(store2_ptr)[3] = T0[(s2_ptr)[0]*4+3] ^ T1[(s3_ptr)[1]*4+3] ^ T2[(s0_ptr)[2]*4+3] ^ T3[(s1_ptr)[3]*4+3] ^ k[4*((round_number)*4)+11]; \
		__LOG_TRACE__("p %d: state0.3 => 0x%02x",p,(store2_ptr)[3]); \
	} \
	\
	/* S3 = ... */ \
	else if(valid_thread && ti == 12) { \
		(store3_ptr)[0] = T0[(s3_ptr)[0]*4+0] ^ T1[(s0_ptr)[1]*4+0] ^ T2[(s1_ptr)[2]*4+0] ^ T3[(s2_ptr)[3]*4+0] ^ k[4*((round_number)*4)+12]; \
		__LOG_TRACE__("p %d: state0.0 => 0x%02x",p,(store2_ptr)[0]); \
	} \
	else if(valid_thread && ti == 13) { \
		(store3_ptr)[1] = T0[(s3_ptr)[0]*4+1] ^ T1[(s0_ptr)[1]*4+1] ^ T2[(s1_ptr)[2]*4+1] ^ T3[(s2_ptr)[3]*4+1] ^ k[4*((round_number)*4)+13]; \
		__LOG_TRACE__("p %d: state0.1 => 0x%02x",p,(store2_ptr)[1]); \
	} \
	else if(valid_thread && ti == 14) { \
		(store3_ptr)[2] = T0[(s3_ptr)[0]*4+2] ^ T1[(s0_ptr)[1]*4+2] ^ T2[(s1_ptr)[2]*4+2] ^ T3[(s2_ptr)[3]*4+2] ^ k[4*((round_number)*4)+14]; \
		__LOG_TRACE__("p %d: state0.3 => 0x%02x",p,(store2_ptr)[2]); \
	} \
	else if(valid_thread && ti == 15) { \
		(store3_ptr)[3] = T0[(s3_ptr)[0]*4+3] ^ T1[(s0_ptr)[1]*4+3] ^ T2[(s1_ptr)[2]*4+3] ^ T3[(s2_ptr)[3]*4+3] ^ k[4*((round_number)*4)+15]; \
		__LOG_TRACE__("p %d: state0.3 => 0x%02x",p,(store2_ptr)[3]); \
	} \
}

#define AES_1B_DECRYPT_ROUND(store0_ptr,store1_ptr,store2_ptr,store3_ptr,s0_ptr, s1_ptr, s2_ptr, s3_ptr, round_number) \
{ \
	/* S0 = ... */ \
	if(valid_thread && ti == 0) { \
		(store0_ptr)[0] = T0[(s0_ptr)[0]*4+0] ^ T1[(s3_ptr)[1]*4+0] ^ T2[(s2_ptr)[2]*4+0] ^ T3[(s1_ptr)[3]*4+0] ^ k[4*((round_number)*4)+0]; \
		__LOG_TRACE__("p %d: state0.0 => 0x%02x",p,(store0_ptr)[0]); \
	} \
	else if(valid_thread && ti == 1) { \
		(store0_ptr)[1] = T0[(s0_ptr)[0]*4+1] ^ T1[(s3_ptr)[1]*4+1] ^ T2[(s2_ptr)[2]*4+1] ^ T3[(s1_ptr)[3]*4+1] ^ k[4*((round_number)*4)+1]; \
		__LOG_TRACE__("p %d: state0.1 => 0x%02x",p,(store0_ptr)[1]); \
	} \
	else if(valid_thread && ti == 2) { \
		(store0_ptr)[2] = T0[(s0_ptr)[0]*4+2] ^ T1[(s3_ptr)[1]*4+2] ^ T2[(s2_ptr)[2]*4+2] ^ T3[(s1_ptr)[3]*4+2] ^ k[4*((round_number)*4)+2]; \
		__LOG_TRACE__("p %d: state0.3 => 0x%02x",p,(store0_ptr)[2]); \
	} \
	else if(valid_thread && ti == 3) { \
		(store0_ptr)[3] = T0[(s0_ptr)[0]*4+3] ^ T1[(s3_ptr)[1]*4+3] ^ T2[(s2_ptr)[2]*4+3] ^ T3[(s1_ptr)[3]*4+3] ^ k[4*((round_number)*4)+3]; \
		__LOG_TRACE__("p %d: state0.3 => 0x%02x",p,(store0_ptr)[3]); \
	} \
	\
	/* S1 = ... */ \
	else if(valid_thread && ti == 4) { \
		(store1_ptr)[0] = T0[(s1_ptr)[0]*4+0] ^ T1[(s0_ptr)[1]*4+0] ^ T2[(s3_ptr)[2]*4+0] ^ T3[(s2_ptr)[3]*4+0] ^ k[4*((round_number)*4)+4]; \
		__LOG_TRACE__("p %d: state0.0 => 0x%02x",p,(store1_ptr)[0]); \
	} \
	else if(valid_thread && ti == 5) { \
		(store1_ptr)[1] = T0[(s1_ptr)[0]*4+1] ^ T1[(s0_ptr)[1]*4+1] ^ T2[(s3_ptr)[2]*4+1] ^ T3[(s2_ptr)[3]*4+1] ^ k[4*((round_number)*4)+5]; \
		__LOG_TRACE__("p %d: state0.1 => 0x%02x",p,(store1_ptr)[1]); \
	} \
	else if(valid_thread && ti == 6) { \
		(store1_ptr)[2] = T0[(s1_ptr)[0]*4+2] ^ T1[(s0_ptr)[1]*4+2] ^ T2[(s3_ptr)[2]*4+2] ^ T3[(s2_ptr)[3]*4+2] ^ k[4*((round_number)*4)+6]; \
		__LOG_TRACE__("p %d: state0.3 => 0x%02x",p,(store1_ptr)[2]); \
	} \
	else if(valid_thread && ti == 7) { \
		(store1_ptr)[3] = T0[(s1_ptr)[0]*4+3] ^ T1[(s0_ptr)[1]*4+3] ^ T2[(s3_ptr)[2]*4+3] ^ T3[(s2_ptr)[3]*4+3] ^ k[4*((round_number)*4)+7]; \
		__LOG_TRACE__("p %d: state0.3 => 0x%02x",p,(store1_ptr)[3]); \
	} \
	\
	/* S2 = ... */ \
	else if(valid_thread && ti == 8) { \
		(store2_ptr)[0] = T0[(s2_ptr)[0]*4+0] ^ T1[(s1_ptr)[1]*4+0] ^ T2[(s0_ptr)[2]*4+0] ^ T3[(s3_ptr)[3]*4+0] ^ k[4*((round_number)*4)+8]; \
		__LOG_TRACE__("p %d: state0.0 => 0x%02x",p,(store2_ptr)[0]); \
	} \
	else if(valid_thread && ti == 9) { \
		(store2_ptr)[1] = T0[(s2_ptr)[0]*4+1] ^ T1[(s1_ptr)[1]*4+1] ^ T2[(s0_ptr)[2]*4+1] ^ T3[(s3_ptr)[3]*4+1] ^ k[4*((round_number)*4)+9]; \
		__LOG_TRACE__("p %d: state0.1 => 0x%02x",p,(store2_ptr)[1]); \
	} \
	else if(valid_thread && ti == 10) { \
		(store2_ptr)[2] = T0[(s2_ptr)[0]*4+2] ^ T1[(s1_ptr)[1]*4+2] ^ T2[(s0_ptr)[2]*4+2] ^ T3[(s3_ptr)[3]*4+2] ^ k[4*((round_number)*4)+10]; \
		__LOG_TRACE__("p %d: state0.3 => 0x%02x",p,(store2_ptr)[2]); \
	} \
	else if(valid_thread && ti == 11) { \
		(store2_ptr)[3] = T0[(s2_ptr)[0]*4+3] ^ T1[(s1_ptr)[1]*4+3] ^ T2[(s0_ptr)[2]*4+3] ^ T3[(s3_ptr)[3]*4+3] ^ k[4*((round_number)*4)+11]; \
		__LOG_TRACE__("p %d: state0.3 => 0x%02x",p,(store2_ptr)[3]); \
	} \
	\
	/* S3 = ... */ \
	else if(valid_thread && ti == 12) { \
		(store3_ptr)[0] = T0[(s3_ptr)[0]*4+0] ^ T1[(s2_ptr)[1]*4+0] ^ T2[(s1_ptr)[2]*4+0] ^ T3[(s0_ptr)[3]*4+0] ^ k[4*((round_number)*4)+12]; \
		__LOG_TRACE__("p %d: state0.0 => 0x%02x",p,(store2_ptr)[0]); \
	} \
	else if(valid_thread && ti == 13) { \
		(store3_ptr)[1] = T0[(s3_ptr)[0]*4+1] ^ T1[(s2_ptr)[1]*4+1] ^ T2[(s1_ptr)[2]*4+1] ^ T3[(s0_ptr)[3]*4+1] ^ k[4*((round_number)*4)+13]; \
		__LOG_TRACE__("p %d: state0.1 => 0x%02x",p,(store2_ptr)[1]); \
	} \
	else if(valid_thread && ti == 14) { \
		(store3_ptr)[2] = T0[(s3_ptr)[0]*4+2] ^ T1[(s2_ptr)[1]*4+2] ^ T2[(s1_ptr)[2]*4+2] ^ T3[(s0_ptr)[3]*4+2] ^ k[4*((round_number)*4)+14]; \
		__LOG_TRACE__("p %d: state0.3 => 0x%02x",p,(store2_ptr)[2]); \
	} \
	else if(valid_thread && ti == 15) { \
		(store3_ptr)[3] = T0[(s3_ptr)[0]*4+3] ^ T1[(s2_ptr)[1]*4+3] ^ T2[(s1_ptr)[2]*4+3] ^ T3[(s0_ptr)[3]*4+3] ^ k[4*((round_number)*4)+15]; \
		__LOG_TRACE__("p %d: state0.3 => 0x%02x",p,(store2_ptr)[3]); \
	} \
}

__global__ void __cuda_aes_1b_encrypt__(
		  const paracrypt::BlockCipher::Mode m,
		  unsigned int n,
		  uint32_t offset,
		  const uint8_t* d,
		  uint8_t* out,
		  uint8_t* neigh,
		  uint8_t* iv,
	  	  uint8_t* k,
		  const int key_bits,
	  	  uint8_t* T0,
	  	  uint8_t* T1,
	  	  uint8_t* T2,
	  	  uint8_t* T3
    )
{
	// Each block has its own shared memory
	// We have an state for each two threads
	extern __shared__ uint32_t state[];

	unsigned int bi = ((blockIdx.x * blockDim.x) + threadIdx.x); // byte index
	const int s_size = blockDim.x/16;
	//__LOG_TRACE__("s_size => %d", s_size);
	uint32_t* s0 = state           ;
	uint32_t* s1 = state+(  s_size);
	uint32_t* s2 = state+(2*s_size);
	uint32_t* s3 = state+(3*s_size);
	uint32_t* t0 = state+(4*s_size);
	uint32_t* t1 = state+(5*s_size);
	uint32_t* t2 = state+(6*s_size);
	uint32_t* t3 = state+(7*s_size);

	unsigned int p = bi;
	uint32_t sti = threadIdx.x/16; //state index
	int ti = threadIdx.x%16;
	int valid_thread = bi < n*16;
	unsigned int extra_rounds = 0;

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
	if(m == paracrypt::BlockCipher::CTR || m == paracrypt::BlockCipher::GCM) {
		uint32_t global_bi = offset+sti;
		uint8_t* global_bi_pointer = (uint8_t*) &global_bi;
		AES_1B_PTR_ROUND_KEY(s0p, 0, global_bi_pointer);
		AES_1B_PTR_ROUND_KEY(s1p, 1, global_bi_pointer);
		AES_1B_PTR_ROUND_KEY(s2p, 2, global_bi_pointer);
		AES_1B_PTR_ROUND_KEY(s3p, 3, global_bi_pointer);
	}
	else if(m == paracrypt::BlockCipher::CFB) {
		AES_1B_CFB_ROUND_KEY(s0p,0);
		AES_1B_CFB_ROUND_KEY(s1p,1);
		AES_1B_CFB_ROUND_KEY(s2p,2);
		AES_1B_CFB_ROUND_KEY(s3p,3);
	}
	else {
		AES_1B_ROUND_KEY(s0p,0);
		AES_1B_ROUND_KEY(s1p,1);
		AES_1B_ROUND_KEY(s2p,2);
		AES_1B_ROUND_KEY(s3p,3);
	}

	// 8 rounds
	#pragma unroll
	for(int r2 = 1; r2 <= 4; r2++) {
		__syncthreads();
		AES_1B_ENCRYPT_ROUND(t0p,t1p,t2p,t3p,s0p,s1p,s2p,s3p,r2*2-1);
		__syncthreads();
		AES_1B_ENCRYPT_ROUND(s0p,s1p,s2p,s3p,t0p,t1p,t2p,t3p,r2*2);
	}

	// +2 rounds
	if(key_bits >= 192) {
		extra_rounds = 2;
		__syncthreads();
		AES_1B_ENCRYPT_ROUND(t0p,t1p,t2p,t3p,s0p,s1p,s2p,s3p,9);
		__syncthreads();
		AES_1B_ENCRYPT_ROUND(s0p,s1p,s2p,s3p,t0p,t1p,t2p,t3p,10);

		// +2 rounds
		if(key_bits == 256) {
			extra_rounds = 4;
			__syncthreads();
			AES_1B_ENCRYPT_ROUND(t0p,t1p,t2p,t3p,s0p,s1p,s2p,s3p,11);
			__syncthreads();
			AES_1B_ENCRYPT_ROUND(s0p,s1p,s2p,s3p,t0p,t1p,t2p,t3p,12);
		}
	}

	__syncthreads();
	AES_1B_ENCRYPT_ROUND(t0p,t1p,t2p,t3p,s0p,s1p,s2p,s3p,9+extra_rounds);

	__syncthreads();
	// last round
	/* S0 = ... */
	if(valid_thread && ti == 0) {
		s0p[0] = T2[t0p[0]*4+0] ^ k[4*((10+extra_rounds)*4)+0];
		__LOG_TRACE__("p %d: state0.0 => 0x%02x",p,s0p[0]);
	}
	else if(valid_thread && ti == 1) {
		s0p[1] = T3[t1p[1]*4+1] ^ k[4*((10+extra_rounds)*4)+1];
		__LOG_TRACE__("p %d: state0.1 => 0x%02x",p,s0p[1]);
	}
	else if(valid_thread && ti == 2) {
		s0p[2] = T0[t2p[2]*4+2] ^ k[4*((10+extra_rounds)*4)+2];
		__LOG_TRACE__("p %d: state0.2 => 0x%02x",p,s0p[2]);
	}
	else if(valid_thread && ti == 3) {
		s0p[3] = T1[t3p[3]*4+3] ^ k[4*((10+extra_rounds)*4)+3];
		__LOG_TRACE__("p %d: state0.3 => 0x%02x",p,s0p[3]);
	}
	/* S1 = ... */
	else if(valid_thread && ti == 4) {
		s1p[0] = T2[t1p[0]*4+0] ^ k[4*((10+extra_rounds)*4)+4];
		__LOG_TRACE__("p %d: state1.0 => 0x%02x",p,s1p[0]);
	}
	else if(valid_thread && ti == 5) {
		s1p[1] = T3[t2p[1]*4+1] ^ k[4*((10+extra_rounds)*4)+5];
		__LOG_TRACE__("p %d: state1.1 => 0x%02x",p,s1p[1]);
	}
	else if(valid_thread && ti == 6) {
		s1p[2] = T0[t3p[2]*4+2] ^ k[4*((10+extra_rounds)*4)+6];
		__LOG_TRACE__("p %d: state1.2 => 0x%02x",p,s1p[2]);
	}
	else if(valid_thread && ti == 7) {
		s1p[3] = T1[t0p[3]*4+3] ^ k[4*((10+extra_rounds)*4)+7];
		__LOG_TRACE__("p %d: state1.3 => 0x%02x",p,s1p[3]);
	}
	/* S2 = ... */
	else if(valid_thread && ti == 8) {
		s2p[0] = T2[t2p[0]*4+0] ^ k[4*((10+extra_rounds)*4)+8];
		__LOG_TRACE__("p %d: state2.0 => 0x%02x",p,s2p[0]);
	}
	else if(valid_thread && ti == 9) {
		s2p[1] = T3[t3p[1]*4+1] ^ k[4*((10+extra_rounds)*4)+9];
		__LOG_TRACE__("p %d: state2.1 => 0x%02x",p,s2p[1]);
	}
	else if(valid_thread && ti == 10) {
		s2p[2] = T0[t0p[2]*4+2] ^ k[4*((10+extra_rounds)*4)+10];
		__LOG_TRACE__("p %d: state2.2 => 0x%02x",p,s2p[2]);
	}
	else if(valid_thread && ti == 11) {
		s2p[3] = T1[t1p[3]*4+3] ^ k[4*((10+extra_rounds)*4)+11];
		__LOG_TRACE__("p %d: state2.3 => 0x%02x",p,s2p[3]);
	}
	/* S3 = ... */
	else if(valid_thread && ti == 12) {
		s3p[0] = T2[t3p[0]*4+0] ^ k[4*((10+extra_rounds)*4)+12];
		__LOG_TRACE__("p %d: state3.0 => 0x%02x",p,s3p[0]);
	}
	else if(valid_thread && ti == 13) {
		s3p[1] = T3[t0p[1]*4+1] ^ k[4*((10+extra_rounds)*4)+13];
		__LOG_TRACE__("p %d: state3.1 => 0x%02x",p,s3p[1]);
	}
	else if(valid_thread && ti == 14) {
		s3p[2] = T0[t1p[2]*4+2] ^ k[4*((10+extra_rounds)*4)+14];
		__LOG_TRACE__("p %d: state3.2 => 0x%02x",p,s3p[2]);
	}
	else if(valid_thread && ti == 15) {
		s3p[3] = T1[t2p[3]*4+3] ^ k[4*((10+extra_rounds)*4)+15];
		__LOG_TRACE__("p %d: state3.3 => 0x%02x",p,s3p[3]);
	}

	if(		   m == paracrypt::BlockCipher::CTR
			|| m == paracrypt::BlockCipher::GCM
			|| m == paracrypt::BlockCipher::CFB
	){
		AES_1B_STATE_XOR_INPUT(s0p,0);
		AES_1B_STATE_XOR_INPUT(s1p,1);
		AES_1B_STATE_XOR_INPUT(s2p,2);
		AES_1B_STATE_XOR_INPUT(s3p,3);
	}

	// Save results
	AES_1B_EXPORT_STATE(s0p,0);
	AES_1B_EXPORT_STATE(s1p,1);
	AES_1B_EXPORT_STATE(s2p,2);
	AES_1B_EXPORT_STATE(s3p,3);
}

__global__ void __cuda_aes_1b_decrypt__(
		const paracrypt::BlockCipher::Mode m,
		unsigned int n,
		unsigned int offset,
		const uint8_t* d,
		uint8_t* out,
		uint8_t* neigh,
		uint8_t* iv,
		uint8_t* k,
		const int key_bits,
	  	uint8_t* T0,
	  	uint8_t* T1,
	  	uint8_t* T2,
	  	uint8_t* T3,
	  	uint8_t* T4
    )
{
	// Each block has its own shared memory
	// We have an state for each two threads
	extern __shared__ uint32_t state[];

	unsigned int bi = ((blockIdx.x * blockDim.x) + threadIdx.x); // byte index
	const int s_size = blockDim.x/16;
	//__LOG_TRACE__("s_size => %d", s_size);
	uint32_t* s0 = state           ;
	uint32_t* s1 = state+(  s_size);
	uint32_t* s2 = state+(2*s_size);
	uint32_t* s3 = state+(3*s_size);
	uint32_t* t0 = state+(4*s_size);
	uint32_t* t1 = state+(5*s_size);
	uint32_t* t2 = state+(6*s_size);
	uint32_t* t3 = state+(7*s_size);

	unsigned int p = bi;
	unsigned int sti = threadIdx.x/16; //state index
	int ti = threadIdx.x%16; // thread index: 16 threads per cipher-block
	int valid_thread = bi < n*16;
	unsigned int extra_rounds = 0;

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
	AES_1B_ROUND_KEY(s0p,0);
	AES_1B_ROUND_KEY(s1p,1);
	AES_1B_ROUND_KEY(s2p,2);
	AES_1B_ROUND_KEY(s3p,3);

	// 8 rounds
	#pragma unroll
	for(int r2 = 1; r2 <= 4; r2++) {
		__syncthreads();
		AES_1B_DECRYPT_ROUND(t0p,t1p,t2p,t3p,s0p,s1p,s2p,s3p,r2*2-1);
		__syncthreads();
		AES_1B_DECRYPT_ROUND(s0p,s1p,s2p,s3p,t0p,t1p,t2p,t3p,r2*2);
	}

	// +2 rounds
	if(key_bits >= 192) {
		extra_rounds = 2;
		__syncthreads();
		AES_1B_DECRYPT_ROUND(t0p,t1p,t2p,t3p,s0p,s1p,s2p,s3p,9);
		__syncthreads();
		AES_1B_DECRYPT_ROUND(s0p,s1p,s2p,s3p,t0p,t1p,t2p,t3p,10);

		// +2 rounds
		if(key_bits == 256) {
			extra_rounds = 4;
			__syncthreads();
			AES_1B_DECRYPT_ROUND(t0p,t1p,t2p,t3p,s0p,s1p,s2p,s3p,11);
			__syncthreads();
			AES_1B_DECRYPT_ROUND(s0p,s1p,s2p,s3p,t0p,t1p,t2p,t3p,12);
		}
	}

	__syncthreads();
	AES_1B_DECRYPT_ROUND(t0p,t1p,t2p,t3p,s0p,s1p,s2p,s3p,9+extra_rounds);

	__syncthreads();
	// last round
	/* S0 = ... */
	if(valid_thread && ti == 0) {
		s0p[0] = T4[t0p[0]] ^ k[4*((10+extra_rounds)*4)+0];
		__LOG_TRACE__("p %d: state0.0 => 0x%02x",p,s0p[0]);
	}
	else if(valid_thread && ti == 1) {
		s0p[1] = T4[t3p[1]] ^ k[4*((10+extra_rounds)*4)+1];
		__LOG_TRACE__("p %d: state0.1 => 0x%02x",p,s0p[1]);
	}
	else if(valid_thread && ti == 2) {
		s0p[2] = T4[t2p[2]] ^ k[4*((10+extra_rounds)*4)+2];
		__LOG_TRACE__("p %d: state0.2 => 0x%02x",p,s0p[2]);
	}
	else if(valid_thread && ti == 3) {
		s0p[3] = T4[t1p[3]] ^ k[4*((10+extra_rounds)*4)+3];
		__LOG_TRACE__("p %d: state0.3 => 0x%02x",p,s0p[3]);
	}
	/* S1 = ... */
	else if(valid_thread && ti == 4) {
		s1p[0] = T4[t1p[0]] ^ k[4*((10+extra_rounds)*4)+4];
		__LOG_TRACE__("p %d: state1.0 => 0x%02x",p,s1p[0]);
	}
	else if(valid_thread && ti == 5) {
		s1p[1] = T4[t0p[1]] ^ k[4*((10+extra_rounds)*4)+5];
		__LOG_TRACE__("p %d: state1.1 => 0x%02x",p,s1p[1]);
	}
	else if(valid_thread && ti == 6) {
		s1p[2] = T4[t3p[2]] ^ k[4*((10+extra_rounds)*4)+6];
		__LOG_TRACE__("p %d: state1.2 => 0x%02x",p,s1p[2]);
	}
	else if(valid_thread && ti == 7) {
		s1p[3] = T4[t2p[3]] ^ k[4*((10+extra_rounds)*4)+7];
		__LOG_TRACE__("p %d: state1.3 => 0x%02x",p,s1p[3]);
	}
	/* S2 = ... */
	else if(valid_thread && ti == 8) {
		s2p[0] = T4[t2p[0]] ^ k[4*((10+extra_rounds)*4)+8];
		__LOG_TRACE__("p %d: state2.0 => 0x%02x",p,s2p[0]);
	}
	else if(valid_thread && ti == 9) {
		s2p[1] = T4[t1p[1]] ^ k[4*((10+extra_rounds)*4)+9];
		__LOG_TRACE__("p %d: state2.1 => 0x%02x",p,s2p[1]);
	}
	else if(valid_thread && ti == 10) {
		s2p[2] = T4[t0p[2]] ^ k[4*((10+extra_rounds)*4)+10];
		__LOG_TRACE__("p %d: state2.2 => 0x%02x",p,s2p[2]);
	}
	else if(valid_thread && ti == 11) {
		s2p[3] = T4[t3p[3]] ^ k[4*((10+extra_rounds)*4)+11];
		__LOG_TRACE__("p %d: state2.3 => 0x%02x",p,s2p[3]);
	}
	/* S3 = ... */
	else if(valid_thread && ti == 12) {
		s3p[0] = T4[t3p[0]] ^ k[4*((10+extra_rounds)*4)+12];
		__LOG_TRACE__("p %d: state3.0 => 0x%02x",p,s3p[0]);
	}
	else if(valid_thread && ti == 13) {
		s3p[1] = T4[t2p[1]] ^ k[4*((10+extra_rounds)*4)+13];
		__LOG_TRACE__("p %d: state3.1 => 0x%02x",p,s3p[1]);
	}
	else if(valid_thread && ti == 14) {
		s3p[2] = T4[t1p[2]] ^ k[4*((10+extra_rounds)*4)+14];
		__LOG_TRACE__("p %d: state3.2 => 0x%02x",p,s3p[2]);
	}
	else if(valid_thread && ti == 15) { \
		s3p[3] = T4[t0p[3]] ^ k[4*((10+extra_rounds)*4)+15];
		__LOG_TRACE__("p %d: state3.3 => 0x%02x",p,s3p[3]);
	}

	if(m == paracrypt::BlockCipher::CBC) {
		AES_1B_CBC_ROUND(s0p,0);
		AES_1B_CBC_ROUND(s1p,1);
		AES_1B_CBC_ROUND(s2p,2);
		AES_1B_CBC_ROUND(s3p,3);
		__syncthreads();
	}

	// Save results
	AES_1B_EXPORT_STATE(s0p,0);
	AES_1B_EXPORT_STATE(s1p,1);
	AES_1B_EXPORT_STATE(s2p,2);
	AES_1B_EXPORT_STATE(s3p,3);
}

void cuda_aes_1b_encrypt(
		  paracrypt::BlockCipher::Mode m,
	  	  int gridSize,
	  	  int threadsPerBlock,
	  	  cudaStream_t stream,
	  	  unsigned int n_blocks,
	  	  uint32_t offset,
	  	  unsigned char* in,
	  	  unsigned char* out,
	  	  unsigned char* neigh,
	  	  unsigned char* iv,
	  	  uint32_t* expanded_key,
	  	  int key_bits,
	  	  uint32_t* deviceTe0,
	  	  uint32_t* deviceTe1,
	  	  uint32_t* deviceTe2,
	  	  uint32_t* deviceTe3
	      )
{
	int shared_memory = threadsPerBlock*sizeof(uint32_t);
	__cuda_aes_1b_encrypt__<<<gridSize,threadsPerBlock,shared_memory,stream>>>(//*2>>>(
			m,
			n_blocks,
			offset,
			(const uint8_t*)in,
			(uint8_t*)out,
			(uint8_t*)neigh,
			(uint8_t*)iv,
			(uint8_t*)expanded_key,
			key_bits,
	   		(uint8_t*)deviceTe0,
	   		(uint8_t*)deviceTe1,
	   		(uint8_t*)deviceTe2,
	   		(uint8_t*)deviceTe3
	);
}

void cuda_aes_1b_decrypt(
		  paracrypt::BlockCipher::Mode m,
	  	  int gridSize,
	  	  int threadsPerBlock,
	  	  cudaStream_t stream,
	  	  unsigned int n_blocks,
	  	  unsigned int offset,
	  	  unsigned char* in,
	  	  unsigned char* out,
	  	  unsigned char* neigh,
	  	  unsigned char* iv,
	  	  uint32_t* expanded_key,
	  	  int key_bits,
	  	  uint32_t* deviceTd0,
	  	  uint32_t* deviceTd1,
	  	  uint32_t* deviceTd2,
	  	  uint32_t* deviceTd3,
	  	  uint8_t* deviceTd4
	      )
{
	int shared_memory = threadsPerBlock*sizeof(uint32_t);
	__cuda_aes_1b_decrypt__<<<gridSize,threadsPerBlock,shared_memory,stream>>>(
			m,
			n_blocks,
			offset,
			(const uint8_t*)in,
			(uint8_t*)out,
			(uint8_t*)neigh,
			(uint8_t*)iv,
			(uint8_t*)expanded_key,
			key_bits,
			(uint8_t*)deviceTd0,
			(uint8_t*)deviceTd1,
			(uint8_t*)deviceTd2,
			(uint8_t*)deviceTd3,
	   		deviceTd4
	);
}
