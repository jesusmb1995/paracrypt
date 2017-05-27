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

#define BOOST_TEST_MODULE paracrypt
#include <boost/test/included/unit_test.hpp>
#include <stdint.h>
#include "logging.hpp"
#include "openssl/AES_key_schedule.h"
#include "device/CUDACipherDevice.hpp"
#include "cipher/AES/CudaAesVersions.hpp"
#include "endianess.h"
#include "Timer.hpp"
#include "assert.h"
#include <stdlib.h>     /* srand, rand */
#include <time.h>       /* time */
#include <stdio.h>
#include <fstream>
#include "io/IO.hpp"
#include "io/SharedIO.hpp"
#include "io/SimpleCudaIO.hpp"
#include "io/BlockIO.hpp"
#include "io/CudaSharedIO.hpp"
#include "io/Pinned.hpp"
#include "Launcher.hpp"
#include <algorithm>

// some tests require openssl
#ifdef OPENSSL_EXISTS
	// OpenSLL
	#include <openssl/conf.h>
	#include <openssl/evp.h>
	#include <openssl/err.h>
	#include <string.h>
#endif

int random_data_n_blocks;
unsigned char *random_data;

paracrypt::CUDACipherDevice* gpu;

struct Setup {
	Setup()   {
#ifdef OPENSSL_EXISTS
		  /* Initialise the OpenSSL library */
		  ERR_load_crypto_strings();
		  OpenSSL_add_all_algorithms();
		  OPENSSL_config(NULL);
#endif

		// 500KiB to 1Mib
	#define TRD_MIN 512*64
	#define TRD_MAX 1024*64
	#define TRD_DIF (TRD_MAX-TRD_MIN)
		srand (time(NULL));
		random_data_n_blocks = (rand() % TRD_DIF + TRD_MIN); // TRD_DIF + TRD_MIN);
		random_data = (unsigned char*) malloc(random_data_n_blocks*16);
		uint32_t* data_ptr = (uint32_t*)random_data;
		for(int i=0; i < random_data_n_blocks*4; i++) {
			data_ptr[i] = (uint32_t) rand();
		}
		//	boost::log::core::get()->set_filter
		//    (
		//    		boost::log::trivial::severity >= boost::log::trivial::trace
		//    );
		//    return true;
		 gpu = new paracrypt::CUDACipherDevice(0);
  }
  ~Setup()  {
	  free(random_data);
	  delete gpu;

#ifdef OPENSSL_EXISTS
	  /* Clean up OpenSSL */
	  EVP_cleanup();
	  ERR_free_strings();
#endif
  }
};
BOOST_GLOBAL_FIXTURE( Setup );

typedef struct tv {
	paracrypt::BlockCipher::Mode m;
	const unsigned char input[16];
	const unsigned char iv[16];
	const unsigned char key[256];
	const unsigned char output[16];
	const int key_bits;
} tv;

// NIST-197: Appendix B - Cipher Example (pag. 33)
// https://doi.org/10.6028/NIST.FIPS.197
const tv aes_example = {
		.m = paracrypt::BlockCipher::ECB,
		.input = {
				0x32U, 0x43U, 0xf6U, 0xa8U,
				0x88U, 0x5aU, 0x30U, 0x8dU,
				0x31U, 0x31U, 0x98U, 0xa2U,
				0xe0U, 0x37U, 0x07U, 0x34U
		},
		.iv = {},
		.key = {
				0x2bU, 0x7eU, 0x15U, 0x16U,
				0x28U, 0xaeU, 0xd2U, 0xa6U,
				0xabU, 0xf7U, 0x15U, 0x88U,
				0x09U, 0xcfU, 0x4fU, 0x3cU
		},
		.output = {
				0x39U, 0x25U, 0x84U, 0x1dU,
				0x02U, 0xdcU, 0x09U, 0xfbU,
				0xdcU, 0x11U, 0x85U, 0x97U,
				0x19U, 0x6aU, 0x0bU, 0x32U
		},
		.key_bits = 128
};

// NIST-197 pag. 38
// Appendix C.2 - Example Vectors: AES-192 (Nk=6, Nr=12)
// https://doi.org/10.6028/NIST.FIPS.197
const tv aes_192_tv = {
		.m = paracrypt::BlockCipher::ECB,
		.input = {
				0x00U, 0x11U, 0x22U, 0x33U,
				0x44U, 0x55U, 0x66U, 0x77U,
				0x88U, 0x99U, 0xaaU, 0xbbU,
				0xccU, 0xddU, 0xeeU, 0xffU
		},
		.iv = {},
		.key = {
				0x00U, 0x01U, 0x02U, 0x03U,
				0x04U, 0x05U, 0x06U, 0x07U,
				0x08U, 0x09U, 0x0aU, 0x0bU,
				0x0cU, 0x0dU, 0x0eU, 0x0fU,
				0x10U, 0x11U, 0x12U, 0x13U,
				0x14U, 0x15U, 0x16U, 0x17U
		},
		.output = {
				0xddU, 0xa9U, 0x7cU, 0xa4U,
				0x86U, 0x4cU, 0xdfU, 0xe0U,
				0x6eU, 0xafU, 0x70U, 0xa0U,
				0xecU, 0x0dU, 0x71U, 0x91U
		},
		.key_bits = 192
};

// NIST-197 pag. 42
// Appendix C.3 - Example Vectors: AES-256 (Nk=8, Nr=14)
// https://doi.org/10.6028/NIST.FIPS.197
const tv aes_256_tv = {
		.m = paracrypt::BlockCipher::ECB,
		.input = {
				0x00U, 0x11U, 0x22U, 0x33U,
				0x44U, 0x55U, 0x66U, 0x77U,
				0x88U, 0x99U, 0xaaU, 0xbbU,
				0xccU, 0xddU, 0xeeU, 0xffU
		},
		.iv = {},
		.key = {
				0x00U, 0x01U, 0x02U, 0x03U,
				0x04U, 0x05U, 0x06U, 0x07U,
				0x08U, 0x09U, 0x0aU, 0x0bU,
				0x0cU, 0x0dU, 0x0eU, 0x0fU,
				0x10U, 0x11U, 0x12U, 0x13U,
				0x14U, 0x15U, 0x16U, 0x17U,
				0x18U, 0x19U, 0x1aU, 0x1bU,
				0x1cU, 0x1dU, 0x1eU, 0x1fU
		},
		.output = {
				0x8eU, 0xa2U, 0xb7u, 0xcaU,
				0x51U, 0x67U, 0x45U, 0xbfU,
				0xeaU, 0xfcU, 0x49U, 0x90U,
				0x4bU, 0x49U, 0x60U, 0x89U
		},
		.key_bits = 256
};

/*
PHP Quality-checker
-------------------
https://github.com/ircmaxell/quality-checker/blob/master/
 tmp/gh_18/PHP-PasswordLib-master/test/Data/Vectors/aes-cbc.test-vectors

Set 1 vector 1
    mode=aes-cbc-128
    key=2b7e151628aed2a6abf7158809cf4f3c
    iv=000102030405060708090A0B0C0D0E0F
    plain=6bc1bee22e409f96e93d7e117393172a
    cipher=7649abac8119b246cee98e9b12e9197d
*/
const tv aes_128_cbc_tv = {
		.m = paracrypt::BlockCipher::CBC,
		.input = {
				0x6bU, 0xc1U, 0xbeU, 0xe2U,
				0x2eU, 0x40U, 0x9fU, 0x96U,
				0xe9U, 0x3dU, 0x7eU, 0x11U,
				0x73U, 0x93U, 0x17U, 0x2aU
		},
		.iv = {
				0x00U, 0x01U, 0x02U, 0x03,
				0x04U, 0x05U, 0x06U, 0x07,
				0x08U, 0x09U, 0x0AU, 0x0B,
				0x0CU, 0x0DU, 0x0EU, 0x0F
		},
		.key = {
				0x2bU, 0x7eU, 0x15U, 0x16U,
				0x28U, 0xaeU, 0xd2U, 0xa6U,
				0xabU, 0xf7U, 0x15U, 0x88U,
				0x09U, 0xcfU, 0x4fU, 0x3c
		},
		.output = {
				0x76U, 0x49U, 0xabU, 0xacU,
				0x81U, 0x19U, 0xb2U, 0x46U,
				0xceU, 0xe9U, 0x8eU, 0x9bU,
				0x12U, 0xe9U, 0x19U, 0x7dU
		},
		.key_bits = 128
};

/*
PHP Quality-checker
-------------------
https://github.com/ircmaxell/quality-checker/blob/master/
 tmp/gh_18/PHP-PasswordLib-master/test/Data/Vectors/aes-cbc.test-vectors

Set 2 vector 1
    mode=aes-cbc-192
    key=8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b
    iv=000102030405060708090A0B0C0D0E0F
    plain=6bc1bee22e409f96e93d7e117393172a
    cipher=4f021db243bc633d7178183a9fa071e8
*/
const tv aes_192_cbc_tv = {
		.m = paracrypt::BlockCipher::CBC,
		.input = {
				0x6bU, 0xc1U, 0xbeU, 0xe2U,
				0x2eU, 0x40U, 0x9fU, 0x96U,
				0xe9U, 0x3dU, 0x7eU, 0x11U,
				0x73U, 0x93U, 0x17U, 0x2aU
		},
		.iv = {
				0x00U, 0x01U, 0x02U, 0x03,
				0x04U, 0x05U, 0x06U, 0x07,
				0x08U, 0x09U, 0x0AU, 0x0B,
				0x0CU, 0x0DU, 0x0EU, 0x0F
		},
		.key = {
				0x8eU, 0x73U, 0xb0U, 0xf7U,
				0xdaU, 0x0eU, 0x64U, 0x52U,
				0xc8U, 0x10U, 0xf3U, 0x2bU,
				0x80U, 0x90U, 0x79U, 0xe5U,
				0x62U, 0xf8U, 0xeaU, 0xd2U,
				0x52U, 0x2cU, 0x6bU, 0x7bU
		},
		.output = {
				0x4fU, 0x02U, 0x1dU, 0xb2U,
				0x43U, 0xbcU, 0x63U, 0x3dU,
				0x71U, 0x78U, 0x18U, 0x3aU,
				0x9fU, 0xa0U, 0x71U, 0xe8U
		},
		.key_bits = 192
};

/*
PHP Quality-checker
-------------------
https://github.com/ircmaxell/quality-checker/blob/master/
 tmp/gh_18/PHP-PasswordLib-master/test/Data/Vectors/aes-cbc.test-vectors

Set 3 vector 1
    mode=aes-cbc-256
    key=603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4
    iv=000102030405060708090A0B0C0D0E0F
    plain=6bc1bee22e409f96e93d7e117393172a
    cipher=f58c4c04d6e5f1ba779eabfb5f7bfbd6
*/
const tv aes_256_cbc_tv = {
		.m = paracrypt::BlockCipher::CBC,
		.input = {
				0x6bU, 0xc1U, 0xbeU, 0xe2U,
				0x2eU, 0x40U, 0x9fU, 0x96U,
				0xe9U, 0x3dU, 0x7eU, 0x11U,
				0x73U, 0x93U, 0x17U, 0x2aU
		},
		.iv = {
				0x00U, 0x01U, 0x02U, 0x03,
				0x04U, 0x05U, 0x06U, 0x07,
				0x08U, 0x09U, 0x0AU, 0x0B,
				0x0CU, 0x0DU, 0x0EU, 0x0F
		},
		.key = {
				0x60U, 0x3dU, 0xebU, 0x10U,
				0x15U, 0xcaU, 0x71U, 0xbeU,
				0x2bU, 0x73U, 0xaeU, 0xf0U,
				0x85U, 0x7dU, 0x77U, 0x81U,
				0x1fU, 0x35U, 0x2cU, 0x07U,
				0x3bU, 0x61U, 0x08U, 0xd7U,
				0x2dU, 0x98U, 0x10U, 0xa3U,
				0x09U, 0x14U, 0xdfU, 0xf4U
		},
		.output = {
				0xf5U, 0x8cU, 0x4cU, 0x04U,
				0xd6U, 0xe5U, 0xf1U, 0xbaU,
				0x77U, 0x9eU, 0xabU, 0xfbU,
				0x5fU, 0x7bU, 0xfbU, 0xd6U
		},
		.key_bits = 256
};

/*
PHP Quality-checker
-------------------
https://github.com/ircmaxell/quality-checker/blob/master/
 tmp/gh_18/PHP-PasswordLib-master/test/Data/Vectors/aes-cfb.test-vectors

Set 1 vector 1
    mode=aes-cfb-128
    key=2b7e151628aed2a6abf7158809cf4f3c
    iv=000102030405060708090A0B0C0D0E0F
    plain=6bc1bee22e409f96e93d7e117393172a
	cipher=3b3fd92eb72dad20333449f8e83cfb4a
*/
const tv aes_128_cfb_tv = {
		.m = paracrypt::BlockCipher::CFB,
		.input = {
				0x6bU, 0xc1U, 0xbeU, 0xe2U,
				0x2eU, 0x40U, 0x9fU, 0x96U,
				0xe9U, 0x3dU, 0x7eU, 0x11U,
				0x73U, 0x93U, 0x17U, 0x2aU
		},
		.iv = {
				0x00U, 0x01U, 0x02U, 0x03,
				0x04U, 0x05U, 0x06U, 0x07,
				0x08U, 0x09U, 0x0AU, 0x0B,
				0x0CU, 0x0DU, 0x0EU, 0x0F
		},
		.key = {
				0x2bU, 0x7eU, 0x15U, 0x16U,
				0x28U, 0xaeU, 0xd2U, 0xa6U,
				0xabU, 0xf7U, 0x15U, 0x88U,
				0x09U, 0xcfU, 0x4fU, 0x3c
		},
		.output = {
				0x3bU, 0x3fU, 0xd9U, 0x2eU,
				0xb7U, 0x2dU, 0xadU, 0x20U,
				0x33U, 0x34U, 0x49U, 0xf8U,
				0xe8U, 0x3cU, 0xfbU, 0x4aU
		},
		.key_bits = 128
};

/*
PHP Quality-checker
-------------------
https://github.com/ircmaxell/quality-checker/blob/master/
 tmp/gh_18/PHP-PasswordLib-master/test/Data/Vectors/aes-cfb.test-vectors

Set 2 vector 1
    mode=aes-cfb-192
    key=8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b
    iv=000102030405060708090A0B0C0D0E0F
    plain=6bc1bee22e409f96e93d7e117393172a
	cipher=cdc80d6fddf18cab34c25909c99a4174
*/
const tv aes_192_cfb_tv = {
		.m = paracrypt::BlockCipher::CFB,
		.input = {
				0x6bU, 0xc1U, 0xbeU, 0xe2U,
				0x2eU, 0x40U, 0x9fU, 0x96U,
				0xe9U, 0x3dU, 0x7eU, 0x11U,
				0x73U, 0x93U, 0x17U, 0x2aU
		},
		.iv = {
				0x00U, 0x01U, 0x02U, 0x03,
				0x04U, 0x05U, 0x06U, 0x07,
				0x08U, 0x09U, 0x0AU, 0x0B,
				0x0CU, 0x0DU, 0x0EU, 0x0F
		},
		.key = {
				0x8eU, 0x73U, 0xb0U, 0xf7U,
				0xdaU, 0x0eU, 0x64U, 0x52U,
				0xc8U, 0x10U, 0xf3U, 0x2bU,
				0x80U, 0x90U, 0x79U, 0xe5U,
				0x62U, 0xf8U, 0xeaU, 0xd2U,
				0x52U, 0x2cU, 0x6bU, 0x7bU
		},
		.output = {
				0xcdU, 0xc8U, 0x0dU, 0x6fU,
				0xddU, 0xf1U, 0x8cU, 0xabU,
				0x34U, 0xc2U, 0x59U, 0x09U,
				0xc9U, 0x9aU, 0x41U, 0x74U
		},
		.key_bits = 192
};

/*
PHP Quality-checker
-------------------
https://github.com/ircmaxell/quality-checker/blob/master/
 tmp/gh_18/PHP-PasswordLib-master/test/Data/Vectors/aes-cfb.test-vectors

Set 3 vector 1
    mode=aes-cfb-256
    key=603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4
    iv=000102030405060708090A0B0C0D0E0F
    plain=6bc1bee22e409f96e93d7e117393172a
	cipher=DC7E84BFDA79164B7ECD8486985D3860
*/
const tv aes_256_cfb_tv = {
		.m = paracrypt::BlockCipher::CFB,
		.input = {
				0x6bU, 0xc1U, 0xbeU, 0xe2U,
				0x2eU, 0x40U, 0x9fU, 0x96U,
				0xe9U, 0x3dU, 0x7eU, 0x11U,
				0x73U, 0x93U, 0x17U, 0x2aU
		},
		.iv = {
				0x00U, 0x01U, 0x02U, 0x03,
				0x04U, 0x05U, 0x06U, 0x07,
				0x08U, 0x09U, 0x0AU, 0x0B,
				0x0CU, 0x0DU, 0x0EU, 0x0F
		},
		.key = {
				0x60U, 0x3dU, 0xebU, 0x10U,
				0x15U, 0xcaU, 0x71U, 0xbeU,
				0x2bU, 0x73U, 0xaeU, 0xf0U,
				0x85U, 0x7dU, 0x77U, 0x81U,
				0x1fU, 0x35U, 0x2cU, 0x07U,
				0x3bU, 0x61U, 0x08U, 0xd7U,
				0x2dU, 0x98U, 0x10U, 0xa3U,
				0x09U, 0x14U, 0xdfU, 0xf4U
		},
		.output = {
				0xDCU, 0x7EU, 0x84U, 0xBFU,
				0xDAU, 0x79U, 0x16U, 0x4BU,
				0x7EU, 0xCDU, 0x84U, 0x86U,
				0x98U, 0x5DU, 0x38U, 0x60U
		},
		.key_bits = 256
};

const tv aes_128_ctr_dummy_tv = {
		.m = paracrypt::BlockCipher::CTR,
		.input = {
				0x6bU, 0xc1U, 0xbeU, 0xe2U,
				0x2eU, 0x40U, 0x9fU, 0x96U,
				0xe9U, 0x3dU, 0x7eU, 0x11U,
				0x73U, 0x93U, 0x17U, 0x2aU
		},
		.iv = {
				0x00U, 0x01U, 0x02U, 0x03,
				0x04U, 0x05U, 0x06U, 0x07,
				0x08U, 0x09U, 0x0AU, 0x0B,
				0x0CU, 0x0DU, 0x0EU, 0x0F
		},
		.key = {
				0x2bU, 0x7eU, 0x15U, 0x16U,
				0x28U, 0xaeU, 0xd2U, 0xa6U,
				0xabU, 0xf7U, 0x15U, 0x88U,
				0x09U, 0xcfU, 0x4fU, 0x3c
		},
		.output = {}, // No output ...
		// this test vector is used to
		// encrypt, decrypt, and check
		// that the same input is obtained.
		.key_bits = 128
};

const tv aes_192_ctr_dummy_tv = {
		.m = paracrypt::BlockCipher::CTR,
		.input = {
				0x6bU, 0xc1U, 0xbeU, 0xe2U,
				0x2eU, 0x40U, 0x9fU, 0x96U,
				0xe9U, 0x3dU, 0x7eU, 0x11U,
				0x73U, 0x93U, 0x17U, 0x2aU
		},
		.iv = {
				0x00U, 0x01U, 0x02U, 0x03,
				0x04U, 0x05U, 0x06U, 0x07,
				0x08U, 0x09U, 0x0AU, 0x0B,
				0x0CU, 0x0DU, 0x0EU, 0x0F
		},
		.key = {
				0x8eU, 0x73U, 0xb0U, 0xf7U,
				0xdaU, 0x0eU, 0x64U, 0x52U,
				0xc8U, 0x10U, 0xf3U, 0x2bU,
				0x80U, 0x90U, 0x79U, 0xe5U,
				0x62U, 0xf8U, 0xeaU, 0xd2U,
				0x52U, 0x2cU, 0x6bU, 0x7bU
		},
		.output = {}, // No output ...
		// this test vector is used to
		// encrypt, decrypt, and check
		// that the same input is obtained.
		.key_bits = 192
};

const tv aes_256_ctr_dummy_tv = {
		.m = paracrypt::BlockCipher::CTR,
		.input = {
				0x6bU, 0xc1U, 0xbeU, 0xe2U,
				0x2eU, 0x40U, 0x9fU, 0x96U,
				0xe9U, 0x3dU, 0x7eU, 0x11U,
				0x73U, 0x93U, 0x17U, 0x2aU
		},
		.iv = {
				0x00U, 0x01U, 0x02U, 0x03,
				0x04U, 0x05U, 0x06U, 0x07,
				0x08U, 0x09U, 0x0AU, 0x0B,
				0x0CU, 0x0DU, 0x0EU, 0x0F
		},
		.key = {
				0x60U, 0x3dU, 0xebU, 0x10U,
				0x15U, 0xcaU, 0x71U, 0xbeU,
				0x2bU, 0x73U, 0xaeU, 0xf0U,
				0x85U, 0x7dU, 0x77U, 0x81U,
				0x1fU, 0x35U, 0x2cU, 0x07U,
				0x3bU, 0x61U, 0x08U, 0xd7U,
				0x2dU, 0x98U, 0x10U, 0xa3U,
				0x09U, 0x14U, 0xdfU, 0xf4U
		},
		.output = {}, // No output ...
		// this test vector is used to
		// encrypt, decrypt, and check
		// that the same input is obtained.
		.key_bits = 256
};

tv get_aes_tv(unsigned int key_bits) {
	switch(key_bits) {
	case 128:
		return aes_example;
		break;
	case 192:
		return aes_192_tv;
		break;
	case 256:
		return aes_256_tv;
		break;
	default:
		ERR("Wrong AES key size");
	}
}

/*
 * Encrypts a random input string, decrypts it,
 * and checks if the result is the same original
 * string.
 */
// TODO remove key_bits argument not needed with tv
void AES_RDN_TEST(std::string title, tv vector_key, paracrypt::CudaAES* aes, paracrypt::CUDACipherDevice* dev, int key_bits, bool constantKey, bool constantTables)
{
	int data_length = random_data_n_blocks*16;
    unsigned char *result = (unsigned char*) malloc(data_length);

    aes->constantKey(constantKey);
    aes->constantTables(constantTables);
    aes->setKey(vector_key.key,vector_key.key_bits);
    aes->setDevice(dev);
    aes->malloc(random_data_n_blocks);

    Timer* t = new Timer();
    t->tic();
    aes->encrypt(random_data, result, random_data_n_blocks);
    aes->waitFinish();
    double sec = t->toc_seconds();
    LOG_INF(boost::format("%s needs %f seconds to encrypt %d blocks\n") % title.c_str() % sec % random_data_n_blocks);
    for(int i=0;i<random_data_n_blocks*4;i++) {
    	//LOG_TRACE(boost::format("block %d") % i);
    	BOOST_REQUIRE(((uint32_t*)result)[i] != ((uint32_t*)random_data)[i]);
    }

    t->tic();
    aes->decrypt(result, result, random_data_n_blocks);
    aes->waitFinish();
    sec = t->toc_seconds();
    LOG_INF(boost::format("%s needs %f seconds to decrypt %d blocks\n") % title.c_str() % sec % random_data_n_blocks);

   	BOOST_CHECK_EQUAL_COLLECTIONS((uint32_t*)result,((uint32_t*)result)+random_data_n_blocks,((uint32_t*)random_data),((uint32_t*)random_data)+random_data_n_blocks);
    free(result);
}

void AES_VECTOR_RDN_TEST(
		std::string title,
		tv vector_key,
		paracrypt::CudaAES* aes,
		paracrypt::CUDACipherDevice* dev,
		bool constantKey,
		bool constantTables,
		bool checkOutput = true,
		bool checkEachOutputDifferent = false,
		int maxNBlocks = 10000000
){
	int nBlocks = std::min(maxNBlocks,random_data_n_blocks);

	int data_length = nBlocks*16;
	unsigned char *result = (unsigned char*) malloc(data_length);
    for(int i=0; i < nBlocks; i++) {
    	memcpy(result+(i*16),vector_key.input,16);
    }

    aes->setDevice(dev);
    aes->setMode(vector_key.m);
    if(vector_key.m != paracrypt::BlockCipher::ECB)
    	aes->setIV(vector_key.iv,128);
    aes->setKey(vector_key.key,vector_key.key_bits);
    aes->constantKey(constantKey);
    aes->constantTables(constantTables);
    aes->malloc(nBlocks);

    Timer* t = new Timer();
    t->tic();
    aes->encrypt(result, result, nBlocks);
    aes->waitFinish();
    double sec = t->toc_seconds();
    LOG_INF(boost::format("%s needs %f seconds to encrypt %d blocks\n") % title.c_str() % sec % nBlocks);
    if(checkOutput) {
		for(int i=0;i<nBlocks*4;i++) {
			//LOG_TRACE(boost::format("block %d") % i);
			BOOST_REQUIRE_EQUAL(((uint32_t*)result)[i], ((uint32_t*)vector_key.output)[i%4]);
		}
    }
    if(checkEachOutputDifferent && nBlocks >= 2){
		for(int i=1;i<nBlocks*4;i++) {
			//LOG_TRACE(boost::format("block %d") % i);
			BOOST_REQUIRE( ((uint32_t*)result)[i-4] != ((uint32_t*)result)[i] );
		}
    }

    t->tic();
    aes->decrypt(result, result, nBlocks);
    aes->waitFinish();
    sec = t->toc_seconds();
    LOG_INF(boost::format("%s needs %f seconds to decrypt %d blocks\n") % title.c_str() % sec % nBlocks);

    for(int i=0;i<nBlocks*4;i++) {
    	//LOG_TRACE(boost::format("block %d") % i);
    	BOOST_REQUIRE_EQUAL(((uint32_t*)result)[i], ((uint32_t*)vector_key.input)[i%4]);
    }
    free(result);
}

void AES_SB_ENCRYPT_TEST(std::string title, tv vector, int n_blocks, paracrypt::CudaAES* aes, paracrypt::CUDACipherDevice* dev, bool constantKey, bool constantTables, bool iv = false)
{
	LOG_TRACE(boost::format("Executing %s...") % title.c_str());
    unsigned char data[16*n_blocks];
    for(int i=0; i < n_blocks; i++) {
    	 memcpy(data+(i*16),vector.input,16);
    }

    aes->setDevice(dev);
    aes->setMode(vector.m);
    if(iv)
    	aes->setIV(vector.iv,128);
    aes->setKey(vector.key,vector.key_bits);
    aes->constantKey(constantKey);
    aes->constantTables(constantTables);
    aes->malloc(n_blocks);
    aes->encrypt((unsigned char *) &data, (unsigned char *) &data, n_blocks);
    aes->waitFinish();

    // first block hexdump
    hexdump("expected",vector.output,16);
    hexdump("data",data,16);

    for(int i=0; i < n_blocks; i++) {
    	BOOST_REQUIRE_EQUAL_COLLECTIONS(data+(i*16),data+(i*16)+16,vector.output,vector.output+16);
    }
}

void AES_SB_DECRYPT_TEST(std::string title, tv vector, int n_blocks, paracrypt::CudaAES* aes, paracrypt::CUDACipherDevice* dev, bool constantKey, bool constantTables, bool iv = false)
{
	LOG_TRACE(boost::format("Executing %s...") % title.c_str());
    unsigned char data[16*n_blocks];
    for(int i=0; i < n_blocks; i++) {
    	memcpy(data+(i*16),vector.output,16);
    }

    aes->setDevice(dev);
    aes->setMode(vector.m);
    if(iv)
    	aes->setIV(vector.iv,128);
    aes->setKey(vector.key,vector.key_bits);
    aes->constantKey(constantKey);
    aes->constantTables(constantTables);
    aes->malloc(n_blocks);
    aes->decrypt((unsigned char *) &data, (unsigned char *) &data, n_blocks);
    aes->waitFinish();

    // first block hexdump
    hexdump("expected",vector.input,16);
    hexdump("data",data,16);

    for(int i=0; i < n_blocks; i++) {
    	BOOST_REQUIRE_EQUAL_COLLECTIONS(data+(i*16),data+(i*16)+16,vector.input,vector.input+16);
    }
}

#ifdef OPENSSL_EXISTS
// from https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption
void handleErrors(void)
{
  ERR_print_errors_fp(stderr);
  abort();
}
int AES_encrypt(const EVP_CIPHER * cipher, unsigned char *plaintext, int plaintext_len, unsigned char *key,
  unsigned char *iv, unsigned char *ciphertext)
{
  EVP_CIPHER_CTX *ctx;

  int len;

  int ciphertext_len;

  /* Create and initialise the context */
  if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

  /* Initialise the encryption operation. IMPORTANT - ensure you use a key
   * and IV size appropriate for your cipher
   * In this example we are using 256 bit AES (i.e. a 256 bit key). The
   * IV size for *most* modes is the same as the block size. For AES this
   * is 128 bits */
  if(1 != EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv))
    handleErrors();

  /* Provide the message to be encrypted, and obtain the encrypted output.
   * EVP_EncryptUpdate can be called multiple times if necessary
   */
  if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
    handleErrors();
  ciphertext_len = len;

  /* Finalise the encryption. Further ciphertext bytes may be written at
   * this stage.
   */
  if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
  ciphertext_len += len;

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  return ciphertext_len;
}

/////////////////////////////////////////////////////////////
// - Uses OpenSSL to encrypt and paracrypt to decrypt.
// - Checks that we obtain the same original message
void AES_RANDOM_DECRYPT_TEST(std::string title,
		tv vector_key,
		const EVP_CIPHER * openSSLCipher,
		paracrypt::CudaAES* aes,
		paracrypt::CUDACipherDevice* dev,
		bool constantKey,
		bool constantTables,
		int maxNBlocks = 10000000)
{
	/* OpenSSL Encryption *********************************************************/
	unsigned char *key = (unsigned char*) vector_key.key;
	unsigned char *iv = (unsigned char*) vector_key.iv;

	int nBlocks = std::min(maxNBlocks,random_data_n_blocks);

	int data_length = nBlocks*16;
	unsigned char *plaintext = (unsigned char*) malloc(data_length);
    for(int i=0; i < nBlocks; i++) {
    	memcpy(plaintext+(i*16),random_data+(i*16),16);
    }

    unsigned char *result = (unsigned char*) malloc(data_length+16);
    int ciphertext_len;

    /* Encrypt the plaintext */
    ciphertext_len = AES_encrypt (openSSLCipher, plaintext, data_length, key, iv, result);
    if(ciphertext_len == data_length+16) {
    	ciphertext_len -= 16;
    }
    BOOST_REQUIRE_EQUAL(ciphertext_len,data_length);
	/******************************************************************************/

    aes->setDevice(dev);
    aes->setMode(vector_key.m);
    if(iv)
    	aes->setIV(vector_key.iv,128);
    aes->setKey(vector_key.key,vector_key.key_bits);
    aes->constantKey(constantKey);
    aes->constantTables(constantTables);
    aes->malloc(nBlocks);

    Timer* t = new Timer();
    t->tic();
    aes->decrypt(result, result, nBlocks);
    aes->waitFinish();
    double sec = t->toc_seconds();
    LOG_INF(boost::format("%s needs %f seconds to decrypt %d blocks\n") % title.c_str() % sec % nBlocks);

    for(int i=0;i<nBlocks*4;i++) {
//    	if(i%4 == 0)
//    		LOG_TRACE(boost::format("block %d") % (i/4)); // TODO COMMENT
    	BOOST_REQUIRE_EQUAL(((uint32_t*)result)[i], ((uint32_t*)plaintext)[i]);
    }
    free(plaintext);
    free(result);
}
#endif

#define AES_TEST_SUITE_KEYSIZE(id, testName, className, tv, keyBitsStr) \
	BOOST_AUTO_TEST_SUITE(id) \
		BOOST_AUTO_TEST_CASE(kc_tc_single) \
		{ \
			paracrypt::CudaAES * aes = new className; \
			AES_SB_ENCRYPT_TEST("AES"keyBitsStr"-ECB example vector | " testName " with constant key and t-table", \
					tv,1,aes,gpu,true,true); \
			delete aes; \
		} \
		BOOST_AUTO_TEST_CASE(kc_tc_single_decrypt) \
		{ \
			paracrypt::CudaAES * aes = new className; \
			AES_SB_DECRYPT_TEST( "AES"keyBitsStr"-ECB example decrypt vector | " testName " with constant key and t-table", \
					tv,1,aes,gpu,true,true); \
			delete aes; \
		} \
		BOOST_AUTO_TEST_CASE(kc_tc_2blocks) \
		{ \
			paracrypt::CudaAES * aes = new className; \
			AES_SB_ENCRYPT_TEST( "AES"keyBitsStr"-ECB example vector | " testName " with constant key and t-table", \
					tv,2,aes,gpu,true,true); \
			delete aes; \
		} \
		BOOST_AUTO_TEST_CASE(kc_tc_2blocks_decrypt) \
		{ \
			paracrypt::CudaAES * aes = new className; \
			AES_SB_DECRYPT_TEST( "AES"keyBitsStr"-ECB example decrypt vector | " testName " with constant key and t-table", \
					tv,2,aes,gpu,true,true); \
			delete aes; \
		} \
		BOOST_AUTO_TEST_CASE(kc_tc_nblocks) \
		{ \
			paracrypt::CudaAES * aes = new className; \
			AES_VECTOR_RDN_TEST( "AES"keyBitsStr"-ECB (" testName ") n blocks with and constant key and t-table", \
					tv,aes,gpu,true,true); \
			delete aes; \
		} \
		BOOST_AUTO_TEST_CASE(kc_nblocks) \
		{ \
			paracrypt::CudaAES * aes = new className; \
			AES_VECTOR_RDN_TEST( "AES"keyBitsStr"-ECB (" testName ") n blocks with and constant key", \
					tv,aes,gpu,true,false); \
			delete aes; \
		} \
		BOOST_AUTO_TEST_CASE(tc_nblocks) \
		{ \
			paracrypt::CudaAES * aes = new className; \
			AES_VECTOR_RDN_TEST( "AES"keyBitsStr"-ECB (" testName ") n blocks with and constant t-table", \
					tv,aes,gpu,false,true); \
			delete aes; \
		} \
		BOOST_AUTO_TEST_CASE(nblocks) \
		{ \
			paracrypt::CudaAES * aes = new className; \
			AES_VECTOR_RDN_TEST( "AES"keyBitsStr"-ECB (" testName ") n blocks with and dynamic key and t-table", \
					tv,aes,gpu,false,false); \
			delete aes; \
		} \
		BOOST_AUTO_TEST_CASE(kc_tc_random) \
		{ \
			paracrypt::CudaAES * aes = new className; \
			AES_RDN_TEST( "AES"keyBitsStr"-ECB (" testName ") with random data and constant key and t-table", \
					tv,aes,gpu,128,true,true); \
			delete aes; \
		} \
		BOOST_AUTO_TEST_CASE(kc_random) \
		{ \
			paracrypt::CudaAES * aes = new className; \
			AES_RDN_TEST( "AES"keyBitsStr"-ECB (" testName ") with random data and constant key", \
					tv,aes,gpu,128,true,false); \
			delete aes; \
		} \
		BOOST_AUTO_TEST_CASE(tc_random) \
		{ \
			paracrypt::CudaAES * aes = new className; \
			AES_RDN_TEST( "AES"keyBitsStr"-ECB (" testName ") with random data and constant t-table", \
					tv,aes,gpu,128,false,true); \
			delete aes; \
		} \
		BOOST_AUTO_TEST_CASE(random) \
		{ \
			paracrypt::CudaAES * aes = new className; \
			AES_RDN_TEST( "AES"keyBitsStr"-ECB (" testName ") with random data and dynamic key and t-table", \
					tv,aes,gpu,128,false,false); \
			delete aes; \
		} \
	BOOST_AUTO_TEST_SUITE_END()


#define AES_TEST_SUITE_ENCRYPT_AND_DECRYPT(id, testName, className, tv, tipeStr) \
	BOOST_AUTO_TEST_SUITE(id) \
		BOOST_AUTO_TEST_CASE(random_1block) \
		{ \
			paracrypt::CudaAES * aes = new className; \
			AES_VECTOR_RDN_TEST( "AES"tipeStr" (" testName ") with random data and dynamic key and t-table", \
					tv,aes,gpu,false,false,false,true,1); \
			delete aes; \
		} \
		BOOST_AUTO_TEST_CASE(random_2blocks) \
		{ \
			paracrypt::CudaAES * aes = new className; \
			AES_VECTOR_RDN_TEST( "AES"tipeStr" (" testName ") with random data and dynamic key and t-table", \
					tv,aes,gpu,false,false,false,true,2); \
			delete aes; \
		} \
		BOOST_AUTO_TEST_CASE(random) \
		{ \
			paracrypt::CudaAES * aes = new className; \
			AES_VECTOR_RDN_TEST( "AES"tipeStr" (" testName ") with random data and dynamic key and t-table", \
					tv,aes,gpu,false,false,false,true); \
			delete aes; \
		} \
	BOOST_AUTO_TEST_SUITE_END()


// to use with CBC and CFB
#ifdef OPENSSL_EXISTS
#define AES_CHAINMODE_TEST_SUITE_KEYSIZE(id, testName, className, EVP_encryption, tv, tipeStr) \
		BOOST_AUTO_TEST_SUITE(id) \
			BOOST_AUTO_TEST_CASE(kc_tc_single) \
			{ \
				paracrypt::CudaAES * aes = new className; \
				AES_SB_DECRYPT_TEST("AES"tipeStr" example vector | " testName " with constant key and t-table", \
						tv,1,aes,gpu,true,true,true); \
				delete aes; \
			} \
			BOOST_AUTO_TEST_CASE(random_decrypt_2blocks) \
			{ \
				paracrypt::CudaAES * aes = new className; \
				AES_RANDOM_DECRYPT_TEST("AES"tipeStr" example vector | " \
						testName " decryption with with random data and constant key and t-table", \
						tv,EVP_encryption,aes,gpu,true,true,2); \
				delete aes; \
			} \
			BOOST_AUTO_TEST_CASE(random_decrypt_65blocks) \
			{ \
				paracrypt::CudaAES * aes = new className; \
				AES_RANDOM_DECRYPT_TEST("AES"tipeStr" example vector | " \
						testName " decryption with with random data and constant key and t-table", \
						tv,EVP_encryption,aes,gpu,true,true,65); \
				delete aes; \
			} \
			BOOST_AUTO_TEST_CASE(random_decrypt) \
			{ \
				paracrypt::CudaAES * aes = new className; \
				AES_RANDOM_DECRYPT_TEST("AES"tipeStr" example vector | " \
						testName " decryption with with random data and constant key and t-table", \
						tv,EVP_encryption,aes,gpu,true,true); \
				delete aes; \
			} \
		BOOST_AUTO_TEST_SUITE_END()
#else
#define AES_CHAINMODE_TEST_SUITE_KEYSIZE(id, testName, className, tv, tipeStr) \
		BOOST_AUTO_TEST_SUITE(id) \
			BOOST_AUTO_TEST_CASE(kc_tc_single) \
			{ \
				paracrypt::CudaAES * aes = new className; \
				AES_SB_DECRYPT_TEST("AES"tipeStr" example vector | " testName " with constant key and t-table", \
						aes_128_cbc_tv,1,aes,gpu,true,true,true); \
				delete aes; \
			} \
		BOOST_AUTO_TEST_SUITE_END()
#endif

#ifdef OPENSSL_EXISTS
#define AES_TEST_SUITE(id, testName, className) \
	BOOST_AUTO_TEST_SUITE(id) \
		AES_TEST_SUITE_KEYSIZE(AES_128_ECB, testName, className, aes_example, "128"); \
		AES_TEST_SUITE_KEYSIZE(AES_192_ECB, testName, className, aes_192_tv, "192"); \
		AES_TEST_SUITE_KEYSIZE(AES_256_ECB, testName, className, aes_256_tv, "256"); \
		AES_CHAINMODE_TEST_SUITE_KEYSIZE(AES_128_CBC, testName, className, EVP_aes_128_cbc(), aes_128_cbc_tv, "128-CBC"); \
		AES_CHAINMODE_TEST_SUITE_KEYSIZE(AES_192_CBC, testName, className, EVP_aes_192_cbc(), aes_192_cbc_tv, "192-CBC"); \
		AES_CHAINMODE_TEST_SUITE_KEYSIZE(AES_256_CBC, testName, className, EVP_aes_256_cbc(), aes_256_cbc_tv, "256-CBC"); \
		AES_CHAINMODE_TEST_SUITE_KEYSIZE(AES_128_CFB, testName, className, EVP_aes_128_cfb(), aes_128_cfb_tv, "128-CFB"); \
		AES_CHAINMODE_TEST_SUITE_KEYSIZE(AES_192_CFB, testName, className, EVP_aes_192_cfb(), aes_192_cfb_tv, "192-CFB"); \
		AES_CHAINMODE_TEST_SUITE_KEYSIZE(AES_256_CFB, testName, className, EVP_aes_256_cfb(), aes_256_cfb_tv, "256-CFB"); \
		AES_TEST_SUITE_ENCRYPT_AND_DECRYPT(AES_128_PTR, testName, className, aes_128_ctr_dummy_tv, "128-PTR") \
		AES_TEST_SUITE_ENCRYPT_AND_DECRYPT(AES_192_PTR, testName, className, aes_192_ctr_dummy_tv, "192-PTR") \
		AES_TEST_SUITE_ENCRYPT_AND_DECRYPT(AES_256_PTR, testName, className, aes_256_ctr_dummy_tv, "256-PTR") \
	BOOST_AUTO_TEST_SUITE_END()
#else
#define AES_TEST_SUITE(id, testName, className) \
	BOOST_AUTO_TEST_SUITE(id) \
		AES_TEST_SUITE_KEYSIZE(AES_128_ECB, testName, className, aes_example, "128"); \
		AES_TEST_SUITE_KEYSIZE(AES_192_ECB, testName, className, aes_192_tv, "192"); \
		AES_TEST_SUITE_KEYSIZE(AES_256_ECB, testName, className, aes_256_tv, "256"); \
		AES_TEST_SUITE_ENCRYPT_AND_DECRYPT(AES_128_PTR, testName, className, aes_128_ctr_dummy_tv, "128-PTR") \
		AES_TEST_SUITE_ENCRYPT_AND_DECRYPT(AES_192_PTR, testName, className, aes_192_ctr_dummy_tv, "192-PTR") \
		AES_TEST_SUITE_ENCRYPT_AND_DECRYPT(AES_256_PTR, testName, className, aes_256_ctr_dummy_tv, "256-PTR") \
	BOOST_AUTO_TEST_SUITE_END()
#endif

BOOST_AUTO_TEST_SUITE(CUDA_AES)
	AES_TEST_SUITE(CUDA_AES_16B, "16B parallelism", paracrypt::CudaAES16B());
	AES_TEST_SUITE(CUDA_AES_16B_PTR, "16B (ptr) parallelism", paracrypt::CudaAES16BPtr());
	AES_TEST_SUITE(CUDA_AES_8B, "8B parallelism", paracrypt::CudaAES8B());
	AES_TEST_SUITE(CUDA_AES_8B_PTR, "8B (ptr) parallelism", paracrypt::CudaAES8BPtr());
	AES_TEST_SUITE(CUDA_AES_4B, "4B parallelism", paracrypt::CudaAES4B());
	AES_TEST_SUITE(CUDA_AES_4B_PTR, "4B (ptr) parallelism", paracrypt::CudaAES4BPtr());
	AES_TEST_SUITE(CUDA_AES_1B, "1B parallelism", paracrypt::CudaAES1B());
BOOST_AUTO_TEST_SUITE_END()

//
// - Creates a input file where each (word) block value is its index except
//   for the last block which can be half-empty. In this case each
//   byte value of the last block is its byte index.
//
//   Block size is 128 bits
//
void GEN_128BPB_IO_FILES(
		std::string *inFileName,
		std::fstream **inFile,
		std::string *outFileName,
		std::fstream **outFile,
		unsigned int blockSize,
		std::streampos totalNBytes,
		bool print=false
){
	{
		char nameBuffer [L_tmpnam];
		std::tmpnam (nameBuffer);
		(*inFileName) = std::string(nameBuffer);
		std::tmpnam (nameBuffer);
		(*outFileName) = std::string(nameBuffer);
	}

	(*inFile) = new std::fstream(inFileName->c_str(),std::fstream::out | std::fstream::binary);
	if(!(*inFile)) {
		FATAL(boost::format("Error creating test input file: %s\n") % strerror(errno));
	}
	(*outFile) = new std::fstream(outFileName->c_str(),std::fstream::out | std::fstream::binary);
	if(!(*outFile)) {
		FATAL(boost::format("Error creating test input file: %s\n") % strerror(errno));
	}

	uint32_t buffer[4];
	std::streampos nBlocks = totalNBytes / blockSize;
	unsigned int remainingBytes = totalNBytes % blockSize;
	for(uint32_t i = 0; i < nBlocks; i++) {
		buffer[0] = i;
		buffer[1] = i;
		buffer[2] = i;
		buffer[3] = i;
		(*inFile)->write((const char*) buffer,4*4);
	}
	for(uint8_t i = 0; i < remainingBytes; i++) {
		(*inFile)->write((const char*) &i,1);
	}
	(*inFile)->flush();
	if(print)
		fdump("input file",*inFileName);
}
void CLOSE_IO_FILES(std::fstream** inFile, std::fstream** outFile)
{
	(*inFile)->close();
	(*outFile)->close();
	delete (*inFile);
	delete (*outFile);
}
//
// - Reads the file using a SharedIO object and checks the read
//    value is correct. Then multiplies the value by two and write
//    it to the output file using the SharedIO object. The first byte
//    of the padding block is incremented by one.
//
// - Finally checks that the output file is correct.
//
void OUT_FILE_128BPB_CORRECTNESS_TEST(
		std::string outFilename,
		std::streamsize size,
		std::streampos beginBlock,
		bool reachPadding,
		const unsigned int remainingBytes
){
	char nameBuffer [L_tmpnam];
	std::tmpnam (nameBuffer); // dummy file
	paracrypt::SimpleIO *io = new paracrypt::SimpleCudaIO(outFilename,nameBuffer,16,AUTO_IO_BUFFER_LIMIT,0,size);
	io->setPadding(paracrypt::BlockIO::UNPADDED);
	paracrypt::BlockIO::chunk c;
	c.status = paracrypt::BlockIO::OK;
	uint32_t check[4];
	unsigned char* checkPtr = (unsigned char*) check;

	// check read correctness and use write interface
	while(c.status == paracrypt::SharedIO::OK) {
		c = io->read();
		uint32_t entireBlocks = remainingBytes > 0 ? c.nBlocks-1 : c.nBlocks;
		// verify n-1 blocks
		for(uint32_t i = 0; i < entireBlocks; i++) {
			uint32_t blockIndex = ((uint32_t) (beginBlock + c.blockOffset)) + i;
			check[0] = check[1] = check[2] = check[3] = blockIndex*2;
			BOOST_REQUIRE_EQUAL_COLLECTIONS(
					checkPtr, checkPtr+16,
					c.data+i*16, c.data+i*16+16
			);
		}
		if(c.status == paracrypt::SharedIO::END && reachPadding && remainingBytes > 0) {
			std::streampos byteIndex;
			for(uint8_t i = 0; i < remainingBytes; i++) {
				byteIndex = (c.nBlocks-1)*16 + i;
				if(i == 0) {
					BOOST_REQUIRE_EQUAL(i+1,c.data[byteIndex]);
				}
				else
					BOOST_REQUIRE_EQUAL(i,c.data[byteIndex]);
			}
			// verify padding correctness
			for(uint8_t i = remainingBytes; i < 16; i++) {
				byteIndex = (c.nBlocks-1)*16 + i;
				BOOST_REQUIRE_EQUAL(0,c.data[byteIndex]);
			}
		}
	}

	delete io;
}
void FILE_128BPB_IO_TEST(std::fstream *inFile, std::fstream *outFile, paracrypt::BlockIO* io, bool print=false)
{
	unsigned int blockSize = io->getBlockSize();
//	std::streamsize maxBlockRead = io->getMaxBlocksRead();
	std::streampos begin = io->getBegin();
	std::streampos beginBlock = begin/blockSize;
	std::streampos end = io->getEnd();
	paracrypt::BlockIO::paddingScheme p = io->getPadding();
	const std::streamsize inFSize = paracrypt::IO::fileSize((std::ifstream*)inFile);
	const unsigned int remainingBytes = inFSize % blockSize; // last block bytes
	uint8_t paddingSize = 16-remainingBytes;
	// end must be at the last remaining Bytes
	bool reachPadding = remainingBytes > 0 && (end == NO_RANDOM_ACCESS || end >= inFSize-((std::streampos)paddingSize));
	std::streamsize totalBlocksRead = 0;

	if(blockSize != 16) {
		FATAL("FILE_128BPB_SIMPLEIO_TEST can only accept a SimpleIO object with 128 bits (16B) block size.");
	} else {
		paracrypt::BlockIO::chunk c;
		c.status = paracrypt::BlockIO::OK;
		uint32_t check[4];
		unsigned char* checkPtr = (unsigned char*) check;

		// check read correctness and use write interface
		while(c.status == paracrypt::SharedIO::OK) {
			c = io->read();
			uint32_t entireBlocks = reachPadding && c.status == paracrypt::SharedIO::END ? c.nBlocks-1 : c.nBlocks;
			// verify n-1 blocks
			for(uint32_t i = 0; i < entireBlocks; i++) {
				totalBlocksRead++;
				uint32_t blockIndex = ((uint32_t) c.blockOffset) + i;
				check[0] = check[1] = check[2] = check[3] = blockIndex;
				BOOST_REQUIRE_EQUAL_COLLECTIONS(
						checkPtr, checkPtr+16,
						c.data+i*16, c.data+i*16+16
				);
				// multiply by 2 each read word
				*((uint32_t*)(c.data+i*16+0 )) *= 2;
				*((uint32_t*)(c.data+i*16+4 )) *= 2;
				*((uint32_t*)(c.data+i*16+8 )) *= 2;
				*((uint32_t*)(c.data+i*16+12)) *= 2;
			}
			if(c.status == paracrypt::SharedIO::END && reachPadding) {
				totalBlocksRead++;
				std::streampos byteIndex;
				for(uint8_t i = 0; i < remainingBytes; i++) {
					byteIndex = (c.nBlocks-1)*16 + i;
					BOOST_REQUIRE_EQUAL(i,c.data[byteIndex]);
				}
				// verify padding correctness
				for(uint8_t i = remainingBytes; i < 16; i++) {
					byteIndex = (c.nBlocks-1)*16 + i;
					if(p == paracrypt::BlockIO::UNPADDED) {
						BOOST_REQUIRE_EQUAL(0,c.data[byteIndex]);
					} else if(p == paracrypt::BlockIO::PKCS7)  {
						BOOST_REQUIRE_EQUAL(paddingSize,c.data[byteIndex]);
					}
				}
				// increment by one first byte of the padding block
				c.data[(c.nBlocks-1)*16]++;
			}
			if(totalBlocksRead > 0) {
				io->dump(c);
			}
		}

		std::string outFilename = io->getOutFileName();
		delete io; // data flushed when IO object is destructed

		// Check write correctness reading the file
		//  with a SimpleIO object.
		if(print)
			fdump("output file",outFilename);
		const std::streamsize outFSize = paracrypt::IO::fileSize((std::ifstream*)outFile);
		std::streamsize expectedSize = 0;
		if(totalBlocksRead != 0) {
			if(remainingBytes > 0 && p == paracrypt::BlockIO::PKCS7) {
//				expectedSize = (totalBlocksRead-1)*16+remainingBytes;
				expectedSize = end == NO_RANDOM_ACCESS ? (totalBlocksRead-1)*16+remainingBytes : std::min((totalBlocksRead-1)*16+remainingBytes,end-begin+1);
			}
			else {
//				expectedSize = totalBlocksRead*16;
				expectedSize = end == NO_RANDOM_ACCESS ? totalBlocksRead*16 : std::min(totalBlocksRead*16,end-begin+1);
			}
		}
		BOOST_REQUIRE_EQUAL(expectedSize,outFSize);

		OUT_FILE_128BPB_CORRECTNESS_TEST(
				outFilename,
				expectedSize,
				beginBlock,
				reachPadding,
				remainingBytes
		);
	}
}
void FILE_128BPB_SIMPLEIO_TEST(
		std::streampos totalNBytes,
		paracrypt::BlockIO::paddingScheme p = paracrypt::BlockIO::UNPADDED,
		std::streampos begin = NO_RANDOM_ACCESS,
		std::streampos end = NO_RANDOM_ACCESS,
		rlim_t bufferSizeLimit = AUTO_IO_BUFFER_LIMIT,
		bool time = false
){
	Timer* t = NULL;
	if(time) {
		t = new Timer();
		t->tic();
	}
	std::string inFileName, outFileName;
	std::fstream *inFile, *outFile;
	bool genPrintFiles = true;
	if(totalNBytes > 16*3) {
		genPrintFiles = false;
	}
	GEN_128BPB_IO_FILES(&inFileName,&inFile,&outFileName,&outFile,16,totalNBytes,genPrintFiles);
	paracrypt::SimpleIO *io = new paracrypt::SimpleCudaIO(inFileName,outFileName,16,bufferSizeLimit,begin,end);
	io->setPadding(p);
	FILE_128BPB_IO_TEST(inFile,outFile,io,genPrintFiles); // destructs io
	CLOSE_IO_FILES(&inFile,&outFile);
	if(time) {
		double cpuSec = t->toc_seconds();
		LOG_INF(boost::format("Test completed in %f CPU seconds\n") % cpuSec);
		delete t;
	}
}
void FILE_128BPB_SHAREDIO_TEST(
		std::streampos totalNBytes,
		unsigned int nChunks,
		paracrypt::BlockIO::paddingScheme p = paracrypt::BlockIO::UNPADDED,
		std::streampos begin = NO_RANDOM_ACCESS,
		std::streampos end = NO_RANDOM_ACCESS,
		rlim_t bufferSizeLimit = AUTO_IO_BUFFER_LIMIT,
		bool time = false
){
	Timer* t = NULL;
	if(time) {
		t = new Timer();
		t->tic();
	}
	std::string inFileName, outFileName;
	std::fstream *inFile, *outFile;
	bool genPrintFiles = true;
	if(totalNBytes > 16*3) {
		genPrintFiles = false;
	}
	GEN_128BPB_IO_FILES(&inFileName,&inFile,&outFileName,&outFile,16,totalNBytes,genPrintFiles);
	paracrypt::CudaSharedIO *io = new paracrypt::CudaSharedIO(inFileName,outFileName,16,nChunks,bufferSizeLimit,begin,end);
	io->setPadding(p);
	FILE_128BPB_IO_TEST(inFile,outFile,io,genPrintFiles); // destructs io
	CLOSE_IO_FILES(&inFile,&outFile);
	if(time) {
		double cpuSec = t->toc_seconds();
		LOG_INF(boost::format("Test completed in %f CPU seconds\n") % cpuSec);
		delete t;
	}
}

BOOST_AUTO_TEST_SUITE(IO)
	BOOST_AUTO_TEST_SUITE(simple_CUDA_IO)
		BOOST_AUTO_TEST_SUITE(simple_CUDA_IO_unlimited)
			BOOST_AUTO_TEST_CASE(just_three_blocks) { FILE_128BPB_SIMPLEIO_TEST(16*3); }
			BOOST_AUTO_TEST_CASE(two_blocks_and_zero_padding) { FILE_128BPB_SIMPLEIO_TEST(16*2+3,paracrypt::BlockIO::UNPADDED); }
			BOOST_AUTO_TEST_CASE(two_blocks_and_PKCS7_padding) { FILE_128BPB_SIMPLEIO_TEST(16*2+3,paracrypt::BlockIO::PKCS7); }
			BOOST_AUTO_TEST_CASE(byte_and_PKCS7_padding) { FILE_128BPB_SIMPLEIO_TEST(1,paracrypt::BlockIO::PKCS7); }
			BOOST_AUTO_TEST_CASE(nothing) { FILE_128BPB_SIMPLEIO_TEST(0); }
			BOOST_AUTO_TEST_CASE(random_access_second_of_three) { FILE_128BPB_SIMPLEIO_TEST(16*3,paracrypt::BlockIO::UNPADDED,16,32-1); }

// TODO OUT_FILE_128BPB_CORRECTNESS_TEST is not yet prepared for these tests (these random access tests are tested in the launcher tests)
//			BOOST_AUTO_TEST_CASE(random_access_first_byte) { FILE_128BPB_SIMPLEIO_TEST(16*3,paracrypt::BlockIO::UNPADDED,16,16); }
//			BOOST_AUTO_TEST_CASE(random_access_first_2bytes) { FILE_128BPB_SIMPLEIO_TEST(16*3,paracrypt::BlockIO::UNPADDED,16,17); }
//			BOOST_AUTO_TEST_CASE(random_access_center_8bytes) { FILE_128BPB_SIMPLEIO_TEST(16*3,paracrypt::BlockIO::UNPADDED,16+4,32-1-4); }
//			BOOST_AUTO_TEST_CASE(random_access_last_2bytes) { FILE_128BPB_SIMPLEIO_TEST(16*3,paracrypt::BlockIO::UNPADDED,32-2,32-1); }
//			BOOST_AUTO_TEST_CASE(random_access_last_byte) { FILE_128BPB_SIMPLEIO_TEST(16*3,paracrypt::BlockIO::UNPADDED,32-1,32-1); }

			BOOST_AUTO_TEST_CASE(random_access_zero_padding) { FILE_128BPB_SIMPLEIO_TEST(16+3,paracrypt::BlockIO::UNPADDED,16,19); }
			BOOST_AUTO_TEST_CASE(random_access_PKCS7_padding) { FILE_128BPB_SIMPLEIO_TEST(16+3,paracrypt::BlockIO::PKCS7,16,19); }
			BOOST_AUTO_TEST_CASE(random_access_eof) { FILE_128BPB_SIMPLEIO_TEST(16,paracrypt::BlockIO::PKCS7,16,32); }
			BOOST_AUTO_TEST_CASE(PKCS7_padding_50MBFile) {
				FILE_128BPB_SIMPLEIO_TEST(50*1000*1000,paracrypt::BlockIO::PKCS7,NO_RANDOM_ACCESS,NO_RANDOM_ACCESS,AUTO_IO_BUFFER_LIMIT,true);
			}
		BOOST_AUTO_TEST_SUITE_END()
		BOOST_AUTO_TEST_SUITE(simple_CUDA_IO_1block_buffer)
			BOOST_AUTO_TEST_CASE(just_three_blocks) { FILE_128BPB_SIMPLEIO_TEST(16*3,paracrypt::BlockIO::UNPADDED,
					NO_RANDOM_ACCESS,NO_RANDOM_ACCESS,16); }
			BOOST_AUTO_TEST_CASE(two_blocks_and_zero_padding) { FILE_128BPB_SIMPLEIO_TEST(16*2+3,paracrypt::BlockIO::UNPADDED,
					NO_RANDOM_ACCESS,NO_RANDOM_ACCESS,16); }
			BOOST_AUTO_TEST_CASE(two_blocks_and_PKCS7_padding) { FILE_128BPB_SIMPLEIO_TEST(16*2+3,paracrypt::BlockIO::PKCS7,
					NO_RANDOM_ACCESS,NO_RANDOM_ACCESS,16); }
			BOOST_AUTO_TEST_CASE(byte_and_PKCS7_padding) { FILE_128BPB_SIMPLEIO_TEST(1,paracrypt::BlockIO::PKCS7,
					NO_RANDOM_ACCESS,NO_RANDOM_ACCESS,16); }
			BOOST_AUTO_TEST_CASE(nothing) { FILE_128BPB_SIMPLEIO_TEST(0,paracrypt::BlockIO::UNPADDED,
					NO_RANDOM_ACCESS,NO_RANDOM_ACCESS,16); }
			BOOST_AUTO_TEST_CASE(random_access_second_of_three) { FILE_128BPB_SIMPLEIO_TEST(16*3,paracrypt::BlockIO::UNPADDED,16,32-1,16); }
			BOOST_AUTO_TEST_CASE(random_access_zero_padding) { FILE_128BPB_SIMPLEIO_TEST(16+3,paracrypt::BlockIO::UNPADDED,16,19,16); }
			BOOST_AUTO_TEST_CASE(random_access_PKCS7_padding) { FILE_128BPB_SIMPLEIO_TEST(16+3,paracrypt::BlockIO::PKCS7,16,19,16); }
			BOOST_AUTO_TEST_CASE(random_access_eof) { FILE_128BPB_SIMPLEIO_TEST(16,paracrypt::BlockIO::PKCS7,16,32,16); }
			BOOST_AUTO_TEST_CASE(PKCS7_padding_50MBFile) {
				FILE_128BPB_SIMPLEIO_TEST(50*1000*1000,paracrypt::BlockIO::PKCS7,NO_RANDOM_ACCESS,NO_RANDOM_ACCESS,16,true);
			}
		BOOST_AUTO_TEST_SUITE_END()
		BOOST_AUTO_TEST_SUITE(simple_CUDA_IO_10block_buffer)
			BOOST_AUTO_TEST_CASE(PKCS7_padding_50MBFile) {
				FILE_128BPB_SIMPLEIO_TEST(50*1000*1000,paracrypt::BlockIO::PKCS7,NO_RANDOM_ACCESS,NO_RANDOM_ACCESS,160,true);
			}
		BOOST_AUTO_TEST_SUITE_END()
		BOOST_AUTO_TEST_SUITE(simple_CUDA_IO_100block_buffer)
			BOOST_AUTO_TEST_CASE(PKCS7_padding_50MBFile) {
				FILE_128BPB_SIMPLEIO_TEST(50*1000*1000,paracrypt::BlockIO::PKCS7,NO_RANDOM_ACCESS,NO_RANDOM_ACCESS,1600,true);
			}
		BOOST_AUTO_TEST_SUITE_END()
	BOOST_AUTO_TEST_SUITE_END()

	BOOST_AUTO_TEST_SUITE(shared_CUDA_IO)
		BOOST_AUTO_TEST_SUITE(shared_CUDA_IO_unlimited)
			BOOST_AUTO_TEST_CASE(just_three_blocks) { FILE_128BPB_SHAREDIO_TEST(16*3,4); }
			BOOST_AUTO_TEST_CASE(two_blocks_and_zero_padding) { FILE_128BPB_SHAREDIO_TEST(16*2+3,4,paracrypt::BlockIO::UNPADDED); }
			BOOST_AUTO_TEST_CASE(two_blocks_and_PKCS7_padding) { FILE_128BPB_SHAREDIO_TEST(16*2+3,4,paracrypt::BlockIO::PKCS7); }
			BOOST_AUTO_TEST_CASE(byte_and_PKCS7_padding) { FILE_128BPB_SHAREDIO_TEST(1,4,paracrypt::BlockIO::PKCS7); }
			BOOST_AUTO_TEST_CASE(nothing) { FILE_128BPB_SHAREDIO_TEST(0,4); }
			BOOST_AUTO_TEST_CASE(random_access_second_of_three) { FILE_128BPB_SHAREDIO_TEST(16*3,4,paracrypt::BlockIO::UNPADDED,16,32-1); }

// TODO OUT_FILE_128BPB_CORRECTNESS_TEST is not yet prepared for these tests (these random access tests are tested in the launcher tests)//			BOOST_AUTO_TEST_CASE(random_access_first_byte) { FILE_128BPB_SHAREDIO_TEST(16*3,4,paracrypt::BlockIO::UNPADDED,16,16); }
//			BOOST_AUTO_TEST_CASE(random_access_first_2bytes) { FILE_128BPB_SHAREDIO_TEST(16*3,4,paracrypt::BlockIO::UNPADDED,16,17); }
//			BOOST_AUTO_TEST_CASE(random_access_center_8bytes) { FILE_128BPB_SHAREDIO_TEST(16*3,4,paracrypt::BlockIO::UNPADDED,16+4,32-1-4); }
//			BOOST_AUTO_TEST_CASE(random_access_last_2bytes) { FILE_128BPB_SHAREDIO_TEST(16*3,4,paracrypt::BlockIO::UNPADDED,32-2,32-1); }
//			BOOST_AUTO_TEST_CASE(random_access_last_byte) { FILE_128BPB_SHAREDIO_TEST(16*3,4,paracrypt::BlockIO::UNPADDED,32-1,32-1); }

			BOOST_AUTO_TEST_CASE(random_access_zero_padding) { FILE_128BPB_SHAREDIO_TEST(16+3,4,paracrypt::BlockIO::UNPADDED,16,19); }
			BOOST_AUTO_TEST_CASE(random_access_PKCS7_padding) { FILE_128BPB_SHAREDIO_TEST(16+3,4,paracrypt::BlockIO::PKCS7,16,19); }
			BOOST_AUTO_TEST_CASE(random_access_eof) { FILE_128BPB_SHAREDIO_TEST(16,4,paracrypt::BlockIO::PKCS7,16,32); }
			BOOST_AUTO_TEST_CASE(PKCS7_padding_50MBFile) {
				FILE_128BPB_SHAREDIO_TEST(50*1000*1000,4,paracrypt::BlockIO::PKCS7,NO_RANDOM_ACCESS,NO_RANDOM_ACCESS,AUTO_IO_BUFFER_LIMIT,true);
			}
		BOOST_AUTO_TEST_SUITE_END()
		BOOST_AUTO_TEST_SUITE(shared_CUDA_IO_4block_buffer)
			BOOST_AUTO_TEST_CASE(just_three_blocks) { FILE_128BPB_SHAREDIO_TEST(16*3,4,paracrypt::BlockIO::UNPADDED,
					NO_RANDOM_ACCESS,NO_RANDOM_ACCESS,16*4); }
			BOOST_AUTO_TEST_CASE(two_blocks_and_zero_padding) { FILE_128BPB_SHAREDIO_TEST(16*2+3,4,paracrypt::BlockIO::UNPADDED,
					NO_RANDOM_ACCESS,NO_RANDOM_ACCESS,16*4); }
			BOOST_AUTO_TEST_CASE(two_blocks_and_PKCS7_padding) { FILE_128BPB_SHAREDIO_TEST(16*2+3,4,paracrypt::BlockIO::PKCS7,
					NO_RANDOM_ACCESS,NO_RANDOM_ACCESS,16*4); }
			BOOST_AUTO_TEST_CASE(byte_and_PKCS7_padding) { FILE_128BPB_SHAREDIO_TEST(1,4,paracrypt::BlockIO::PKCS7,
					NO_RANDOM_ACCESS,NO_RANDOM_ACCESS,16*4); }
			BOOST_AUTO_TEST_CASE(nothing) { FILE_128BPB_SHAREDIO_TEST(0,4,paracrypt::BlockIO::UNPADDED,
					NO_RANDOM_ACCESS,NO_RANDOM_ACCESS,16*4); }
			BOOST_AUTO_TEST_CASE(random_access_second_of_three) { FILE_128BPB_SHAREDIO_TEST(16*3,4,paracrypt::BlockIO::UNPADDED,16,32-1,16*4); }
			BOOST_AUTO_TEST_CASE(random_access_zero_padding) { FILE_128BPB_SHAREDIO_TEST(16+3,4,paracrypt::BlockIO::UNPADDED,16,19,16*4); }
			BOOST_AUTO_TEST_CASE(random_access_PKCS7_padding) { FILE_128BPB_SHAREDIO_TEST(16+3,4,paracrypt::BlockIO::PKCS7,16,19,16*4); }
			BOOST_AUTO_TEST_CASE(random_access_eof) { FILE_128BPB_SHAREDIO_TEST(16,4,paracrypt::BlockIO::PKCS7,16,32,16*4); }
		BOOST_AUTO_TEST_SUITE_END()
		BOOST_AUTO_TEST_SUITE(shared_CUDA_IO_80block_buffer)
			BOOST_AUTO_TEST_CASE(PKCS7_padding_50MBFile) {
				FILE_128BPB_SHAREDIO_TEST(50*1000*1000,4,paracrypt::BlockIO::PKCS7,NO_RANDOM_ACCESS,NO_RANDOM_ACCESS,16*80,true);
			}
		BOOST_AUTO_TEST_SUITE_END()
	BOOST_AUTO_TEST_SUITE_END()
BOOST_AUTO_TEST_SUITE_END()


void GEN_AES_TEST_FILE(
		std::string *fileName,
		std::fstream **file, // WARNING: Must be closed by the caller
		const char* testData,
		unsigned int blockSize,
		unsigned int nBlocks
){
	{
		char nameBuffer [L_tmpnam];
		std::tmpnam (nameBuffer);
		(*fileName) = std::string(nameBuffer);
	}

	(*file) = new std::fstream(fileName->c_str(),std::fstream::out | std::fstream::binary);
	if(!(*file)) {
		FATAL(boost::format("Error creating test file: %s\n") % strerror(errno));
	}
    for(unsigned int i=0; i < nBlocks; i++) {
    	(*file)->write(testData,blockSize);
    	if(!(*file)) {
    		FATAL(boost::format("Error writing to test file: %s\n") % strerror(errno));
    	}
    }
	(*file)->flush();
}
void GEN_AES_ENCRYPT_FILE(
		std::string *fileName,
		std::fstream **file, // WARNING: Must be closed by the caller
		tv vector,
		unsigned int nBlocks
){
	GEN_AES_TEST_FILE(fileName,file,(const char*)vector.input,sizeof(vector.input),nBlocks);
}
void GEN_AES_DECRYPT_FILE(
		std::string *fileName,
		std::fstream **file, // WARNING: Must be closed by the caller
		tv vector,
		unsigned int nBlocks
){
	GEN_AES_TEST_FILE(fileName,file,(const char*)vector.output,sizeof(vector.output),nBlocks);
}

// TODO launcher random encrypt tests

template < class CudaAES_t >
void CUDA_AES_SHARED_IO_LAUNCHER_SB_OPERATION_TEST(
		paracrypt::Launcher::operation_t op,
		std::string title,
		tv vector,
		int n_blocks,
		bool constantKey,
		bool constantTables,
		bool outOfOrder = false
){
	LOG_TRACE(boost::format("Executing %s...") % title.c_str());

	std::string inFileName;
	std::fstream *inFile;

	switch(op) {
		case paracrypt::Launcher::ENCRYPT:
			GEN_AES_ENCRYPT_FILE(&inFileName,&inFile,vector,n_blocks);
			break;
		case paracrypt::Launcher::DECRYPT:
			GEN_AES_DECRYPT_FILE(&inFileName,&inFile,vector,n_blocks);
			break;
		default:
			ERR("Unknown cipher operation.");
	}

	std::string outFileName;
	{
		char nameBuffer [L_tmpnam];
		std::tmpnam (nameBuffer);
		outFileName = std::string(nameBuffer);
	}
	std::ofstream* outFile = new std::ofstream(outFileName.c_str(),std::fstream::out | std::fstream::binary);

    paracrypt::Launcher::launchSharedIOCudaAES<CudaAES_t>(
    		op,
    		inFileName, outFileName,
    		vector.key, vector.key_bits,
    		constantKey, constantTables,
    		vector.m, vector.iv, sizeof(vector.iv)*8,
    		outOfOrder
    );

	// Verify output blocks are correct
	std::ifstream* upadatedOutFile = new std::ifstream(outFileName.c_str(),std::fstream::in | std::fstream::binary);
	std::streamsize inFileSize  = paracrypt::IO::fileSize(inFile);
	std::streamsize outFileSize = paracrypt::IO::fileSize(upadatedOutFile);
	BOOST_REQUIRE_EQUAL(inFileSize,outFileSize);
	unsigned char buffer[16];
	for(int i = 0; i < n_blocks; i++) {
		upadatedOutFile->read((char*)buffer,16);
		bool err = upadatedOutFile;
	    BOOST_CHECK(err); // check no err
		if(upadatedOutFile->fail()){
			if(upadatedOutFile->eof()) {
				std::streamsize readBytes = upadatedOutFile->gcount();
				BOOST_REQUIRE_EQUAL(readBytes, 16); // the files only contain full blocks
			} else {
				FATAL(boost::format("Error reading input file: %s\n") % strerror(errno));
			}
		}
		switch(op) {
			case paracrypt::Launcher::ENCRYPT:
		    	BOOST_REQUIRE_EQUAL_COLLECTIONS(buffer,buffer+16,vector.output,vector.output+16);
				break;
			case paracrypt::Launcher::DECRYPT:
				BOOST_REQUIRE_EQUAL_COLLECTIONS(buffer,buffer+16,vector.input,vector.input+16);
				break;
			default:
				ERR("Unknown cipher operation.");
		}
	}
	upadatedOutFile->close();
	delete upadatedOutFile;

    inFile->close();
    delete inFile;

    outFile->close();
    delete outFile;
}

template < class CudaAES_t >
void CUDA_AES_SHARED_IO_LAUNCHER_SB_ENCRYPT_TEST(
			std::string title,
			tv vector,
			int n_blocks,
			bool constantKey,
			bool constantTables,
			bool outOfOrder = false
){
	CUDA_AES_SHARED_IO_LAUNCHER_SB_OPERATION_TEST<CudaAES_t>(
			paracrypt::Launcher::ENCRYPT,
			title,
			vector, n_blocks,
			constantKey, constantTables,
			outOfOrder
	);
}

template < class CudaAES_t >
void CUDA_AES_SHARED_IO_LAUNCHER_SB_DECRYPT_TEST(
			std::string title,
			tv vector,
			int n_blocks,
			bool constantKey,
			bool constantTables,
			bool outOfOrder = false
){
	CUDA_AES_SHARED_IO_LAUNCHER_SB_OPERATION_TEST<CudaAES_t>(
			paracrypt::Launcher::DECRYPT,
			title,
			vector, n_blocks,
			constantKey, constantTables,
			outOfOrder
	);
}


void GEN_AES_RACC_TEST_FILE(
		std::string *fileName,
		std::fstream **file, // WARNING: Must be closed by the caller
		const char* testData,
		unsigned int blockSize,
		unsigned int nBlocks,
		std::streampos beginBlock,
		std::streampos endBlock
){
	{
		char nameBuffer [L_tmpnam];
		std::tmpnam (nameBuffer);
		(*fileName) = std::string(nameBuffer);
	}

	(*file) = new std::fstream(fileName->c_str(),std::fstream::out | std::fstream::binary);
	if(!(*file)) {
		FATAL(boost::format("Error creating test file: %s\n") % strerror(errno));
	}

//	srand (time(NULL));
//	uint32_t random_block_words[4];
	unsigned char zeroes[16];
	memset(zeroes, 0, 16);

    for(unsigned int i=0; i < nBlocks; i++) {
    	if(beginBlock <= i&&i <= endBlock) {
//    		(*file)->flush(); // TODO TOREMOVE
//    		break; // TODO TOREMOVE
    		(*file)->write(testData,blockSize);
    	} else {
//    		// random data at blocks we will not access
//    		for(int j=0; j < 4; j++) {
//    			random_block_words[j] = (uint32_t) rand();
//    		}
    		zeroes[0] = (unsigned char) i;
    		(*file)->write((const char*)zeroes,blockSize);
//    		(*file)->write((const char*)random_block_words,blockSize);
//    		LOG_TRACE(boost::format("written %i bytes\n") % blockSize);// TODO TOREMOVE
//    		hexdump("block_words",(const unsigned char*)random_block_words,blockSize);
    	}
    	if(!(*file)) {
    		FATAL(boost::format("Error writing to test file: %s\n") % strerror(errno));
    	}
    }
	(*file)->flush();
}

template < class CudaAES_t >
void CUDA_AES_SHARED_IO_LAUNCHER_RACC_TEST(
		std::string title,
		tv vector,
		int n_blocks,
		bool constantKey,
		bool constantTables,
		std::streampos begin,
		std::streampos end,
		bool outOfOrder = false
){
	LOG_TRACE(boost::format("Executing %s...") % title.c_str());

	unsigned int blockSize = sizeof(vector.input);
	std::streampos beginBlock = begin/blockSize; // begin block
	std::streampos endBlock = end/blockSize; // end block // TODO somethn wrong here ?
	if(end % blockSize != 0)
		endBlock += 1;
	assert(endBlock > beginBlock);
	std::streampos nBlocks = endBlock-beginBlock;

	std::string inFileName;
	std::fstream *inFile;
	GEN_AES_RACC_TEST_FILE(&inFileName,&inFile,(const char*) vector.input,sizeof(vector.input),n_blocks,beginBlock,endBlock);
//	std::streamsize inFileSize = paracrypt::IO::fileSize(inFile);
//
//	if(rem != 0 && end > inFileSize) {
//		nBlocks -= 1;
//	}

	std::string outFileName;
	std::string raccFileName;
	{
		char nameBuffer [L_tmpnam];
		std::tmpnam (nameBuffer);
		outFileName = std::string(nameBuffer);
		std::tmpnam (nameBuffer);
		raccFileName = std::string(nameBuffer);
	}
	std::ofstream* outFile = new std::ofstream(outFileName.c_str(),std::fstream::out | std::fstream::binary);
	std::ofstream* raccFile = new std::ofstream(raccFileName.c_str(),std::fstream::out | std::fstream::binary);

    paracrypt::Launcher::launchSharedIOCudaAES<CudaAES_t>(
    		paracrypt::Launcher::ENCRYPT,
    		inFileName, outFileName,
    		vector.key, vector.key_bits,
    		constantKey, constantTables,
    		vector.m, vector.iv, sizeof(vector.iv)*8,
    		outOfOrder
    );

    paracrypt::Launcher::launchSharedIOCudaAES<CudaAES_t>(
    		paracrypt::Launcher::DECRYPT,
    		outFileName, raccFileName,
    		vector.key, vector.key_bits,
    		constantKey, constantTables,
    		vector.m, vector.iv, sizeof(vector.iv)*8,
    		outOfOrder,
    		begin, end
    );

	// Verify output blocks are correct
	std::ifstream* upadatedRaccFile = new std::ifstream(raccFileName.c_str(),std::fstream::in | std::fstream::binary);
	std::streamsize raccFileSize = paracrypt::IO::fileSize(upadatedRaccFile);
	BOOST_REQUIRE_EQUAL(raccFileSize,nBlocks*16);

	unsigned char buffer[16];
	for(int i = 0; i < nBlocks; i++) {
		upadatedRaccFile->read((char*)buffer,16);
		bool err = upadatedRaccFile;
	    BOOST_CHECK(err); // check no err
		if(upadatedRaccFile->fail()){
			if(upadatedRaccFile->eof()) {
				std::streamsize readBytes = upadatedRaccFile->gcount();
				BOOST_REQUIRE_EQUAL(readBytes, 16); // the files only contain full blocks
			} else {
				FATAL(boost::format("Error reading input file: %s\n") % strerror(errno));
			}
		}
    	BOOST_REQUIRE_EQUAL_COLLECTIONS(buffer,buffer+16,vector.input,vector.input+16);
	}
	upadatedRaccFile->close();
	delete upadatedRaccFile;

    inFile->close();
    delete inFile;

    outFile->close();
    delete outFile;

    raccFile->close();
    delete raccFile;
}

int GEN_AES_RANDOM_TEST_FILE(
		std::string *fileName,
		std::fstream **file, // WARNING: Must be closed by the caller
		int maxNBlocks,
		tv vector_key,
		const EVP_CIPHER * openSSLCipher = NULL // generate an encrypted file
){
	{
		char nameBuffer [L_tmpnam];
		std::tmpnam (nameBuffer);
		(*fileName) = std::string(nameBuffer);
	}

	(*file) = new std::fstream(fileName->c_str(),std::fstream::out | std::fstream::binary);
	if(!(*file)) {
		FATAL(boost::format("Error creating test file: %s\n") % strerror(errno));
	}

	int nBlocks = std::min(maxNBlocks,random_data_n_blocks);
	int paddingBytes = rand() % 15 + 1; // 1-15
	int data_length = openSSLCipher == NULL ? nBlocks*16-paddingBytes : nBlocks*16;
	unsigned char *plaintext = (unsigned char*) malloc(data_length);
    if(plaintext == NULL) {
    	FATAL("Error allocating memory for the encryption plantext buffer\n");
    }
    memcpy(plaintext,random_data,data_length);
    if(openSSLCipher != NULL) {
		// PKCS7
		uint8_t n = (uint8_t) paddingBytes;
		int paddingOffset = data_length-paddingBytes;
		assert(paddingOffset+n <= data_length);
		unsigned char *paddingStart = plaintext+paddingOffset;
		memset(paddingStart, n, paddingBytes);
    }
	unsigned char *result = plaintext;

	if(maxNBlocks <= 65) {
		hexdump("random data",result,data_length);
	}

    if(openSSLCipher != NULL) {
    	// OpenSSL Encryption /////////////////////////////////////////////////////////////
#ifdef OPENSSL_EXISTS
    	unsigned char *key = (unsigned char*) vector_key.key;
    	unsigned char *iv = (unsigned char*) vector_key.iv;
        result = (unsigned char*) malloc(data_length+16);
        if(result == NULL) {
        	FATAL("Error allocating memory for the encryption result buffer\n");
        }
        int ciphertext_len;

        // Encrypt the plaintext
        ciphertext_len = AES_encrypt (openSSLCipher, plaintext, data_length, key, iv, result);
        if(ciphertext_len == data_length+16) {
        	ciphertext_len -= 16;
        }
        BOOST_REQUIRE_EQUAL(ciphertext_len,data_length);
#endif
        ////////////////////////////////////////////////////////////////////////////////////
    }

    (*file)->write((const char*) result,data_length);
    if(!(*file)){
    	FATAL(boost::format("Error reading input file: %s\n") % strerror(errno));
    }
    (*file)->flush();
    free(result);
    if(openSSLCipher != NULL)
    	free(plaintext);

	if(openSSLCipher != NULL && maxNBlocks <= 65) {
		fdump("encrypted random data",(*fileName));
	} else if(maxNBlocks <= 65) {
		fdump("random data file",(*fileName));
	}

    return paddingBytes;
}

template < class CudaAES_t >
void CUDA_AES_SHARED_IO_LAUNCHER_RANDOM_DECRYPT_TEST(
		std::string title,
		tv vector, // iv, key, and mode (we dont need input-output)
		const EVP_CIPHER * openSSLCipher,
		bool constantKey,
		bool constantTables,
		std::streampos begin,
		std::streampos end,
		int maxNBlocks = 10000000,
		bool outOfOrder = false
){
	assert(end >= begin);
	LOG_TRACE(boost::format("Executing %s...") % title.c_str());

	std::string inFileName;
	std::fstream *inFile;
	int paddingBytes = GEN_AES_RANDOM_TEST_FILE(&inFileName,&inFile,maxNBlocks,vector,openSSLCipher);

	std::string raccFileName;
	{
		char nameBuffer [L_tmpnam];
		std::tmpnam (nameBuffer);
		raccFileName = std::string(nameBuffer);
	}
	std::ofstream* raccFile = new std::ofstream(raccFileName.c_str(),std::fstream::out | std::fstream::binary);

    paracrypt::Launcher::launchSharedIOCudaAES<CudaAES_t>(
    		paracrypt::Launcher::DECRYPT,
    		inFileName, raccFileName,
    		vector.key, vector.key_bits,
    		constantKey, constantTables,
    		vector.m, vector.iv, sizeof(vector.iv)*8,
    		outOfOrder,
    		begin, end
    );

	// Verify output blocks are correct
	std::ifstream* upadatedRaccFile = new std::ifstream(raccFileName.c_str(),std::fstream::in | std::fstream::binary);
	std::streamsize raccFileSize = paracrypt::IO::fileSize(upadatedRaccFile);
	std::streamsize inFileSize = paracrypt::IO::fileSize(inFile);

	if(maxNBlocks <= 65) {
		fdump("Resultant file after decryption with Paracrypt",raccFileName);
	}

	if(begin == NO_RANDOM_ACCESS)
		begin = 0;
	std::streamsize stimatedSize;
	if(end != NO_RANDOM_ACCESS && end < inFileSize) {
		stimatedSize = end-begin+1;
	}
	else  {
		stimatedSize = inFileSize-begin-paddingBytes;
	}

	BOOST_REQUIRE_EQUAL(raccFileSize,stimatedSize);
	unsigned char buffer[16];
	int nBlocks = std::min(random_data_n_blocks,maxNBlocks);
	for(int i = 0; i < nBlocks; i++) {
		upadatedRaccFile->read((char*)buffer,16);
		bool err = upadatedRaccFile;
	    BOOST_CHECK(err); // check no err
	    std::streamsize readBytes = 16;
		if(upadatedRaccFile->fail()){
			if(upadatedRaccFile->eof()) {
				readBytes = upadatedRaccFile->gcount();
				BOOST_REQUIRE_EQUAL(readBytes, stimatedSize%16);
			} else {
				FATAL(boost::format("Error reading input file: %s\n") % strerror(errno));
			}
		}
		unsigned char* begin_random_data = random_data+begin+(16*i);
		unsigned char* end_random_data = begin_random_data+readBytes;
    	BOOST_REQUIRE_EQUAL_COLLECTIONS(buffer,buffer+readBytes,begin_random_data,end_random_data);
	}
	upadatedRaccFile->close();
	delete upadatedRaccFile;

    inFile->close();
    delete inFile;

    raccFile->close();
    delete raccFile;
}

template < class CudaAES_t >
void CUDA_AES_SHARED_IO_LAUNCHER_RANDOM_TEST(
		std::string title,
		tv vector, // iv, key, and mode (we dont need input-output)
		bool constantKey,
		bool constantTables,
		std::streampos begin,
		std::streampos end,
		int maxNBlocks = 10000000,
		bool outOfOrder = false
){
	assert(end >= begin);
	LOG_TRACE(boost::format("Executing %s...") % title.c_str());

	std::string inFileName;
	std::fstream *inFile;
	//int paddingBytes =
	GEN_AES_RANDOM_TEST_FILE(&inFileName,&inFile,maxNBlocks,vector);

	std::string outFileName;
	std::string raccFileName;
	{
		char nameBuffer [L_tmpnam];
		std::tmpnam (nameBuffer);
		outFileName = std::string(nameBuffer);
		std::tmpnam (nameBuffer);
		raccFileName = std::string(nameBuffer);
	}
	std::ofstream* outFile = new std::ofstream(outFileName.c_str(),std::fstream::out | std::fstream::binary);
	std::ofstream* raccFile = new std::ofstream(raccFileName.c_str(),std::fstream::out | std::fstream::binary);

    paracrypt::Launcher::launchSharedIOCudaAES<CudaAES_t>(
    		paracrypt::Launcher::ENCRYPT,
    		inFileName, outFileName,
    		vector.key, vector.key_bits,
    		constantKey, constantTables,
    		vector.m, vector.iv, sizeof(vector.iv)*8,
    		outOfOrder
    );

	if(maxNBlocks <= 65) {
		fdump("Resultant file after encryption with Paracrypt",outFileName);
	}

    paracrypt::Launcher::launchSharedIOCudaAES<CudaAES_t>(
    		paracrypt::Launcher::DECRYPT,
    		outFileName, raccFileName,
    		vector.key, vector.key_bits,
    		constantKey, constantTables,
    		vector.m, vector.iv, sizeof(vector.iv)*8,
    		outOfOrder,
    		begin, end
    );

	// Verify output blocks are correct
	std::ifstream* upadatedRaccFile = new std::ifstream(raccFileName.c_str(),std::fstream::in | std::fstream::binary);
	std::streamsize raccFileSize = paracrypt::IO::fileSize(upadatedRaccFile);
	std::streamsize inFileSize = paracrypt::IO::fileSize(inFileName);

	if(maxNBlocks <= 65) {
		fdump("Resultant file after decryption with Paracrypt",raccFileName);
	}

	if(begin == NO_RANDOM_ACCESS)
		begin = 0;
	std::streamsize stimatedSize;
	if(end != NO_RANDOM_ACCESS && end < inFileSize) {
		stimatedSize = end-begin+1;
	}
	else  {
		stimatedSize = inFileSize-begin;//-paddingBytes;
	}

	BOOST_REQUIRE_EQUAL(raccFileSize,stimatedSize);
	unsigned char buffer[16];
	int nBlocks = std::min(random_data_n_blocks,maxNBlocks);
	for(int i = 0; i < nBlocks; i++) {
		upadatedRaccFile->read((char*)buffer,16);
		bool err = upadatedRaccFile;
	    BOOST_CHECK(err); // check no err
	    std::streamsize readBytes = 16;
		if(upadatedRaccFile->fail()){
			if(upadatedRaccFile->eof()) {
				readBytes = upadatedRaccFile->gcount();
				BOOST_REQUIRE_EQUAL(readBytes, stimatedSize%16);
			} else {
				FATAL(boost::format("Error reading input file: %s\n") % strerror(errno));
			}
		}
		unsigned char* begin_random_data = random_data+begin+(16*i);
		unsigned char* end_random_data = begin_random_data+readBytes;
    	BOOST_REQUIRE_EQUAL_COLLECTIONS(buffer,buffer+readBytes,begin_random_data,end_random_data);
	}
	upadatedRaccFile->close();
	delete upadatedRaccFile;

	outFile->close();
	delete outFile;

    inFile->close();
    delete inFile;

    raccFile->close();
    delete raccFile;
}

#define AES_LAUNCHER_KEYSIZE_TEST_SUITE_ORDER(id, testName, className, keySizeStr, iv, outOfOrder) \
		BOOST_AUTO_TEST_SUITE(id) \
				BOOST_AUTO_TEST_CASE(constant_key_and_tables) { \
					CUDA_AES_SHARED_IO_LAUNCHER_SB_ENCRYPT_TEST<className>( \
							"Multistream " testName " CUDA AES-"keySizeStr" with constant key and tables.", iv,1000,true, true, outOfOrder);} \
				BOOST_AUTO_TEST_CASE(constant_key) { \
					CUDA_AES_SHARED_IO_LAUNCHER_SB_ENCRYPT_TEST<className>( \
							"Multistream " testName " CUDA AES-"keySizeStr" with constant key.", iv,1000,true, false, outOfOrder);} \
				BOOST_AUTO_TEST_CASE(dynamic_key_and_tables) { \
					CUDA_AES_SHARED_IO_LAUNCHER_SB_ENCRYPT_TEST<className>( \
							"Multistream " testName " CUDA AES-"keySizeStr".", iv,1000,false, false, outOfOrder);} \
 \
				BOOST_AUTO_TEST_CASE(constant_key_and_tables_decrypt) { \
					CUDA_AES_SHARED_IO_LAUNCHER_SB_DECRYPT_TEST<className>( \
							"Multistream " testName " CUDA AES-"keySizeStr" with constant key and tables.", iv,1000,true, true, outOfOrder);} \
				BOOST_AUTO_TEST_CASE(constant_key_decrypt) { \
					CUDA_AES_SHARED_IO_LAUNCHER_SB_DECRYPT_TEST<className>( \
							"Multistream " testName " CUDA AES-"keySizeStr" with constant key.", iv,1000,true, false, outOfOrder);} \
				BOOST_AUTO_TEST_CASE(dynamic_key_and_tables_decrypt) { \
					CUDA_AES_SHARED_IO_LAUNCHER_SB_DECRYPT_TEST<className>( \
							"Multistream " testName " CUDA AES-"keySizeStr".", iv,1000,false, false, outOfOrder);} \
\
				BOOST_AUTO_TEST_CASE(constant_key_and_tables_racc) { \
					CUDA_AES_SHARED_IO_LAUNCHER_RACC_TEST<className>( \
						"Multistream encryption and random access decryption using " testName " CUDA AES-"keySizeStr" with constant key and tables.", iv,1000,true, true, 16*100,16*200-1, outOfOrder);} \
				BOOST_AUTO_TEST_CASE(constant_key_decrypt_racc) { \
					CUDA_AES_SHARED_IO_LAUNCHER_RACC_TEST<className>( \
						"Multistream encryption and random access decryption using " testName " CUDA AES-"keySizeStr" with constant key.", iv,1000,true, false, 16*100,16*200-1, outOfOrder);} \
				BOOST_AUTO_TEST_CASE(dynamic_key_and_tables_racc) { \
					CUDA_AES_SHARED_IO_LAUNCHER_RACC_TEST<className>( \
						"Multistream encryption and random access decryption using " testName " CUDA AES-"keySizeStr".", iv,1000,false, false, 16*100,16*200-1, outOfOrder);} \
		BOOST_AUTO_TEST_SUITE_END()

// TODO tests not prepared for this
/*
\
				BOOST_AUTO_TEST_CASE(constant_key_and_tables_racc_unalig) { \
					CUDA_AES_SHARED_IO_LAUNCHER_RACC_TEST<className>( \
						"Multistream encryption and random access (unaligned to block) decryption using " testName " CUDA AES-"keySizeStr" with constant key and tables.", iv,1000,true, true, 16*99+8,16*200-8, outOfOrder);} \
				BOOST_AUTO_TEST_CASE(constant_key_racc_unalig) { \
					CUDA_AES_SHARED_IO_LAUNCHER_RACC_TEST<className>( \
						"Multistream encryption and random access (unaligned to block) decryption using " testName " CUDA AES-"keySizeStr" with constant key.", iv,1000,true, false, 16*99+8,16*200-8, outOfOrder);} \
				BOOST_AUTO_TEST_CASE(dynamic_key_and_tables_racc_unalig) { \
					CUDA_AES_SHARED_IO_LAUNCHER_RACC_TEST<className>( \
						"Multistream encryption and random access (unaligned to block) decryption using " testName " CUDA AES-"keySizeStr".", iv,1000,false, false, 16*99+8,16*200-8, outOfOrder);} \
*/

#define AES_LAUNCHER_KEYSIZE_TEST_SUITE(id, testName, className, keySizeStr, iv) \
		BOOST_AUTO_TEST_SUITE(id) \
			AES_LAUNCHER_KEYSIZE_TEST_SUITE_ORDER(IN_ORDER, testName, className, keySizeStr, iv, false); \
			AES_LAUNCHER_KEYSIZE_TEST_SUITE_ORDER(OUT_OF_ORDER, testName, className, keySizeStr, iv, true); \
		BOOST_AUTO_TEST_SUITE_END()

#define AES_LAUNCHER_DECRYPT_TEST_SUITE_(id, testName, className, openSSLCipher, keySizeStr, iv, begin, end, maxNBlocks) \
BOOST_AUTO_TEST_SUITE(id) \
	BOOST_AUTO_TEST_CASE(in_order_constant_key_and_tables) { \
			CUDA_AES_SHARED_IO_LAUNCHER_RANDOM_DECRYPT_TEST<className>( \
				"Multistream " testName " CUDA AES-"keySizeStr" with constant key and tables.", iv, openSSLCipher, \
				true, true, begin, end, maxNBlocks, false); \
	} \
	BOOST_AUTO_TEST_CASE(out_of_order_constant_key_and_tables) { \
			CUDA_AES_SHARED_IO_LAUNCHER_RANDOM_DECRYPT_TEST<className>( \
				"Multistream " testName " CUDA AES-"keySizeStr" with constant key and tables.", iv, openSSLCipher, \
				true, true, begin, end, maxNBlocks, true); \
	} \
	BOOST_AUTO_TEST_CASE(in_order_constant_key) { \
			CUDA_AES_SHARED_IO_LAUNCHER_RANDOM_DECRYPT_TEST<className>( \
					"Multistream " testName " CUDA AES-"keySizeStr" with constant key.", iv, openSSLCipher, \
					true, false, begin, end, maxNBlocks, false); \
	} \
	BOOST_AUTO_TEST_CASE(out_of_order_constant_key) { \
			CUDA_AES_SHARED_IO_LAUNCHER_RANDOM_DECRYPT_TEST<className>( \
				"Multistream " testName " CUDA AES-"keySizeStr" with constant key .", iv, openSSLCipher, \
					true, false, begin, end, maxNBlocks, true); \
	} \
	BOOST_AUTO_TEST_CASE(in_order_constant_tables) { \
			CUDA_AES_SHARED_IO_LAUNCHER_RANDOM_DECRYPT_TEST<className>( \
					"Multistream " testName " CUDA AES-"keySizeStr" with constant tables.", iv, openSSLCipher, \
					false, true, begin, end, maxNBlocks, false); \
	} \
	BOOST_AUTO_TEST_CASE(out_of_order_constant_tables) { \
			CUDA_AES_SHARED_IO_LAUNCHER_RANDOM_DECRYPT_TEST<className>( \
				"Multistream " testName " CUDA AES-"keySizeStr" with constant tables .", iv, openSSLCipher, \
					false, true, begin, end, maxNBlocks, true); \
	} \
	BOOST_AUTO_TEST_CASE(in_order_dynamic_key_and_tables) { \
			CUDA_AES_SHARED_IO_LAUNCHER_RANDOM_DECRYPT_TEST<className>( \
				"Multistream " testName " CUDA AES-"keySizeStr" with dynamic key and tables.", iv, openSSLCipher, \
				true, true, begin, end, maxNBlocks, false); \
	} \
	BOOST_AUTO_TEST_CASE(out_of_order_dynamic_key_and_tables) { \
			CUDA_AES_SHARED_IO_LAUNCHER_RANDOM_DECRYPT_TEST<className>( \
				"Multistream " testName " CUDA AES-"keySizeStr" with dynamic key and tables.", iv, openSSLCipher, \
				true, true, begin, end, maxNBlocks, true); \
	} \
BOOST_AUTO_TEST_SUITE_END()

#ifdef OPENSSL_EXISTS
#define AES_LAUNCHER_DECRYPT_TEST_SUITE(id, testName, className, openSSLCipher, keySizeStr, iv) \
BOOST_AUTO_TEST_SUITE(id) \
	AES_LAUNCHER_DECRYPT_TEST_SUITE_(just_one_entire_block,testName,className,openSSLCipher,keySizeStr,iv,NO_RANDOM_ACCESS,NO_RANDOM_ACCESS,1) \
	AES_LAUNCHER_DECRYPT_TEST_SUITE_(two_entire_blocks,testName,className,openSSLCipher,keySizeStr,iv,NO_RANDOM_ACCESS,NO_RANDOM_ACCESS,2) \
	AES_LAUNCHER_DECRYPT_TEST_SUITE_(sixtyfive_blocks,testName,className,openSSLCipher,keySizeStr,iv,NO_RANDOM_ACCESS,NO_RANDOM_ACCESS,65) \
	AES_LAUNCHER_DECRYPT_TEST_SUITE_(n_blocks,testName,className,openSSLCipher,keySizeStr,iv,NO_RANDOM_ACCESS,NO_RANDOM_ACCESS,10000000) \
BOOST_AUTO_TEST_SUITE_END()
#else
#define AES_LAUNCHER_DECRYPT_TEST_SUITE(id, testName, className, openSSLCipher, keySizeStr, iv)
#endif

#define AES_LAUNCHER_RANDOM_TEST_SUITE_(id, testName, className, keySizeStr, iv, begin, end, maxNBlocks) \
BOOST_AUTO_TEST_SUITE(id) \
	BOOST_AUTO_TEST_CASE(in_order_constant_key_and_tables) { \
	CUDA_AES_SHARED_IO_LAUNCHER_RANDOM_TEST<className>( \
				"Multistream " testName " CUDA AES-"keySizeStr" with constant key and tables.", iv, \
				true, true, begin, end, maxNBlocks, false); \
	} \
	BOOST_AUTO_TEST_CASE(out_of_order_constant_key_and_tables) { \
		CUDA_AES_SHARED_IO_LAUNCHER_RANDOM_TEST<className>( \
				"Multistream " testName " CUDA AES-"keySizeStr" with constant key and tables.", iv, \
				true, true, begin, end, maxNBlocks, true); \
	} \
	BOOST_AUTO_TEST_CASE(in_order_constant_key) { \
		CUDA_AES_SHARED_IO_LAUNCHER_RANDOM_TEST<className>( \
				"Multistream " testName " CUDA AES-"keySizeStr" with constant key.", iv, \
				true, false, begin, end, maxNBlocks, false); \
	} \
	BOOST_AUTO_TEST_CASE(out_of_order_constant_key) { \
		CUDA_AES_SHARED_IO_LAUNCHER_RANDOM_TEST<className>( \
				"Multistream " testName " CUDA AES-"keySizeStr" with constant key .", iv, \
				true, false, begin, end, maxNBlocks, true); \
	} \
	BOOST_AUTO_TEST_CASE(in_order_constant_tables) { \
		CUDA_AES_SHARED_IO_LAUNCHER_RANDOM_TEST<className>( \
				"Multistream " testName " CUDA AES-"keySizeStr" with constant tables.", iv, \
				false, true, begin, end, maxNBlocks, false); \
	} \
	BOOST_AUTO_TEST_CASE(out_of_order_constant_tables) { \
		CUDA_AES_SHARED_IO_LAUNCHER_RANDOM_TEST<className>( \
				"Multistream " testName " CUDA AES-"keySizeStr" with constant tables .", iv, \
				false, true, begin, end, maxNBlocks, true); \
	} \
	BOOST_AUTO_TEST_CASE(in_order_dynamic_key_and_tables) { \
		CUDA_AES_SHARED_IO_LAUNCHER_RANDOM_TEST<className>( \
				"Multistream " testName " CUDA AES-"keySizeStr" with dynamic key and tables.", iv, \
				true, true, begin, end, maxNBlocks, false); \
	} \
	BOOST_AUTO_TEST_CASE(out_of_order_dynamic_key_and_tables) { \
		CUDA_AES_SHARED_IO_LAUNCHER_RANDOM_TEST<className>( \
				"Multistream " testName " CUDA AES-"keySizeStr" with dynamic key and tables.", iv, \
				true, true, begin, end, maxNBlocks, true); \
	} \
BOOST_AUTO_TEST_SUITE_END()

#define AES_LAUNCHER_RANDOM_TEST_SUITE(id, testName, className,  keySizeStr, iv) \
BOOST_AUTO_TEST_SUITE(id) \
	AES_LAUNCHER_RANDOM_TEST_SUITE_(just_one_entire_block,testName,className,keySizeStr,iv,NO_RANDOM_ACCESS,NO_RANDOM_ACCESS,1) \
	AES_LAUNCHER_RANDOM_TEST_SUITE_(two_entire_blocks,testName,className,keySizeStr,iv,NO_RANDOM_ACCESS,NO_RANDOM_ACCESS,2) \
	AES_LAUNCHER_RANDOM_TEST_SUITE_(sixtyfive_entire_blocks,testName,className,keySizeStr,iv,NO_RANDOM_ACCESS,NO_RANDOM_ACCESS,65) \
	AES_LAUNCHER_RANDOM_TEST_SUITE_(n_entire_blocks,testName,className,keySizeStr,iv,NO_RANDOM_ACCESS,NO_RANDOM_ACCESS,10000000) \
BOOST_AUTO_TEST_SUITE_END()


#define AES_LAUNCHER_TEST_SUITE(id, testName, className) \
		BOOST_AUTO_TEST_SUITE(id) \
			AES_LAUNCHER_KEYSIZE_TEST_SUITE(ECB_128, testName, className, "ECB-128", aes_example); \
			AES_LAUNCHER_KEYSIZE_TEST_SUITE(ECB_192, testName, className, "ECB-192", aes_192_tv); \
			AES_LAUNCHER_KEYSIZE_TEST_SUITE(ECB_256, testName, className, "ECB-256", aes_256_tv); \
			AES_LAUNCHER_DECRYPT_TEST_SUITE(RANDOM_DECRYPT_ECB_128, testName, className, EVP_aes_128_ecb(), "ECB-128", aes_example); \
			AES_LAUNCHER_DECRYPT_TEST_SUITE(RANDOM_DECRYPT_ECB_192, testName, className, EVP_aes_192_ecb(), "ECB-192", aes_192_tv); \
			AES_LAUNCHER_DECRYPT_TEST_SUITE(RANDOM_DECRYPT_ECB_256, testName, className, EVP_aes_256_ecb(), "ECB-256", aes_256_tv); \
			AES_LAUNCHER_DECRYPT_TEST_SUITE(RANDOM_DECRYPT_CBC_128, testName, className, EVP_aes_128_cbc(), "CBC-128", aes_128_cbc_tv); \
			AES_LAUNCHER_DECRYPT_TEST_SUITE(RANDOM_DECRYPT_CBC_192, testName, className, EVP_aes_192_cbc(), "CBC-192", aes_192_cbc_tv); \
			AES_LAUNCHER_DECRYPT_TEST_SUITE(RANDOM_DECRYPT_CBC_256, testName, className, EVP_aes_256_cbc(), "CBC-256", aes_256_cbc_tv); \
			AES_LAUNCHER_DECRYPT_TEST_SUITE(RANDOM_DECRYPT_CFB_128, testName, className, EVP_aes_128_cfb(), "CFB-128", aes_128_cfb_tv); \
			AES_LAUNCHER_DECRYPT_TEST_SUITE(RANDOM_DECRYPT_CFB_192, testName, className, EVP_aes_192_cfb(), "CFB-192", aes_192_cfb_tv); \
			AES_LAUNCHER_DECRYPT_TEST_SUITE(RANDOM_DECRYPT_CFB_256, testName, className, EVP_aes_256_cfb(), "CFB-256", aes_256_cfb_tv); \
			AES_LAUNCHER_RANDOM_TEST_SUITE(RANDOM_CTR_128, testName, className, "CTR-128", aes_128_ctr_dummy_tv); \
			AES_LAUNCHER_RANDOM_TEST_SUITE(RANDOM_CTR_192, testName, className, "CTR-192", aes_192_ctr_dummy_tv); \
			AES_LAUNCHER_RANDOM_TEST_SUITE(RANDOM_CTR_256, testName, className, "CTR-256", aes_256_ctr_dummy_tv); \
		BOOST_AUTO_TEST_SUITE_END()
/*  */
// TODO random encrypt and decrypt
// TODO random decrypt (OpenSSL encrypt)
// TODO random padding tests.
// TODO random access tests
// TODO unaligned random access tests

/* TODO uncomment
			AES_LAUNCHER_KEYSIZE_TEST_SUITE(CBC_128, testName, className, "CBC-128", aes_128_cbc_tv); \
			AES_LAUNCHER_KEYSIZE_TEST_SUITE(CBC_192, testName, className, "CBC-192", aes_192_cbc_tv); \
			AES_LAUNCHER_KEYSIZE_TEST_SUITE(CBC_256, testName, className, "CBC-256", aes_256_cbc_tv); \
			AES_LAUNCHER_KEYSIZE_TEST_SUITE(CFB_128, testName, className, "CFB-128", aes_128_cfb_tv); \
			AES_LAUNCHER_KEYSIZE_TEST_SUITE(CFB_192, testName, className, "CFB-192", aes_192_cfb_tv); \
			AES_LAUNCHER_KEYSIZE_TEST_SUITE(CFB_256, testName, className, "CFB-256", aes_256_cfb_tv); \  TODO only random test */

/*			AES_LAUNCHER_KEYSIZE_TEST_SUITE(CTR_128, testName, className, "CTR-128", aes_128_cfb_tv); \
			AES_LAUNCHER_KEYSIZE_TEST_SUITE(CTR_192, testName, className, "CTR-192", aes_192_cfb_tv); \
			AES_LAUNCHER_KEYSIZE_TEST_SUITE(CTR_256, testName, className, "CTR-256", aes_256_cfb_tv); \ TODO only random test */


BOOST_AUTO_TEST_SUITE(LAUNCHERS)
	BOOST_AUTO_TEST_SUITE(CUDA)
		BOOST_AUTO_TEST_SUITE(SHAREDIO)
			BOOST_AUTO_TEST_SUITE(AES)
				AES_LAUNCHER_TEST_SUITE(PARA_16B,"16B parallelism",paracrypt::CudaAES16B);
				AES_LAUNCHER_TEST_SUITE(PARA_16B_PTR,"16B (ptr) parallelism",paracrypt::CudaAES16BPtr);
				AES_LAUNCHER_TEST_SUITE(PARA_8B,"8B parallelism",paracrypt::CudaAES8B);
				AES_LAUNCHER_TEST_SUITE(PARA_8B_PTR,"8B (ptr) parallelism",paracrypt::CudaAES8BPtr);
				AES_LAUNCHER_TEST_SUITE(PARA_4B,"4B parallelism",paracrypt::CudaAES4B);
				AES_LAUNCHER_TEST_SUITE(PARA_4B_PTR,"4B (ptr) parallelism",paracrypt::CudaAES4BPtr);
				AES_LAUNCHER_TEST_SUITE(PARA_1B,"1B parallelism",paracrypt::CudaAES1B);
			BOOST_AUTO_TEST_SUITE_END()
		BOOST_AUTO_TEST_SUITE_END()
	BOOST_AUTO_TEST_SUITE_END()
BOOST_AUTO_TEST_SUITE_END()
