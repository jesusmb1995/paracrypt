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

#include "Paracrypt.hpp"
#include "Launcher.hpp"
#include "cipher/BlockCipher.hpp"
#include "cipher/AES/CudaAesVersions.hpp"
#include "utils/logging.hpp"

#include <boost/log/core.hpp>
#include <boost/log/trivial.hpp>
#include <boost/log/expressions.hpp>
namespace logging = boost::log;

void paracrypt::exec(paracrypt::config_t c) {

	boost::shared_ptr< logging::core > logger = logging::core::get();
	switch(c.verbosity)	{
		case QUIET:
			logger->set_logging_enabled(false);
			break;
		case WARNING:
			logger->set_filter(logging::trivial::severity >= logging::trivial::warning);
			break;
		case INFO:
			logger->set_filter(logging::trivial::severity >= logging::trivial::info);
			break;
		case DBG:
			logger->set_filter(logging::trivial::severity >= logging::trivial::debug);
			break;
		case TRACE:
			logger->set_filter(logging::trivial::severity >= logging::trivial::trace);
			break;
	}

	// convert API public types to internal types
	paracrypt::Launcher::operation_t op = (paracrypt::Launcher::operation_t) c.op;
	paracrypt::BlockCipher::Mode m = (paracrypt::BlockCipher::Mode) c.m;

	LOG_DEBUG(boost::format(
		"\nparacrypt::Launcher::launchSharedIOCudaAES<%i>(\n"
				"\top=%i,\n"
				"\tinFile=%s, outFile=%s,\n"
				"\tkey_bits=%i,\n"
				"\tconstantKey=%d, constantTables=%d,\n"
				"\tm=%i, ivBits=%i,\n"
				"\toutOfOrder=%d,\n"
				"\tbegin=%llu, end=%llu,\n"
				"\tuseLogicOperators=%d\n"
		")"
	 )
		% ((int) c.c)
		% ((int) op)
		% c.inFile.c_str() % c.outFile.c_str()
		% c.key_bits
		% c.constantKey % c.constantTables
		% ((int) c.m) % c.ivBits
		% c.outOfOrder
		% c.begin % c.end
		% c.useLogicOperators
	);

	hexdump("key",c.key,c.key_bits/8);
	if(c.ivBits != 0)
		hexdump("iv",c.iv,c.ivBits/8);

	if(c.stagingLimit != 0) {
		LOG_DEBUG(boost::format("staging area limit: %llu") % c.stagingLimit);
		paracrypt::Launcher::limitStagging(c.stagingLimit);
	}

	if(c.kernelParalellismLimit != -1) {
		LOG_DEBUG(boost::format("maximum number of streams per GPU: %llu") % c.kernelParalellismLimit);
		paracrypt::CUDACipherDevice::limitConcurrentKernels(c.kernelParalellismLimit);
	}

#define LAUNCH_SHARED_IO_CUDA_AES(implementation) \
		paracrypt::Launcher::launchSharedIOCudaAES<implementation>( \
		   		op, \
		   		c.inFile, c.outFile, \
		   		c.key, c.key_bits, \
		   		c.constantKey, c.constantTables, \
		   		m, c.iv, c.ivBits, \
		   		c.outOfOrder, \
		   		c.begin, c.end \
		);

	// Only CUDA AES is supported in this version
	switch(c.c)	{
		case paracrypt::AES16B:
			if(c.useLogicOperators) {
				LAUNCH_SHARED_IO_CUDA_AES(paracrypt::CudaAES16B);
			} else {
				LAUNCH_SHARED_IO_CUDA_AES(paracrypt::CudaAES16BPtr);
			}
			break;
		case paracrypt::AES8B:
			if(c.useLogicOperators) {
				LAUNCH_SHARED_IO_CUDA_AES(paracrypt::CudaAES8B);
			} else {
				LAUNCH_SHARED_IO_CUDA_AES(paracrypt::CudaAES8BPtr);
			}
			break;
		case paracrypt::AES4B:
			if(c.useLogicOperators) {
				LAUNCH_SHARED_IO_CUDA_AES(paracrypt::CudaAES4B);
			} else {
				LAUNCH_SHARED_IO_CUDA_AES(paracrypt::CudaAES4BPtr);
			}
			break;
		case paracrypt::AES1B:
				LAUNCH_SHARED_IO_CUDA_AES(paracrypt::CudaAES1B);
			break;
	}
}
