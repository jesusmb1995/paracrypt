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

#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sstream>
#include <boost/log/core.hpp>
#include <boost/log/trivial.hpp>
#include <boost/log/expressions.hpp>
#include <boost/format.hpp>

#if defined(DEBUG) && defined(DEVEL)
#define DEV_TRACE(str) BOOST_LOG_TRIVIAL(trace) << (str)
#define DEV_DEBUG(str) BOOST_LOG_TRIVIAL(debug) << (str)
#else
#define DEV_TRACE(str)
#define DEV_DEBUG(str)
#endif

#ifdef DEBUG
#define LOG_TRACE(str) BOOST_LOG_TRIVIAL(trace) << (str)
#define LOG_DEBUG(str) BOOST_LOG_TRIVIAL(debug) << (str)
#else
#define LOG_TRACE(str)
#define LOG_DEBUG(str)
#endif
#define LOG_INF(str) BOOST_LOG_TRIVIAL(info) << (str)
#define LOG_WAR(str) BOOST_LOG_TRIVIAL(warning) << (str)
#define LOG_ERR(str) BOOST_LOG_TRIVIAL(error) << (str)
#define LOG_FATAL(str) BOOST_LOG_TRIVIAL(fatal) << (str)

#define ERR(str) LOG_ERR(str); exit(-1);
#define FATAL(str) LOG_FATAL(str); exit(-1);


void hexdump(std::string title, const unsigned char *s, int length);
void fdump(std::string title, std::string filename);

